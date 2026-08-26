use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection};

use crate::upstream;
use crate::utils::no_window;

// The fallback route: unblock the traffic instead of the name.
//
// The DNS layer can only help with a name some provider still substitutes, and
// it cannot help with how slow that provider's proxy is. `cloudcode-pa` is
// substituted by nobody (S9), and `daily-cloudcode-pa` only by geohide, which
// has been measured taking 1.4-14.8 s over a TLS handshake xbox does in 249 ms
// (P6). So this is a second route, working at the traffic level rather than at
// the name.
//
// It is a loopback CONNECT proxy and nothing else. A gate host goes through the
// authenticated relay in the private `relay` module - a CONNECT tunnel whose TLS
// stays end to end with Google, so no certificate of ours is anywhere near it.
// Everything else, *including* every other `*.googleapis.com`, is a raw byte
// tunnel: sign-in, token refresh and every other program on the machine keep
// exactly the TLS they had before this tool existed.
//
// It used to terminate the client's TLS with a CA generated on this machine and
// carry blocked names in under an SNI the unblock proxies accept - they are
// SNI-whitelisted forwarders (N13), but Google's frontend routes
// `*.googleapis.com` on the HTTP **Host** header, so a carrier SNI reaches the
// right backend. That whole route is gone: the relay reaches the same backends
// with no CA at all, and intercepting the rest black-screened the Desktop app
// with `BadCertificate`. The CA helpers below survive for one purpose - removing
// a certificate an older version installed. Measurements: kb/dns.md.

/// Loopback only. The port is fixed because `HTTPS_PROXY` is a static string in
/// the user's environment - an ephemeral port would need rewriting on every
/// relay start, and would be wrong for any process that read it earlier.
pub const LISTEN_IP: &str = "127.0.0.1";
pub const LISTEN_PORT: u16 = 53129;

/// Common name of the certificate authority older versions generated on this
/// machine. Nothing creates one any more; the name is kept so the three helpers
/// below can find and remove one that is still installed.
const CA_NAME: &str = "AG Unlocker local CA";

// The fast relay route's whole method - host, CONNECT-with-credential logic and
// the credential itself - lives in the gitignored `src/relay.rs`, compiled in
// only under `cfg(relay)` (set by build.rs when that file and `.relay_key` are
// both present). A build from the public source has neither, compiles the stub
// below, and runs the DNS route. `relay_available()` is the only symbol the rest
// of the crate needs; everything else stays private to that module.
#[cfg(relay)]
#[path = "relay.rs"]
mod relay;
#[cfg(relay)]
pub use relay::{probe_relay, relay_available, relay_is_benched};

#[cfg(not(relay))]
pub fn relay_available() -> bool {
    false
}

/// No relay route to check in a build that has no relay module.
#[cfg(not(relay))]
pub fn probe_relay() {}

#[cfg(not(relay))]
pub fn relay_is_benched() -> bool {
    false
}

// The built-in exits - third-party CONNECT proxies that already egress in a
// permitted region - live in the gitignored `src/exits.rs` with their address
// list in `.exits`, compiled in only under `cfg(exits)`. Same arrangement as the
// relay, for a different reason: the method here is not secret (it is the plain
// CONNECT `upstream.rs` already speaks in public source), the addresses are, and
// only because naming somebody else's free proxy in a public repository is how it
// stops being one.
#[cfg(exits)]
#[path = "exits.rs"]
mod exits;
#[cfg(exits)]
pub use exits::probe_health as probe_exits;

/// No built-in exits to check in a build that has no exits module.
#[cfg(not(exits))]
pub fn probe_exits() {}

// The byte pump's timings, the upstream handshake and `would_block` below are
// the primitives the private relay module is built on, and its only users. A
// public build has no such module, so each is marked dead-code-allowed under
// `cfg(not(relay))` - a clone should compile without a wall of warnings, and
// silencing them one by one is honest about *why* they look unused.

/// How long the byte pump sleeps when both directions are idle. It starts at the
/// minimum and doubles to the maximum, so an active connection never sleeps and
/// an idle one costs a wakeup every 50 ms.
#[cfg_attr(not(relay), allow(dead_code))]
const PUMP_MIN_SLEEP: Duration = Duration::from_millis(1);
#[cfg_attr(not(relay), allow(dead_code))]
const PUMP_MAX_SLEEP: Duration = Duration::from_millis(50);
/// How long a freshly accepted socket may stay silent before it is dropped.
/// Long, because a pooling client legitimately opens sockets before it has
/// anything to send; bounded, so an abandoned one does not hold a thread.
const REQUEST_IDLE: Duration = Duration::from_secs(120);

/// Proxy status lines, kept as named constants rather than written inline.
///
/// The CRLF pairs in them are load-bearing and easy to lose: a tool that
/// normalises line endings turns the escape into a bare newline, rustc accepts
/// that without a word, and the result is a response no HTTP client will parse.
/// `status_lines_are_crlf_terminated` is what stops that reaching a release.
const RESP_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const RESP_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
const RESP_NOT_ALLOWED: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n";

// Cleanup only, from here to `untrust_ca`. Up to 2.9.1_27 the fallback route
// terminated TLS and needed a per-machine CA; the relay route replaced it and
// needs none, so nothing here creates or signs anything. What is left finds the
// old certificate and takes it out, because a machine that ran an earlier build
// still has a root certificate in its user store and both undo paths (menu 6 and
// menu 7) have to remove it. Delete these only once no installed build can still
// have one.

/// Where an older build kept its CA. Beside the relay's log rather than beside
/// its exe: the relay runs unelevated and cannot write into the directory an
/// administrator installed it into (the same reason the log is there).
pub fn ca_dir() -> PathBuf {
    PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default()).join("AGUnlocker")
}

pub fn ca_cert_path() -> PathBuf {
    ca_dir().join("ca.pem")
}

fn ca_key_path() -> PathBuf {
    ca_dir().join("ca.key")
}

/// The proxy URL that goes into the environment of the processes being routed.
pub fn proxy_url() -> String {
    format!("http://{}:{}", LISTEN_IP, LISTEN_PORT)
}

/// Takes the CA back out of the trust store and deletes its key.
///
/// Deliberately best-effort and idempotent: revert must not stop half way and
/// leave a root certificate behind, so every step runs even if an earlier one
/// found nothing to do.
pub fn untrust_ca() {
    let mut cmd = std::process::Command::new("certutil");
    cmd.args(["-user", "-delstore", "Root", CA_NAME]);
    no_window(&mut cmd).output().ok();
    fs::remove_file(ca_cert_path()).ok();
    fs::remove_file(ca_key_path()).ok();
}

// There used to be a `ca_is_trusted()` here, to decide whether `untrust_ca` had
// anything to do. It was the gate on the revert, and the gate is what let a
// machine come out of a revert with its proxy variables still set. `untrust_ca`
// is idempotent and costs one `certutil` call, so asking first bought nothing
// and could only ever skip work that needed doing.

/// The same client configuration, for the resolver's handshake probe.
///
/// Shared deliberately: the probe has to negotiate what the real connection will
/// negotiate, or it measures something the client never does.
pub fn probe_config() -> Arc<ClientConfig> {
    upstream_config()
}

fn upstream_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

/// The two region-gated CloudCode endpoints - the only names that ever need a
/// route other than a plain direct tunnel. Everything else reaches genuine
/// Google unaided, so it is never sent through anybody's proxy.
///
/// Lives here rather than in the private relay module because it is policy, not
/// method: every route has to agree on which hosts it applies to, and a second
/// copy of a list like this drifts.
pub fn is_gate_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "cloudcode-pa.googleapis.com" || h == "daily-cloudcode-pa.googleapis.com"
}

/// Sends a gate host through the user's own proxy, when they gave us one and it
/// is currently working. `Err` hands the client back untouched for the next
/// route to try - nothing has been said to it yet.
///
/// Health is judged by the warm loop's probe, not by what happens here, with one
/// exception: a proxy that will not even accept the `CONNECT` is unambiguously
/// down and says so immediately. Everything subtler - accepting tunnels and
/// cutting them at the handshake, which is exactly how the relay failed - is left
/// to the probe, because "bytes moved" is not the same question as "it worked"
/// and reading it that way once already let an outage run.
fn try_own_proxy(mut client: TcpStream, host: &str, port: u16) -> Result<(), TcpStream> {
    if port != 443 || !is_gate_host(host) || !upstream::available() {
        return Err(client);
    }
    let Some(up) = upstream::configured() else {
        return Err(client);
    };
    let upstream_sock = match upstream::open(&up, host, port, upstream::LIVE_OPEN_BUDGET) {
        Ok(sock) => sock,
        Err(why) => {
            crate::dns_forwarder::log_proxy(&format!("свой прокси {}: {}", up.display(), why));
            upstream::OWN.health.note(false);
            return Err(client);
        }
    };
    // Committed: from here the client is talking to Google through their proxy.
    if client.write_all(RESP_ESTABLISHED).is_err() {
        return Ok(());
    }
    crate::dns_forwarder::log_proxy(&format!("свой прокси -> {}", host));
    splice(client, upstream_sock);
    Ok(())
}

/// `CONNECT host:port HTTP/1.1` and the headers after it, up to the blank line.
///
/// Returns the target. Anything that is not a CONNECT is refused rather than
/// guessed at: this proxy exists for one client and one method.
fn read_connect(sock: &mut TcpStream) -> Request {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8 * 1024 {
            return Request::Malformed;
        }
        match sock.read(&mut byte) {
            // The client hung up, or never spoke inside REQUEST_IDLE. Neither is
            // a request to refuse, and answering one is worse than silence: a
            // pooling client - Node opens proxy sockets before it has anything
            // to send - would find a status line where its CONNECT response
            // belongs. That was the whole of "Proxy connection ended before
            // receiving CONNECT response": a 10 s timeout writing 405 into a
            // socket the client had not used yet.
            Ok(0) | Err(_) => return Request::Gone,
            Ok(_) => head.push(byte[0]),
        }
    }
    match parse_connect(&String::from_utf8_lossy(&head)) {
        Some((host, port)) => Request::Connect(host, port),
        None => Request::Malformed,
    }
}

/// What arrived on a freshly accepted socket.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    Connect(String, u16),
    /// Something that is not a CONNECT. Answered, because the client is there.
    Malformed,
    /// Nothing arrived. Closed in silence, because there is nobody to answer.
    Gone,
}

fn parse_connect(head: &str) -> Option<(String, u16)> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let target = parts.next()?;
    let (host, port) = target.rsplit_once(':')?;
    // An IPv6 literal is bracketed; strip them so the name is usable as an SNI.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

#[cfg_attr(not(relay), allow(dead_code))]
fn would_block(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

/// Raw byte tunnel, for everything this proxy has no business decrypting.
fn tunnel(mut client: TcpStream, host: &str, port: u16) {
    let Ok(upstream) = TcpStream::connect((host, port)) else {
        // The client is still waiting for a status line; without one it sits
        // there until it gives up, which reads as "the proxy hung" rather than
        // "that host is unreachable".
        client.write_all(RESP_BAD_GATEWAY).ok();
        return;
    };
    if client.write_all(RESP_ESTABLISHED).is_err() {
        return;
    }
    splice(client, upstream);
}

/// Moves raw bytes between two sockets until one of them ends.
///
/// Split out of `tunnel` because a tunnel through the user's proxy is the same
/// splice with a socket that was opened differently - and a second copy of the
/// teardown discipline below would be a second place to get it wrong.
fn splice(mut client: TcpStream, mut upstream: TcpStream) {
    // A tunnel sets its own idle policy, whatever the two sockets were carrying
    // when they got here - the accept loop's silence limit on one, a CONNECT
    // reply budget on the other. Neither is a tunnel policy, and a stray one is
    // not harmless: `upstream::open`'s ten-second reply budget rode into the
    // splice and killed every pooled connection at 10.3 s of silence. `io::copy`
    // reads a timeout as the end of the stream, so the tunnel simply closed; the
    // language server saw its pooled connection die on the next write and
    // reconnected, over and over - 35 tunnels in 25 seconds, which is what a long
    // hang on "Authenticating" looks like from this side. Only the relay route
    // escaped it, because it pumps its own sockets (I37).
    //
    // None, rather than a reaper: expiring an idle tunnel is a real policy with a
    // real risk of cutting a live stream (P4), and it belongs with the payload
    // clock in the relay's pump, not smuggled in as a socket option.
    for s in [&client, &upstream] {
        s.set_read_timeout(None).ok();
        s.set_write_timeout(None).ok();
    }
    let Ok(mut client_w) = client.try_clone() else {
        return;
    };
    let Ok(mut upstream_w) = upstream.try_clone() else {
        return;
    };
    // Raw bytes need no shared TLS state, so the simple two-thread shape works
    // here even though the intercepted path cannot use it.
    let up = thread::spawn(move || io::copy(&mut client, &mut upstream_w));
    io::copy(&mut upstream, &mut client_w).ok();
    // FIN first, and only then the full shutdown that releases the thread still
    // reading from this socket. Going straight to `Both` closes it with whatever
    // the client had already sent still unread, and Windows answers unread bytes
    // with RST - which a pooling client reports as "An existing connection was
    // forcibly closed by the remote host" instead of quietly reconnecting.
    client_w.shutdown(std::net::Shutdown::Write).ok();
    thread::sleep(PUMP_MAX_SLEEP);
    client_w.shutdown(std::net::Shutdown::Both).ok();
    up.join().ok();
}

/// Longest one candidate address may take - connect *and* TLS together - before
/// the next one deserves the rest of the budget.
///
/// Sized so a pool of several is actually walked: the relay's whole-route budget
/// is 8 s, and at this slice three addresses get a real attempt instead of one
/// black-holing address consuming almost all of it.
#[cfg_attr(not(relay), allow(dead_code))]
pub const UPSTREAM_PROBE_BUDGET: Duration = Duration::from_millis(2500);

/// Drives `conn` to a completed handshake over `sock` before `deadline`, or gives
/// up.
///
/// Blocking with timeouts on purpose: this runs before the client has been told
/// anything, so waiting here is honest, and the alternative - discovering a dead
/// upstream halfway through a tunnel - has no way back.
#[cfg_attr(not(relay), allow(dead_code))]
fn handshake(
    conn: &mut ClientConnection,
    sock: &mut TcpStream,
    deadline: Instant,
) -> Result<(), String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("таймаут".to_string());
    }
    sock.set_nonblocking(false).ok();
    // The socket timeouts come from the caller's deadline, not from a constant of
    // our own. A fixed six seconds here is not a local decision: it is spent out of
    // whatever budget the caller is holding, and one address that completes TCP and
    // then black-holes TLS ate almost all of the relay pool's eight seconds, so the
    // address that actually worked was never reached (G7, one layer up).
    sock.set_read_timeout(Some(left)).ok();
    sock.set_write_timeout(Some(left)).ok();
    while conn.is_handshaking() {
        if Instant::now() >= deadline {
            return Err("таймаут".to_string());
        }
        if conn.wants_write() {
            conn.write_tls(sock).map_err(|e| e.to_string())?;
        }
        if conn.wants_read() {
            match conn.read_tls(sock) {
                Ok(0) => return Err("апстрим закрыл соединение".to_string()),
                Ok(_) => conn.process_new_packets().map_err(|e| e.to_string())?,
                Err(e) => return Err(e.to_string()),
            };
        }
    }
    Ok(())
}

/// Tries the fast relay route for a gate host, else hands the client straight
/// back so `serve` uses the direct tunnel. The only place the private relay
/// module is touched: a build compiled from the public source has no such module
/// (`cfg(not(relay))`) and always falls through to the DNS route.
#[cfg(relay)]
fn try_relay_route(client: TcpStream, host: &str, port: u16) -> Result<(), TcpStream> {
    if port == 443 && relay::relay_available() && is_gate_host(host) {
        relay::relay_tunnel(client, host, port)
    } else {
        Err(client)
    }
}

#[cfg(not(relay))]
fn try_relay_route(client: TcpStream, _host: &str, _port: u16) -> Result<(), TcpStream> {
    Err(client)
}

/// Tries the built-in exits for a gate host, else hands the client straight back.
/// The only place the private exits module is touched; a build from the public
/// source has no such module and falls through to the relay and the DNS route.
#[cfg(exits)]
fn try_builtin_exit(client: TcpStream, host: &str, port: u16) -> Result<(), TcpStream> {
    if port == 443 && is_gate_host(host) && exits::available() {
        exits::tunnel(client, host, port)
    } else {
        Err(client)
    }
}

#[cfg(not(exits))]
fn try_builtin_exit(client: TcpStream, _host: &str, _port: u16) -> Result<(), TcpStream> {
    Err(client)
}

fn serve(mut client: TcpStream, _if_index: u32) {
    client.set_read_timeout(Some(REQUEST_IDLE)).ok();
    let (host, port) = match read_connect(&mut client) {
        Request::Connect(host, port) => (host, port),
        Request::Malformed => {
            client.write_all(RESP_NOT_ALLOWED).ok();
            return;
        }
        Request::Gone => return,
    };

    // Four routes for a gate host, best first, each handing the client back
    // untouched if it cannot serve it:
    //
    //   1. the user's own proxy, when they gave us one. It stays first even though
    //      the built-in exits below are usually faster: they typed it in by hand,
    //      it is theirs rather than a third party we chose for them, and silently
    //      overriding what somebody configured is not a speed optimisation. Almost
    //      nobody sets one, so in practice route 2 is the first that runs.
    //   2. a built-in exit - somebody else's CONNECT proxy that already egresses
    //      in a permitted region, so it lifts the gate outright (S25) with no DNS
    //      trickery, no credential and no certificate. Measured faster than the
    //      relay and several times faster than the DNS route (kb/dns.md).
    //   3. the relay, cert-free but somebody else's and revocable.
    //   4. a plain direct tunnel, which the DNS layer has already pointed at a
    //      substituted address.
    //
    // Nothing is decided before `200 Connection Established` goes out, so falling
    // from one to the next costs the client nothing (I35).
    let client = match try_own_proxy(client, &host, port) {
        Ok(()) => return,
        Err(returned) => returned,
    };
    let client = match try_builtin_exit(client, &host, port) {
        Ok(()) => return,
        Err(returned) => returned,
    };
    let client = match try_relay_route(client, &host, port) {
        Ok(()) => return,
        Err(returned) => returned,
    };

    // Everything that is not a gate host is a plain direct tunnel - including
    // every other `*.googleapis.com` (e.g. `storage.googleapis.com`, which the
    // Desktop app loads at startup). The proxy terminates no TLS and holds no CA:
    // MITMing those hosts with a certificate no client trusts is exactly what
    // black-screened the Desktop app with `BadCertificate`. The gate hosts are
    // reached cert-free through the relay above; nothing here needs a CA.
    client.set_read_timeout(None).ok();
    tunnel(client, &host, port);
}

/// Runs the proxy until the process ends. Never returns while the socket holds.
pub fn run(if_index: u32) -> Result<(), String> {
    let listener = TcpListener::bind((LISTEN_IP.parse::<Ipv4Addr>().unwrap(), LISTEN_PORT))
        .map_err(|e| format!("не занять {}:{} — {}", LISTEN_IP, LISTEN_PORT, e))?;
    // Costs a loopback socket and nothing else: no key is generated, nothing is
    // put in a trust store, and a client that never points at this port never
    // notices it is here.

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        thread::spawn(move || serve(stream, if_index));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A status line that lost its carriage returns is still valid Rust and
    /// still compiles - it just produces a response no HTTP client accepts.
    /// Written as raw byte values so no tool can normalise the test itself.
    #[test]
    fn status_lines_are_crlf_terminated() {
        for line in [RESP_ESTABLISHED, RESP_BAD_GATEWAY, RESP_NOT_ALLOWED] {
            assert_eq!(&line[line.len() - 4..], &[13u8, 10, 13, 10], "{:?}", line);
            assert!(!line[..line.len() - 4].contains(&10u8), "{:?}", line);
        }
    }

    /// A tunnel must not be closed by a budget that was only ever meant to bound
    /// the CONNECT handshake.
    ///
    /// The regression this pins: `upstream::open` left its ten-second reply budget
    /// on the socket it returned, `splice` handed that socket to `io::copy`, and a
    /// timeout reads as end-of-stream - so every tunnel through the user's own
    /// proxy or a built-in exit died at 10.3 s of silence. A pooling client
    /// reconnects on the failed reuse, which showed up as a long hang on
    /// "Authenticating" and 35 tunnels in 25 seconds in the log.
    ///
    /// Sixteen seconds of silence, comfortably past the old ten, then the tunnel
    /// is used - a live client would fail here, not at the handshake.
    ///
    ///     cargo test an_idle_tunnel_outlives_the_connect_budget -- --ignored --nocapture
    #[test]
    #[ignore = "holds a tunnel open for 16 s against a real route; needs a live network"]
    fn an_idle_tunnel_outlives_the_connect_budget() {
        use rustls::pki_types::ServerName;
        use rustls::ClientConnection;
        use std::net::TcpListener;

        const HOST: &str = "daily-cloudcode-pa.googleapis.com";
        const IDLE: Duration = Duration::from_secs(16);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accepted");
            serve(sock, 0);
        });

        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(
                format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n").as_bytes(),
            )
            .expect("sent CONNECT");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(client.read(&mut byte).expect("reply"), 1, "proxy hung up");
            head.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&head).contains(" 200"));

        let name = ServerName::try_from(HOST).expect("name");
        let mut tls = ClientConnection::new(probe_config(), name).expect("tls");
        let mut stream = rustls::Stream::new(&mut tls, &mut client);
        // Complete the handshake before going quiet, so the silence is measured on
        // an established tunnel - which is the state a pooled connection sits in.
        stream.flush().ok();

        thread::sleep(IDLE);

        stream
            .write_all(
                format!(
                    "GET /v1internal:probe HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("the tunnel was closed under an idle client");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).expect("no answer after idling");
        assert!(
            buf[..n].starts_with(b"HTTP/"),
            "not an HTTP answer: {:?}",
            String::from_utf8_lossy(&buf[..n])
        );
        println!(
            "tunnel survived {} s idle and still carried a request",
            IDLE.as_secs()
        );
    }

    #[test]
    fn reads_the_connect_target() {
        assert_eq!(
            parse_connect(
                "CONNECT jetski-webchannel.googleapis.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"
            ),
            Some(("jetski-webchannel.googleapis.com".to_string(), 443))
        );
        assert_eq!(
            parse_connect("connect example.com:8443 HTTP/1.1\r\n\r\n"),
            Some(("example.com".to_string(), 8443))
        );
        assert_eq!(
            parse_connect("CONNECT [::1]:443 HTTP/1.1\r\n\r\n"),
            Some(("::1".to_string(), 443))
        );
    }

    /// The bug the IDE actually hit. A client that opens a proxy socket and has
    /// not spoken yet must be closed in silence: answering it puts a status line
    /// where its CONNECT response belongs, and the client reports only "Proxy
    /// connection ended before receiving CONNECT response".
    #[test]
    fn a_socket_that_says_nothing_is_closed_without_an_answer() {
        use std::net::TcpListener;

        fn ask(send: Option<&'static [u8]>) -> Request {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            let writer = thread::spawn(move || {
                let mut c = TcpStream::connect(addr).unwrap();
                match send {
                    Some(bytes) => {
                        c.write_all(bytes).unwrap();
                        // Held open so the read cannot end on the socket closing
                        // instead of on the request being complete.
                        thread::sleep(Duration::from_millis(200));
                    }
                    None => drop(c),
                }
            });
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let got = read_connect(&mut sock);
            writer.join().ok();
            got
        }

        assert_eq!(ask(None), Request::Gone);
        assert_eq!(
            ask(Some(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")),
            Request::Malformed
        );
        assert_eq!(
            ask(Some(
                b"CONNECT a.googleapis.com:443 HTTP/1.1\r\nHost: a\r\n\r\n"
            )),
            Request::Connect("a.googleapis.com".to_string(), 443)
        );
    }

    /// Anything that is not a CONNECT is refused rather than guessed at.
    #[test]
    fn a_non_connect_request_is_refused() {
        assert_eq!(parse_connect("GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_connect("CONNECT nohost HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_connect("CONNECT :443 HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_connect(""), None);
    }

    #[test]
    fn the_proxy_url_is_loopback() {
        assert!(proxy_url().starts_with("http://127.0.0.1:"));
    }
}
