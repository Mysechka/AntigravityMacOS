use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection};

use crate::utils::{no_window, powershell};

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
pub use relay::relay_available;

#[cfg(not(relay))]
pub fn relay_available() -> bool {
    false
}

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

// Cleanup only, from here to `ca_is_trusted`. Up to 2.9.1_27 the fallback route
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

/// True when a certificate an older build installed is still in the user's root
/// store - i.e. when there is something for `untrust_ca` to do.
pub fn ca_is_trusted() -> bool {
    powershell(&format!(
        "if (Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object {{ $_.Subject -like '*{}*' }}) {{ 'yes' }} else {{ 'no' }}",
        CA_NAME
    ))
    .map_or(false, |o| {
        String::from_utf8_lossy(&o.stdout).trim() == "yes"
    })
}

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
    let Ok(mut upstream) = TcpStream::connect((host, port)) else {
        // The client is still waiting for a status line; without one it sits
        // there until it gives up, which reads as "the proxy hung" rather than
        // "that host is unreachable".
        client.write_all(RESP_BAD_GATEWAY).ok();
        return;
    };
    if client.write_all(RESP_ESTABLISHED).is_err() {
        return;
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

/// Longest a candidate may take before it is not worth carrying traffic through.
#[cfg_attr(not(relay), allow(dead_code))]
const UPSTREAM_PROBE_BUDGET: Duration = Duration::from_secs(6);

/// Drives `conn` to a completed handshake over `sock`, or gives up.
///
/// Blocking with timeouts on purpose: this runs before the client has been told
/// anything, so waiting here is honest, and the alternative - discovering a dead
/// upstream halfway through a tunnel - has no way back.
#[cfg_attr(not(relay), allow(dead_code))]
fn handshake(conn: &mut ClientConnection, sock: &mut TcpStream) -> Result<(), String> {
    sock.set_nonblocking(false).ok();
    sock.set_read_timeout(Some(UPSTREAM_PROBE_BUDGET)).ok();
    sock.set_write_timeout(Some(UPSTREAM_PROBE_BUDGET)).ok();
    let deadline = Instant::now() + UPSTREAM_PROBE_BUDGET;
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
    if port == 443 && relay::relay_available() && relay::is_gate_host(host) {
        relay::relay_tunnel(client, host, port)
    } else {
        Err(client)
    }
}

#[cfg(not(relay))]
fn try_relay_route(client: TcpStream, _host: &str, _port: u16) -> Result<(), TcpStream> {
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

    // Gate hosts take the relay tunnel first (cert-free, end-to-end TLS). If it is
    // unavailable - no key baked in (a public build), relay down, or the credential
    // revoked - the client is handed back untouched and falls through to the direct
    // tunnel below.
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
