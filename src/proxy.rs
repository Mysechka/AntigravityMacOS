use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

use crate::resolvers;
use crate::utils::{no_window, powershell};

// The fallback route: unblock the traffic instead of the name.
//
// The DNS layer can only help with a name some provider still substitutes.
// `jetski-webchannel.googleapis.com` - which the language server is *told by
// Google* to stream the planner through - is substituted by nobody, so no NRPT
// rule and no resolver pool can move it off the blocked exit. Measured across
// all three providers and a reference: genuine 172.217/16 every time.
//
// Pointing that name at a proxy address does not work either: the unblock
// proxies are SNI-whitelisted TCP forwarders and reset the handshake for any
// name off their list (N13). But Google's frontend routes `*.googleapis.com` on
// the HTTP **Host** header, not on SNI - measured today through geohide, where
// SNI `generativelanguage` + `Host: jetski-webchannel` reached a different
// backend (`Server: ESF`) than `Host: generativelanguage` did (`Server:
// scaffolding on HTTPServer2`).
//
// The only client that can send an accepted SNI with the real Host is one that
// owns the TLS. So this proxy terminates the client's TLS with a certificate
// from a CA generated on this machine, opens its own TLS to the unblock proxy
// under the carrier name, and then simply **relays the plaintext untouched** -
// the language server already wrote the correct `Host:` header, so there is
// nothing to rewrite and no HTTP to parse.
//
// Everything else is passed through as an ordinary CONNECT tunnel: raw bytes, no
// interception, no certificate of ours anywhere near it. That covers every name
// outside `*.googleapis.com` *and* the identity and telemetry hosts inside it
// (`NEVER_CARRIED`) - sign-in, token refresh and every other program on the
// machine keep their end-to-end TLS with Google exactly as before.

/// Loopback only. The port is fixed because `HTTPS_PROXY` is a static string in
/// the user's environment - an ephemeral port would need rewriting on every
/// relay start, and would be wrong for any process that read it earlier.
pub const LISTEN_IP: &str = "127.0.0.1";
pub const LISTEN_PORT: u16 = 53129;

/// The name the unblock proxies accept in an SNI. All three providers were
/// measured substituting it and accepting it, which is exactly what makes it
/// usable as a carrier for names they refuse.
const CARRIER: &str = "generativelanguage.googleapis.com";

/// Only these are carried. Google routes them on the Host header, so a carrier
/// SNI reaches the right backend; nothing else is intercepted.
const CARRIED_SUFFIX: &str = ".googleapis.com";

/// Names that are never intercepted even though they match the suffix.
///
/// These carry credentials and identity, not model traffic: `oauth2` mints and
/// refreshes the access token, `www` serves userinfo, `people` the profile,
/// `sts`/`iamcredentials` exchange tokens, `play` is Clearcut telemetry. None of
/// them is region-gated - they worked before this tool existed and they work
/// through a plain tunnel now - so terminating their TLS would put a token
/// endpoint's plaintext through our process for no benefit whatsoever. That is
/// not a trade worth making at any exchange rate.
const NEVER_CARRIED: &[&str] = &[
    "oauth2.googleapis.com",
    "www.googleapis.com",
    "people.googleapis.com",
    "play.googleapis.com",
    "sts.googleapis.com",
    "iamcredentials.googleapis.com",
];

/// Common name of the certificate authority generated on this machine.
const CA_NAME: &str = "AG Unlocker local CA";

/// How long the byte pump sleeps when both directions are idle. It starts at the
/// minimum and doubles to the maximum, so an active connection never sleeps and
/// an idle one costs a wakeup every 50 ms.
const PUMP_MIN_SLEEP: Duration = Duration::from_millis(1);
const PUMP_MAX_SLEEP: Duration = Duration::from_millis(50);
/// How long a connection may sit with neither side saying anything.
const IDLE_LIMIT: Duration = Duration::from_secs(90);
/// Reaching the unblock proxy. A live one connects in ~35 ms, so this is
/// already generous - and every second here is a second the client spends
/// waiting for a CONNECT response it may give up on first.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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

/// Everything the proxy needs that is expensive to build: the CA it signs with
/// and the leaf certificates it has already signed.
struct Authority {
    cert: rcgen::Certificate,
    cert_pem: String,
    key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

static AUTHORITY: Mutex<Option<Arc<Authority>>> = Mutex::new(None);

/// Where the CA lives. Beside the relay's log rather than beside its exe: the
/// relay runs unelevated and cannot write into the directory an administrator
/// installed it into (the same reason the log is there).
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

/// Loads the machine's CA, generating it the first time.
///
/// **Generated here, never shipped.** A certificate authority whose private key
/// travelled with the binary would let anyone holding a copy of the release
/// impersonate any site to every user who installed it. This one exists only on
/// this machine and is deleted on revert.
fn load_or_make_ca() -> Result<Arc<Authority>, String> {
    let dir = ca_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;

    let (cert_pem, key) = match (
        fs::read_to_string(ca_cert_path()),
        fs::read_to_string(ca_key_path()),
    ) {
        (Ok(c), Ok(k)) => {
            let key = KeyPair::from_pem(&k).map_err(|e| format!("ключ CA нечитаем: {}", e))?;
            (c, key)
        }
        _ => {
            let key = KeyPair::generate().map_err(|e| format!("не создать ключ: {}", e))?;
            let params = ca_params()?;
            let cert = params
                .self_signed(&key)
                .map_err(|e| format!("не подписать CA: {}", e))?;
            let pem = cert.pem();
            fs::write(ca_cert_path(), &pem).map_err(|e| format!("не записать ca.pem: {}", e))?;
            fs::write(ca_key_path(), key.serialize_pem())
                .map_err(|e| format!("не записать ca.key: {}", e))?;
            (pem, key)
        }
    };

    // Rebuilt from the stored PEM rather than kept from generation time, so a
    // relay that starts against an existing CA follows exactly the same path as
    // one that just made it.
    let params = CertificateParams::from_ca_cert_pem(&cert_pem)
        .map_err(|e| format!("сертификат CA нечитаем: {}", e))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("не восстановить CA: {}", e))?;

    Ok(Arc::new(Authority {
        cert,
        cert_pem,
        key,
        leaves: Mutex::new(HashMap::new()),
    }))
}

fn ca_params() -> Result<CertificateParams, String> {
    let mut params =
        CertificateParams::new(Vec::new()).map_err(|e| format!("не задать параметры: {}", e))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name.push(DnType::CommonName, CA_NAME);
    params
        .distinguished_name
        .push(DnType::OrganizationName, CA_NAME);
    Ok(params)
}

/// The certificate authority in force right now.
///
/// Deliberately re-checked against the file rather than cached for the process
/// lifetime: a revert deletes the CA and a later opt-in makes a new one, and a
/// relay still holding the old one would go on signing leaves that nothing
/// trusts. That failure would look like a broken proxy rather than a stale key,
/// which is exactly the kind of thing that costs a day. One small file read per
/// intercepted connection is nothing beside the handshake that follows it.
fn authority() -> Option<Arc<Authority>> {
    let on_disk = fs::read_to_string(ca_cert_path()).ok();
    let mut guard = AUTHORITY.lock().ok()?;
    if let Some(current) = guard.as_ref() {
        if on_disk.as_deref() == Some(current.cert_pem.as_str()) {
            return Some(current.clone());
        }
    }
    let fresh = load_or_make_ca().ok()?;
    *guard = Some(fresh.clone());
    Some(fresh)
}

/// Adds the CA to the *current user's* trust store.
///
/// `-user`, never `-enterprise` or the machine store: the only processes that
/// have to trust it are this user's, and a machine-wide root would extend the
/// consequences of a stolen key to every account on the box.
pub fn trust_ca() -> Result<(), String> {
    let ca = authority().ok_or_else(|| "не удалось подготовить CA".to_string())?;
    fs::write(ca_cert_path(), &ca.cert_pem).map_err(|e| format!("не записать ca.pem: {}", e))?;
    let mut cmd = std::process::Command::new("certutil");
    cmd.args([
        "-user",
        "-addstore",
        "Root",
        &ca_cert_path().to_string_lossy(),
    ]);
    let out = no_window(&mut cmd)
        .output()
        .map_err(|e| format!("certutil не запустился: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
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

/// True when a certificate with our CA's name is in the user's root store.
pub fn ca_is_trusted() -> bool {
    powershell(&format!(
        "if (Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object {{ $_.Subject -like '*{}*' }}) {{ 'yes' }} else {{ 'no' }}",
        CA_NAME
    ))
    .map_or(false, |o| {
        String::from_utf8_lossy(&o.stdout).trim() == "yes"
    })
}

/// A server config presenting a freshly-signed certificate for `host`.
///
/// Only `http/1.1` is offered in ALPN, which is what keeps the relay honest: the
/// plaintext it shuttles is then a protocol it does not have to understand, and
/// an HTTP/2 client would otherwise negotiate a framing this proxy never parses.
fn leaf_for(host: &str) -> Option<Arc<ServerConfig>> {
    let ca = authority()?;
    if let Ok(cache) = ca.leaves.lock() {
        if let Some(cfg) = cache.get(host) {
            return Some(cfg.clone());
        }
    }

    let mut params = CertificateParams::new(vec![host.to_string()]).ok()?;
    params.distinguished_name.push(DnType::CommonName, host);
    let key = KeyPair::generate().ok()?;
    let leaf = params.signed_by(&key, &ca.cert, &ca.key).ok()?;

    let chain = vec![leaf.der().clone(), ca.cert.der().clone()];
    let der = PrivateKeyDer::try_from(key.serialize_der()).ok()?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, der)
        .ok()?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let cfg = Arc::new(cfg);

    if let Ok(mut cache) = ca.leaves.lock() {
        cache.insert(host.to_string(), cfg.clone());
    }
    Some(cfg)
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

/// Whether this host can ride in on the carrier name.
///
/// The Host-header routing was measured on `*.googleapis.com` and nowhere else,
/// so nothing else is intercepted - a guess here would mean presenting our own
/// certificate for a site we cannot actually reach.
pub fn is_carried(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.ends_with(CARRIED_SUFFIX) && host != CARRIER && !NEVER_CARRIED.iter().any(|n| *n == host)
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

/// Moves plaintext between the two TLS connections until one of them ends.
///
/// Blocking sockets with a short read timeout rather than a poll loop: rustls
/// connections cannot be split across threads, so each side is serviced in turn
/// and a timeout is simply "nothing to say right now". `IDLE_LIMIT` is what
/// eventually reclaims a connection both sides have forgotten about.
fn pump(
    label: &str,
    mut a: rustls::Connection,
    mut sock_a: TcpStream,
    mut b: rustls::Connection,
    mut sock_b: TcpStream,
) {
    // Non-blocking, not a read timeout. With a timeout, servicing one direction
    // blocks for the whole slice before the other is even looked at, so every
    // round trip inside the TLS handshake and the HTTP exchange pays it twice -
    // measured as roughly a second of pure polling latency on a request whose
    // upstream handshake takes 162 ms. Non-blocking sockets make an active
    // connection cost nothing and leave the sleep for when there is nothing to do.
    sock_a.set_nonblocking(true).ok();
    sock_b.set_nonblocking(true).ok();
    let mut idle = Duration::ZERO;
    let mut backoff = PUMP_MIN_SLEEP;
    let mut buf = [0u8; 16 * 1024];
    // Per direction, because they end independently: a client that has finished
    // sending its request closes its half long before the response arrives.
    // Tearing the whole connection down on the first end-of-stream is what a
    // client reports as "server closed abruptly (missing close_notify)".
    let mut done = [false, false];

    while !(done[0] && done[1]) {
        let mut moved = false;

        for dir in 0..2 {
            if done[dir] {
                continue;
            }
            let (src, src_sock, dst, dst_sock) = if dir == 0 {
                (&mut a, &mut sock_a, &mut b, &mut sock_b)
            } else {
                (&mut b, &mut sock_b, &mut a, &mut sock_a)
            };

            match service(src, src_sock, dst, dst_sock, &mut buf) {
                Ok(0) => {}
                Ok(_) => moved = true,
                // A clean end-of-stream is how every connection finishes and is
                // not worth a line; anything else is a fault worth naming - a
                // client refusing our certificate looks exactly like a proxy
                // that drops connections until this says otherwise.
                Err(e) => {
                    if e.kind() != ErrorKind::UnexpectedEof {
                        crate::dns_forwarder::log_proxy(&format!("{} ended: {}", label, e));
                        done = [true, true];
                    } else {
                        done[dir] = true;
                    }
                }
            }
        }

        if moved {
            idle = Duration::ZERO;
            backoff = PUMP_MIN_SLEEP;
            continue;
        }
        thread::sleep(backoff);
        idle += backoff;
        backoff = (backoff * 2).min(PUMP_MAX_SLEEP);
        if idle > IDLE_LIMIT {
            break;
        }
    }

    // Say goodbye properly. Without it the peer cannot tell a finished response
    // from a truncated one, and a strict client calls it an error.
    for (conn, sock) in [(&mut a, &mut sock_a), (&mut b, &mut sock_b)] {
        conn.send_close_notify();
        let deadline = Instant::now() + PUMP_MAX_SLEEP;
        while conn.wants_write() && Instant::now() < deadline {
            if conn.write_tls(sock).is_err() {
                break;
            }
        }
        sock.flush().ok();
    }
    sock_a.shutdown(std::net::Shutdown::Both).ok();
    sock_b.shutdown(std::net::Shutdown::Both).ok();
}

/// One turn of one direction: pull whatever TLS has arrived, hand the plaintext
/// to the other side, and flush both.
fn service(
    src: &mut rustls::Connection,
    src_sock: &mut TcpStream,
    dst: &mut rustls::Connection,
    dst_sock: &mut TcpStream,
    buf: &mut [u8],
) -> io::Result<usize> {
    let mut moved = 0usize;

    if src.wants_read() {
        match src.read_tls(src_sock) {
            Ok(0) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Ok(_) => {
                src.process_new_packets()
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            }
            Err(e) if would_block(&e) => {}
            Err(e) => return Err(e),
        }
    }

    loop {
        match src.reader().read(buf) {
            Ok(0) => break,
            Ok(n) => {
                dst.writer().write_all(&buf[..n])?;
                moved += n;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }

    while dst.wants_write() {
        match dst.write_tls(dst_sock) {
            Ok(_) => {}
            Err(e) if would_block(&e) => break,
            Err(e) => return Err(e),
        }
    }
    while src.wants_write() {
        match src.write_tls(src_sock) {
            Ok(_) => {}
            Err(e) if would_block(&e) => break,
            Err(e) => return Err(e),
        }
    }
    dst_sock.flush().ok();
    Ok(moved)
}

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
        client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").ok();
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
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
    client_w.shutdown(std::net::Shutdown::Both).ok();
    up.join().ok();
}

/// How long a measured upstream choice is kept before it is measured again.
/// The providers' proxies change speed on the scale of minutes, not seconds, and
/// re-measuring costs a handshake per candidate.
const UPSTREAM_TTL: Duration = Duration::from_secs(3 * 60);
/// Longest a candidate may take before it is not worth carrying traffic through.
const UPSTREAM_PROBE_BUDGET: Duration = Duration::from_secs(6);

/// The upstream proxy currently in use, and when it was chosen.
static UPSTREAM: Mutex<Option<(Ipv4Addr, Instant)>> = Mutex::new(None);

/// How long a full TCP + TLS handshake to `addr` takes under the carrier name,
/// or `None` if it does not finish inside the budget.
///
/// This is the number that decides everything: TCP is uninformative here (34 ms
/// to a proxy that then spends ten seconds on the handshake), and it is the
/// handshake the client will pay for on its first request.
fn handshake_cost(addr: Ipv4Addr) -> Option<Duration> {
    let started = Instant::now();
    let mut sock = TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::V4(addr), 443),
        UPSTREAM_PROBE_BUDGET,
    )
    .ok()?;
    let name = ServerName::try_from(CARRIER).ok()?;
    let mut conn = ClientConnection::new(upstream_config(), name).ok()?;
    sock.set_read_timeout(Some(UPSTREAM_PROBE_BUDGET)).ok();
    sock.set_write_timeout(Some(UPSTREAM_PROBE_BUDGET)).ok();
    let deadline = started + UPSTREAM_PROBE_BUDGET;
    while conn.is_handshaking() {
        if Instant::now() >= deadline {
            return None;
        }
        if conn.wants_write() && conn.write_tls(&mut sock).is_err() {
            return None;
        }
        if conn.wants_read() {
            match conn.read_tls(&mut sock) {
                Ok(0) | Err(_) => return None,
                Ok(_) => conn.process_new_packets().ok()?,
            };
        }
    }
    Some(started.elapsed())
}

/// Measures every provider's proxy for the carrier name and keeps the quickest.
///
/// Called from the relay's warm loop, never from a client's connection: it is
/// several handshakes and they are exactly the thing being timed. What it buys
/// is the difference between 249 ms and 10 s per request, which is the whole
/// reason this route is worth having at all.
pub fn refresh_upstream(if_index: u32) {
    let mut best: Option<(Ipv4Addr, Duration)> = None;
    for (provider, addrs) in resolvers::substituted_addrs(CARRIER, if_index) {
        for addr in addrs {
            let Some(cost) = handshake_cost(addr) else {
                continue;
            };
            if best.map_or(true, |(_, b)| cost < b) {
                crate::dns_forwarder::log_proxy(&format!(
                    "upstream {} via {} {} ms",
                    addr,
                    provider,
                    cost.as_millis()
                ));
                best = Some((addr, cost));
            }
        }
    }
    if let Some((addr, _)) = best {
        if let Ok(mut guard) = UPSTREAM.lock() {
            *guard = Some((addr, Instant::now()));
        }
    }
}

/// The measured upstream, if one is still current.
fn chosen_upstream() -> Option<Ipv4Addr> {
    let guard = UPSTREAM.lock().ok()?;
    let (addr, at) = (*guard)?;
    (at.elapsed() < UPSTREAM_TTL).then_some(addr)
}

/// Drives `conn` to a completed handshake over `sock`, or gives up.
///
/// Blocking with timeouts on purpose: this runs before the client has been told
/// anything, so waiting here is honest, and the alternative - discovering a dead
/// upstream halfway through a tunnel - has no way back.
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

/// Drops the measured upstream so the next warm pass picks again. Called when
/// the chosen one stops performing - a measurement minutes old is a guess.
fn forget_upstream() {
    if let Ok(mut guard) = UPSTREAM.lock() {
        *guard = None;
    }
}

/// Everything that has to succeed *before* the client is told anything.
///
/// Ordered this way on purpose: once `200 Connection Established` has gone out
/// the client is committed to talking TLS to us, so there is no falling back to
/// a plain tunnel after that point. Every failure that can happen must happen
/// here, while the client still has no idea which route it is on.
fn prepare(
    host: &str,
    if_index: u32,
) -> Result<(ServerConnection, ClientConnection, TcpStream), String> {
    let server_cfg = leaf_for(host).ok_or_else(|| "Ð½ÐµÑ ÑÐµÑÑÐ¸ÑÐ¸ÐºÐ°ÑÐ°".to_string())?;

    // The address is chosen the same way every other answer is: whichever
    // provider actually substitutes the carrier right now, dead addresses cut.
    // Whichever proxy measured fastest on the warm loop. The resolver race is
    // only the fallback until the first measurement lands: that race answers
    // "who substitutes the carrier", and all three providers do - so on its own
    // it picks at random among proxies that differ by a factor of forty.
    let addr = match chosen_upstream() {
        Some(addr) => addr,
        None => {
            let (addrs, _, verdict) = resolvers::resolve_a_best(CARRIER, if_index)
                .ok_or_else(|| "Ð°Ð¿ÑÑÑÐ¸Ð¼ Ð½Ðµ ÑÐ°Ð·ÑÐµÑÐ¸Ð»ÑÑ".to_string())?;
            if verdict != resolvers::Verdict::Substituted {
                return Err("Ð°Ð¿ÑÑÑÐ¸Ð¼ Ð½Ðµ Ð¿Ð¾Ð´Ð¼ÐµÐ½ÑÐ½".to_string());
            }
            *addrs.first().ok_or_else(|| "Ð¿ÑÑÑÐ¾Ð¹ Ð¾ÑÐ²ÐµÑ".to_string())?
        }
    };

    let mut upstream =
        TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(addr), 443), CONNECT_TIMEOUT)
            .map_err(|e| format!("{} Ð½ÐµÐ´Ð¾ÑÑÑÐ¿ÐµÐ½: {}", addr, e))?;

    let name = ServerName::try_from(CARRIER).map_err(|e| e.to_string())?;
    let mut to_upstream =
        ClientConnection::new(upstream_config(), name).map_err(|e| e.to_string())?;

    // Finish the upstream handshake here, under a deadline, rather than letting
    // the byte pump discover it. The pump has no timeout of its own, so a
    // provider that degrades after it was measured turns into a client that
    // hangs for the full idle limit - observed as two 25 s stalls in eight
    // requests. Failing here instead falls through to the plain tunnel, which is
    // slower but answers.
    handshake(&mut to_upstream, &mut upstream).map_err(|e| {
        forget_upstream();
        format!("{} не завершил рукопожатие: {}", addr, e)
    })?;

    let to_client = ServerConnection::new(server_cfg).map_err(|e| e.to_string())?;
    Ok((to_client, to_upstream, upstream))
}

fn serve(mut client: TcpStream, if_index: u32) {
    client.set_read_timeout(Some(REQUEST_IDLE)).ok();
    let (host, port) = match read_connect(&mut client) {
        Request::Connect(host, port) => (host, port),
        Request::Malformed => {
            client.write_all(RESP_NOT_ALLOWED).ok();
            return;
        }
        Request::Gone => return,
    };

    if port == 443 && is_carried(&host) {
        match prepare(&host, if_index) {
            Ok((to_client, to_upstream, upstream)) => {
                if client.write_all(RESP_ESTABLISHED).is_ok() {
                    crate::dns_forwarder::log_proxy(&format!("carry {}", host));
                    pump(
                        &format!("carry {}", host),
                        rustls::Connection::from(to_client),
                        client,
                        rustls::Connection::from(to_upstream),
                        upstream,
                    );
                }
                return;
            }
            // Degrading to a plain tunnel is the right failure: the request then
            // leaves from the blocked region and Antigravity says so, which is a
            // far better outcome than a connection that never answers.
            Err(e) => crate::dns_forwarder::log_proxy(&format!("tunnel {} ({})", host, e)),
        }
    }
    client.set_read_timeout(None).ok();
    tunnel(client, &host, port);
}

/// Runs the proxy until the process ends. Never returns while the socket holds.
pub fn run(if_index: u32) -> Result<(), String> {
    let listener = TcpListener::bind((LISTEN_IP.parse::<Ipv4Addr>().unwrap(), LISTEN_PORT))
        .map_err(|e| format!("не занять {}:{} — {}", LISTEN_IP, LISTEN_PORT, e))?;
    // The certificate authority is deliberately NOT created here. The listener
    // costs a loopback socket and nothing else, but a private key on disk is a
    // liability, and a user who never turns the fallback on should never have
    // one. It is created by `trust_ca()`, i.e. at the moment they opt in.

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
    fn only_googleapis_names_are_intercepted() {
        assert!(is_carried("jetski-webchannel.googleapis.com"));
        assert!(is_carried("cloudcode-pa.googleapis.com"));
        assert!(is_carried("DAILY-CLOUDCODE-PA.GOOGLEAPIS.COM"));
        assert!(is_carried("jetski-webchannel.googleapis.com."));

        // Sign-in, telemetry and everything else keep their own TLS.
        assert!(!is_carried("accounts.google.com"));
        assert!(!is_carried("antigravity-unleash.goog"));
        assert!(!is_carried("example.com"));
        // A name that only looks like one of ours must not be intercepted.
        assert!(!is_carried("evil-googleapis.com"));
        assert!(!is_carried("googleapis.com.attacker.net"));
    }

    /// Credentials must never pass through our TLS termination. These hosts are
    /// not region-gated - they worked before this tool existed - so intercepting
    /// them would put a token endpoint's plaintext through this process for
    /// nothing at all.
    #[test]
    fn identity_and_telemetry_hosts_are_never_intercepted() {
        for host in NEVER_CARRIED {
            assert!(!is_carried(host), "{}", host);
            assert!(!is_carried(&host.to_uppercase()), "{}", host);
        }
        // The gate hosts still are, or the fallback route does nothing.
        assert!(is_carried("cloudcode-pa.googleapis.com"));
        assert!(is_carried("daily-cloudcode-pa.googleapis.com"));
        assert!(is_carried("jetski-webchannel.googleapis.com"));
    }

    /// The carrier reaches its own backend directly and needs no interception;
    /// presenting our certificate for it would be pure loss.
    #[test]
    fn the_carrier_itself_is_not_intercepted() {
        assert!(!is_carried(CARRIER));
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
