//! "Bring your own exit" - the user's own proxy in a permitted region.
//!
//! Everything else in this tool exists to make Google see a request from a
//! region it allows: an NRPT rule, a substituted address, a relay somebody else
//! runs. A proxy that already egresses in such a region does that directly, and
//! it was proven end to end rather than assumed - through a Dutch CONNECT proxy
//! the language server got a correct answer out of the model while our own relay
//! log stayed empty and not one DNS rule was involved (kb/dns.md).
//!
//! So if a user has one, it is the best route available and it is theirs, not a
//! third party we chose for them. It is asked for once, in menu 1, and may be
//! skipped with Enter.
//!
//! HTTP CONNECT only. That is what proxy clients in this space overwhelmingly
//! speak, it is the one protocol the rest of this file already implements for
//! the relay, and guessing wrong about SOCKS would fail in a way a user cannot
//! read. The prompt says so plainly.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::ClientConnection;

use crate::health::Health;

/// Reaching the proxy itself. It is usually on loopback or a short hop away.
const CONNECT_BUDGET: Duration = Duration::from_secs(5);
/// Waiting for its answer to our `CONNECT`, and for a probe to complete.
const REPLY_BUDGET: Duration = Duration::from_secs(10);
const PROBE_BUDGET: Duration = Duration::from_secs(20);

/// The host a probe asks for: the one the IDE actually uses, so a probe measures
/// the path a request will take rather than a neighbouring one.
const PROBE_HOST: &str = "daily-cloudcode-pa.googleapis.com";

/// Health of this route, consulted before every connection and updated by the
/// warm loop's probe.
pub static HEALTH: Health = Health::new("Свой прокси");

/// A user-supplied HTTP CONNECT proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    /// `user:pass`, already joined; `None` when the proxy needs no credential.
    pub auth: Option<String>,
}

impl Upstream {
    /// How it is shown back to the user - without the password, which they do
    /// not need to see again and which has no business being on screen or in a
    /// screenshot attached to a bug report.
    pub fn display(&self) -> String {
        match &self.auth {
            Some(a) => {
                let user = a.split(':').next().unwrap_or("");
                format!("{}:{}@{}:{}", user, "***", self.host, self.port)
            }
            None => format!("{}:{}", self.host, self.port),
        }
    }

    fn as_line(&self) -> String {
        match &self.auth {
            Some(a) => format!("{}@{}:{}", a, self.host, self.port),
            None => format!("{}:{}", self.host, self.port),
        }
    }
}

/// Reads what the user typed.
///
/// Deliberately forgiving about the shapes people actually paste - with or
/// without a scheme, with or without a credential - and strict about the one
/// thing that must be right, the port. A silently mis-parsed proxy would look
/// exactly like a proxy that is down.
pub fn parse(input: &str) -> Result<Upstream, String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("пустая строка".to_string());
    }
    let rest = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))
        .unwrap_or(raw);
    if rest.contains("://") {
        return Err("поддерживается только HTTP-прокси (http://…)".to_string());
    }
    // Split on the LAST '@': a password may contain one, a hostname may not.
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, hp)) => {
            if !a.contains(':') {
                return Err("логин без пароля — нужно логин:пароль@хост:порт".to_string());
            }
            (Some(a.to_string()), hp)
        }
        None => (None, rest),
    };
    let hostport = hostport.trim_end_matches('/');
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| "не указан порт — нужно хост:порт".to_string())?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("не указан адрес".to_string());
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("порт «{}» не число", port))?;
    if port == 0 {
        return Err("порт не может быть 0".to_string());
    }
    Ok(Upstream {
        host: host.to_string(),
        port,
        auth,
    })
}

/// Where the address is kept.
///
/// Beside the relay's log, because both processes have to reach it: menu 1 runs
/// as the user and writes it, and the relay - which is what actually opens the
/// connections - runs under an S4U principal for that same user and reads it.
/// A registry value or an environment variable would need a relay restart to
/// take effect; a file is picked up on the next connection.
pub fn config_path() -> PathBuf {
    crate::dns_forwarder::log_dir().join("upstream.txt")
}

pub fn save(up: &Upstream) -> Result<(), String> {
    let path = config_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(&path, up.as_line()).map_err(|e| e.to_string())
}

pub fn clear() {
    fs::remove_file(config_path()).ok();
}

/// The configured proxy, or `None` when the user skipped the question.
///
/// Read from disk every time rather than cached: the relay runs for weeks, and a
/// user who changes or removes their proxy in menu 1 should not have to restart
/// a background service for it to matter. One small read per connection is
/// nothing beside the handshake that follows it - the same reasoning the old CA
/// lookup used.
pub fn configured() -> Option<Upstream> {
    let raw = fs::read_to_string(config_path()).ok()?;
    parse(&raw).ok()
}

/// Whether the route should be tried for this connection.
///
/// Three things have to hold: the user gave us one, it is answering, and it
/// comes out somewhere Google will accept. The last is checked against a pinned
/// address rather than a clock - see `BAD_EXIT`.
pub fn available() -> bool {
    configured().is_some() && bad_exit().is_none() && !HEALTH.is_benched()
}

fn basic(auth: &str) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let data = auth.as_bytes();
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Opens a tunnel to `host:port` through the user's proxy.
///
/// Everything that can fail happens here, before the caller has told its client
/// anything - the same rule the relay route follows (I35). A `None` means the
/// caller still holds an untouched client socket and can take another route.
pub fn open(up: &Upstream, host: &str, port: u16) -> Result<TcpStream, String> {
    let addr = format!("{}:{}", up.host, up.port);
    let mut sock = addr
        .parse()
        .map(|a| TcpStream::connect_timeout(&a, CONNECT_BUDGET))
        .unwrap_or_else(|_| TcpStream::connect(&addr))
        .map_err(|e| format!("{} недоступен: {}", up.display(), e))?;
    sock.set_read_timeout(Some(REPLY_BUDGET)).ok();
    sock.set_write_timeout(Some(REPLY_BUDGET)).ok();

    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(a) = &up.auth {
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", basic(a)));
    }
    req.push_str("\r\n");
    sock.write_all(req.as_bytes())
        .map_err(|e| format!("не отправить CONNECT: {}", e))?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8 * 1024 {
            return Err("прокси ответил чем-то очень длинным".to_string());
        }
        match sock.read(&mut byte) {
            Ok(0) => return Err("прокси закрыл соединение".to_string()),
            Ok(_) => head.push(byte[0]),
            Err(e) => return Err(format!("нет ответа: {}", e)),
        }
    }
    let status = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    if !status.contains(" 200") {
        // 407 is the one worth naming: it is a credential problem, not an outage,
        // and it will not fix itself however long the route is benched.
        if status.contains(" 407") {
            return Err("прокси требует логин и пароль".to_string());
        }
        return Err(format!("прокси отказал: {}", status));
    }
    Ok(sock)
}

/// A full request through the proxy: TLS to Google inside the tunnel, and an
/// answer back. What a probe has to prove is that the route *carries* something,
/// not merely that the proxy accepts a CONNECT - the relay taught that lesson by
/// accepting tunnels for an hour and cutting every one at the handshake.
pub fn probe(up: &Upstream) -> Result<(), String> {
    let mut sock = open(up, PROBE_HOST, 443)?;
    sock.set_read_timeout(Some(PROBE_BUDGET)).ok();
    sock.set_write_timeout(Some(PROBE_BUDGET)).ok();
    let name = ServerName::try_from(PROBE_HOST).map_err(|e| e.to_string())?;
    let mut tls =
        ClientConnection::new(crate::proxy::probe_config(), name).map_err(|e| e.to_string())?;
    let mut stream = rustls::Stream::new(&mut tls, &mut sock);
    let req = format!(
        "GET /v1internal:probe HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        PROBE_HOST
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("рукопожатие: {}", e))?;
    let mut buf = [0u8; 64];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("ответа нет: {}", e))?;
    // Any status line means the tunnel carried a request end to end; which status
    // it is says nothing, since the path is deliberately not a real API call.
    if n > 0 && buf.starts_with(b"HTTP/") {
        Ok(())
    } else {
        Err("ответ не похож на HTTP".to_string())
    }
}

/// Checked on the warm loop, so the route is judged on our time and never with
/// somebody's request.
pub fn probe_health() {
    let Some(up) = configured() else {
        return;
    };

    // Where it comes out is checked first, and separately, because it answers a
    // different question. A proxy can be perfectly responsive and still be
    // useless: if it surfaces in the blocked region, Google refuses the request
    // with the very 400 this whole tool exists to remove - and that refusal is
    // invisible from here, because it arrives inside the client's own TLS. The
    // exit address is the one part of it we *can* see, so it is what the route
    // is judged on.
    match exit_info(&up) {
        Some((ip, loc)) if region_is_blocked(&loc) => {
            note_blocked_exit(&ip, &loc);
            // Nothing else is worth measuring: it is not coming back until the
            // address changes, and this runs again in two minutes to see if it
            // has.
            return;
        }
        Some((ip, loc)) => note_usable_exit(&ip, &loc),
        // Cloudflare unreachable through it. That is a fault of its own and the
        // carry probe below will say so; it is not evidence about the region, so
        // an existing verdict is left standing.
        None => {}
    }

    match probe(&up) {
        Ok(()) => HEALTH.revive("проверка прошла"),
        Err(why) => {
            crate::dns_forwarder::log_proxy(&format!("свой прокси не отвечает: {}", why));
            HEALTH.probe_failed();
        }
    }
}

/// Which country the proxy comes out in, as Cloudflare sees it.
///
/// The single most useful thing to tell a user at setup time. A proxy that exits
/// in the blocked region changes the address and nothing else - measured on WARP,
/// which reported `loc=RU` exactly like the direct connection - so it cannot lift
/// the gate, and saying so at once saves them believing otherwise.
pub fn exit_country(up: &Upstream) -> Option<String> {
    exit_info(up).map(|(_, loc)| loc)
}

/// The address the proxy comes out on, and the country Cloudflare puts it in.
///
/// The address matters as much as the country: a proxy that surfaces somewhere
/// blocked is unusable *at that exit*, and the way it becomes usable again is by
/// rotating to another one. Watching the address is how we notice that without
/// asking the user to press anything.
pub fn exit_info(up: &Upstream) -> Option<(String, String)> {
    const HOST: &str = "www.cloudflare.com";
    let mut sock = open(up, HOST, 443).ok()?;
    sock.set_read_timeout(Some(PROBE_BUDGET)).ok();
    sock.set_write_timeout(Some(PROBE_BUDGET)).ok();
    let name = ServerName::try_from(HOST).ok()?;
    let mut tls = ClientConnection::new(crate::proxy::probe_config(), name).ok()?;
    let mut stream = rustls::Stream::new(&mut tls, &mut sock);
    stream
        .write_all(
            format!(
                "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                HOST
            )
            .as_bytes(),
        )
        .ok()?;
    let mut body = Vec::new();
    let mut chunk = [0u8; 2048];
    while let Ok(n) = stream.read(&mut chunk) {
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > 8 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&body);
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
            .filter(|v| !v.is_empty())
    };
    Some((field("ip=")?, field("loc=")?))
}

/// The exit the route was last found unusable at, if it is standing down for
/// that reason.
///
/// Separate from the timed bench on purpose. A bench answers "is it responding",
/// and waiting longer is the right response to that. This answers "does it come
/// out somewhere Google will refuse", and no amount of waiting fixes it - only a
/// different exit does. So it is held against the address itself: pinned when a
/// blocked exit is seen, released the moment the address changes.
static BAD_EXIT: Mutex<Option<String>> = Mutex::new(None);

fn bad_exit() -> Option<String> {
    BAD_EXIT.lock().ok().and_then(|g| g.clone())
}

/// Records that this exit is in a region that is blocked, so the route stands
/// down until the address changes. Quiet when it is the same exit as last time -
/// this runs on a timer and would otherwise repeat itself forever.
fn note_blocked_exit(ip: &str, loc: &str) {
    let Ok(mut pinned) = BAD_EXIT.lock() else {
        return;
    };
    if pinned.as_deref() == Some(ip) {
        return;
    }
    *pinned = Some(ip.to_string());
    crate::dns_forwarder::log_proxy(&format!(
        "свой прокси выходит через {} ({}) — это заблокированный регион,          маршрут отключён до смены выхода",
        ip, loc
    ));
}

/// Releases the pin, because the exit moved somewhere usable.
fn note_usable_exit(ip: &str, loc: &str) {
    let Ok(mut pinned) = BAD_EXIT.lock() else {
        return;
    };
    if pinned.is_none() {
        return;
    }
    *pinned = None;
    crate::dns_forwarder::log_proxy(&format!(
        "свой прокси сменил выход на {} ({}) — снова используем",
        ip, loc
    ));
}

/// Regions where a proxy is pointless, because they are the ones being blocked.
/// Not a complete list and not meant to be - it exists to catch the common case
/// of someone pointing this at a VPN that surfaces next door.
const BLOCKED_REGIONS: &[&str] = &["RU", "BY"];

pub fn region_is_blocked(loc: &str) -> bool {
    BLOCKED_REGIONS.iter().any(|r| r.eq_ignore_ascii_case(loc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_shapes_people_actually_paste() {
        let plain = Upstream {
            host: "127.0.0.1".into(),
            port: 1371,
            auth: None,
        };
        assert_eq!(parse("127.0.0.1:1371").unwrap(), plain);
        assert_eq!(parse("http://127.0.0.1:1371").unwrap(), plain);
        assert_eq!(parse("  http://127.0.0.1:1371/  ").unwrap(), plain);
        assert_eq!(
            parse("http://user:pw@proxy.example.com:8080").unwrap(),
            Upstream {
                host: "proxy.example.com".into(),
                port: 8080,
                auth: Some("user:pw".into())
            }
        );
        // A password may contain '@'; a hostname may not, so the last one wins.
        assert_eq!(
            parse("user:p@ss@proxy.example.com:8080").unwrap().auth,
            Some("user:p@ss".into())
        );
    }

    /// A mis-parsed proxy is indistinguishable from a proxy that is down, so
    /// anything ambiguous has to be refused while the user is still looking.
    #[test]
    fn refuses_what_it_cannot_be_sure_of() {
        for bad in [
            "",
            "   ",
            "proxy.example.com",
            "proxy.example.com:",
            "proxy.example.com:port",
            "proxy.example.com:0",
            "socks5://127.0.0.1:1080",
            "user@proxy.example.com:8080",
        ] {
            assert!(parse(bad).is_err(), "should have been refused: {:?}", bad);
        }
    }

    /// A password must not come back out onto the screen.
    #[test]
    fn the_password_is_never_displayed() {
        let up = parse("bob:hunter2@proxy.example.com:8080").unwrap();
        let shown = up.display();
        assert!(!shown.contains("hunter2"), "{}", shown);
        assert!(shown.contains("bob") && shown.contains("proxy.example.com:8080"));
    }

    /// Round-trip through the file format, since that is what the relay reads.
    #[test]
    fn survives_the_trip_through_the_config_line() {
        for raw in [
            "127.0.0.1:1371",
            "bob:hunter2@proxy.example.com:8080",
            "[::1]:3128",
        ] {
            let up = parse(raw).unwrap();
            assert_eq!(parse(&up.as_line()).unwrap(), up, "{}", raw);
        }
    }

    /// A blocked exit stands the route down, and only a *different* address
    /// brings it back - not a timer, because waiting does not move a proxy.
    ///
    /// The one test that touches the pin; keep it that way, or two of them in
    /// parallel will fight over the same global.
    #[test]
    fn a_blocked_exit_stands_the_route_down_until_the_address_changes() {
        *BAD_EXIT.lock().unwrap() = None;

        note_blocked_exit("203.0.113.7", "RU");
        assert_eq!(bad_exit().as_deref(), Some("203.0.113.7"));

        // Same exit seen again on the next pass: still down, and it must not
        // announce itself a second time.
        note_blocked_exit("203.0.113.7", "RU");
        assert_eq!(bad_exit().as_deref(), Some("203.0.113.7"));

        // Rotated, still blocked: down, now pinned to the new address.
        note_blocked_exit("198.51.100.4", "BY");
        assert_eq!(bad_exit().as_deref(), Some("198.51.100.4"));

        // Rotated somewhere usable: back in service.
        note_usable_exit("203.0.113.9", "NL");
        assert_eq!(bad_exit(), None);
        note_usable_exit("203.0.113.9", "NL");
        assert_eq!(bad_exit(), None);
    }

    /// Live: the whole path against a real proxy, which is the only way to know
    /// the parser, the CONNECT and the probe agree with each other. Ignored by
    /// default - it needs an HTTP proxy on `127.0.0.1:1371` and a network.
    ///
    ///     cargo test upstream_route_works_against_a_real_proxy -- --ignored --nocapture
    #[test]
    #[ignore = "needs an HTTP proxy on 127.0.0.1:1371 and a live network"]
    fn upstream_route_works_against_a_real_proxy() {
        let up = parse("127.0.0.1:1371").expect("parsed");
        probe(&up).expect("the proxy carried a request to Google");
        let loc = exit_country(&up).expect("exit country");
        println!(
            "exit country: {} (blocked: {})",
            loc,
            region_is_blocked(&loc)
        );
        assert!(!loc.is_empty());
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(basic("f"), "Zg==");
        assert_eq!(basic("fo"), "Zm8=");
        assert_eq!(basic("foo"), "Zm9v");
        assert_eq!(basic("foobar"), "Zm9vYmFy");
    }

    /// The check that saves a user believing a same-region VPN will help.
    #[test]
    fn a_proxy_that_surfaces_in_the_blocked_region_is_recognised() {
        assert!(region_is_blocked("RU"));
        assert!(region_is_blocked("ru"));
        assert!(!region_is_blocked("NL"));
        assert!(!region_is_blocked(""));
    }
}
