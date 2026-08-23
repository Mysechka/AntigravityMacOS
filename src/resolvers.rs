use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use crate::dns_client;

// Choosing an unblock resolver at query time instead of trusting one forever.
//
// Why this module exists: on 2026-08-24 xbox-dns.ru silently dropped
// `cloudcode-pa.googleapis.com` from the list of names it substitutes. Measured
// over a raw socket, it answers that name with the genuine Google address
// (172.217.x, TTL 300) while still substituting `generativelanguage` to its
// proxy (87.228.47.204, TTL 60). comss.one and geohide.ru had done the same.
// Nothing in the tool noticed: the relay forwarded, the NRPT rules applied, the
// answer arrived - it was simply not a substituted answer any more.
//
// A single hardcoded resolver cannot detect that, so the relay now asks every
// provider at once and, in parallel, a reference resolver that is known NOT to
// substitute anything. An answer equal to the reference is a passthrough, and
// the next provider is tried; an answer that differs is a real substitution.
// When a provider re-adds a name, or a new provider is added below, it starts
// being used with no code change and no release.

/// One unblock service. Addresses are tried in order; the first that answers
/// speaks for the provider, so a dead front-end does not cost it the race.
pub struct Provider {
    pub name: &'static str,
    pub v4: &'static [&'static str],
    pub v6: &'static [&'static str],
}

/// Services that substitute Google/AI endpoints for clients they geolocate to a
/// blocked region. All three were verified to answer over plain UDP:53 and to
/// front a real SNI proxy (see kb/dns.md); their lists differ and change
/// without notice, which is exactly why the choice is made per query.
pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "xbox-dns.ru",
        v4: &["111.88.96.50", "111.88.96.51"],
        v6: &["2a00:ab00:1233:26::50", "2a00:ab00:1233:26::51"],
    },
    Provider {
        name: "comss.one",
        v4: &["83.220.169.155", "212.109.195.93", "195.133.25.16"],
        v6: &[],
    },
    Provider {
        name: "geohide.ru",
        v4: &["45.155.204.190", "37.230.192.51"],
        v6: &["2a0c:9300:0:54::1"],
    },
];

/// Resolvers used only to recognise an unsubstituted answer. They must be
/// services with no geo-unblocking of their own - that is the whole point of
/// the comparison - and are never used to answer the client.
pub const REFERENCE_V4: &[&str] = &["8.8.8.8", "1.1.1.1"];

/// Addresses the DPI on the ISP link injects instead of the real answer for
/// some names (measured: both 1.1.1.1 and 8.8.8.8 return this pair for
/// `example.com` and `chatgpt.com` over that link). A reference poisoned this
/// way would make every provider look like it substituted, so these are dropped
/// before the comparison and an all-stub reference counts as no reference.
const REFERENCE_STUBS: &[Ipv4Addr] = &[Ipv4Addr::new(8, 6, 112, 0), Ipv4Addr::new(8, 47, 69, 0)];

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

/// How long a decision is reused before the providers are raced again. Short
/// enough to pick up a list change within minutes, long enough that the routed
/// names - which Windows re-asks every 60 s, the substituted TTL - cost one
/// upstream query each rather than a fan-out to every provider.
const CHOICE_TTL: Duration = Duration::from_secs(5 * 60);

/// Budget for a full race. The Windows DNS client gives a nameserver about a
/// second before moving to the next one in the NRPT rule, and that fallback is
/// a direct provider query whose unsubstituted answer would then be cached for
/// its full TTL. Providers answer in 30-80 ms, so this is generous and still
/// well inside that window.
const RACE_BUDGET: Duration = Duration::from_millis(700);

/// Timeout for a single upstream query once a provider has been chosen.
const QUERY_TIMEOUT: Duration = Duration::from_secs(4);

/// Names every one of these services exists to unblock. Asking a provider for
/// one is how the relay learns what that provider's proxy address actually
/// looks like, instead of trying to recognise Google's netblocks - which span a
/// dozen unrelated /8s and change.
///
/// The answer is only believed when it differs from what the reference resolver
/// says for the same name, so a provider that stops proxying a control name
/// yields an empty set rather than teaching the relay that Cloudflare is a
/// proxy.
///
/// Several names, used in rotation, for two reasons. This source is public, so
/// a provider can read exactly what the relay asks and when: one fixed control
/// name is a crisp signature and a single point to special-case. And they are
/// deliberately spread across unrelated operators (Cloudflare, Anthropic,
/// Google), so no single upstream change takes the whole set out. All five were
/// measured proxied by all three providers.
///
/// Avoid `grok.com` here: the DPI on the ISP link answers it with the stub pair,
/// so the reference is unusable and nothing can be learned from it.
const CONTROL_NAMES: &[&str] = &[
    "chatgpt.com",
    "api.openai.com",
    "claude.ai",
    "gemini.google.com",
    "ai.google.dev",
];

/// How long learned proxy addresses are kept. Long, because they are stable and
/// the set is a union: geohide rotates between three addresses in three
/// unrelated /16s, so a single probe only ever sees part of it.
const PROXY_SET_TTL: Duration = Duration::from_secs(30 * 60);

/// Proxy addresses learned per provider, with the moment the entry was last
/// refreshed.
static PROXY_SET: Mutex<Option<HashMap<usize, (Vec<IpAddr>, Instant)>>> = Mutex::new(None);

/// A substituted address is only useful if the client can actually open a TLS
/// connection to it, and that does not follow from answering DNS: geohide hands
/// out three proxy addresses for `daily-cloudcode-pa` and `95.182.120.241`
/// silently drops SYNs on 443. Handing it to the client cost ~20 s on the first
/// connection - Windows' SYN retransmission budget - before it fell through to
/// a live address. So substituted addresses are probed on the port the client
/// will use, and the dead ones are cut out of the answer.
const LIVENESS_PORT: u16 = 443;
/// Probed on the default route rather than the ISP interface: DNS has to dodge
/// the tunnel, but the client's own connection will not, so this must ask the
/// question the client is going to ask.
const LIVENESS_BUDGET: Duration = Duration::from_millis(500);
const LIVENESS_TTL_ALIVE: Duration = Duration::from_secs(10 * 60);
/// Short, so an address that comes back is used again within a minute or two
/// rather than being written off for the rest of the session.
const LIVENESS_TTL_DEAD: Duration = Duration::from_secs(60);

static LIVENESS: Mutex<Option<HashMap<IpAddr, (bool, Instant)>>> = Mutex::new(None);

/// Rotates which provider wins a tie, so equally good providers share the load
/// instead of the first entry serving everything.
static ROTATION: AtomicUsize = AtomicUsize::new(0);

/// Winning provider per (name, qtype), with the verdict that won it and the
/// moment it was decided. The verdict is remembered too, so a cache hit can
/// still tell a caller whether the answer it is about to use was substituted.
static CHOICE: Mutex<Option<HashMap<(String, u16), (usize, Verdict, Instant)>>> = Mutex::new(None);

/// Every provider's IPv6 addresses, in provider order. The NRPT rule takes
/// these only when the relay is off - with the relay up a v6 nameserver would
/// let Windows send the query straight out, skipping the relay entirely.
pub fn all_v6() -> Vec<&'static str> {
    PROVIDERS
        .iter()
        .flat_map(|p| p.v6.iter().copied())
        .collect()
}

/// One address per provider - what goes into an NRPT rule. Windows tries the
/// nameservers in order, so listing every address of one provider ahead of the
/// next provider would make a provider outage look like a total failure.
pub fn fallback_v4() -> Vec<&'static str> {
    PROVIDERS
        .iter()
        .filter_map(|p| p.v4.first().copied())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Outside every netblock the reference answered from - a proxy address.
    Substituted,
    /// A different address in the same netblock family. Google rotates its edge
    /// per query and per resolver, so this is almost always just another
    /// genuine Google address, not a substitution.
    Sibling,
    /// The same netblock the reference gave: a passthrough.
    Passthrough,
    /// No usable reference, or no addresses to compare.
    Unknown,
}

/// The netblock an address belongs to, coarse enough that Google's per-query
/// edge rotation does not look like a change: a /16 for IPv4, a /32 for IPv6.
fn block(addr: &IpAddr) -> (u8, u32) {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (4, u32::from_be_bytes([o[0], o[1], 0, 0]))
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            (6, u32::from_be_bytes([o[0], o[1], o[2], o[3]]))
        }
    }
}

/// Decides what a provider's answer is worth, given what an honest resolver
/// says for the same name (`reference`) and which addresses that provider is
/// known to hand out as its proxy (`proxy`, from `learn_proxy_addrs`).
///
/// Both inputs are needed, and this is the whole subtlety of the module.
/// Comparing against the reference alone marks `oauth2.googleapis.com` as
/// substituted whenever a provider's recursion lands on 173.194.0.0/16 while
/// the reference landed on 64.233.0.0/16 - both are plain Google, reached
/// through different edges. Nothing about the address itself separates those
/// two cases: Google's netblocks span a dozen unrelated /8s, and reverse DNS
/// does not help either (measured: 172.217.113.4, a perfectly genuine Google
/// answer, has no PTR at all, and neither does the geohide proxy). So the
/// proxy address is measured instead of guessed - see `learn_proxy_addrs`.
///
/// With no proxy knowledge yet, "differs from the honest answer" is the best
/// evidence available and is taken at face value. That is the behaviour the
/// tool had before, and it can only ever prefer a different answer to an
/// identical one - never a passthrough.
pub fn classify(candidate: &[IpAddr], reference: &[IpAddr], proxy: &[IpAddr]) -> Verdict {
    if candidate.is_empty() {
        return Verdict::Unknown;
    }
    let reference: Vec<&IpAddr> = reference
        .iter()
        .filter(|a| match a {
            IpAddr::V4(v4) => !REFERENCE_STUBS.contains(v4),
            IpAddr::V6(_) => true,
        })
        .collect();
    if reference.is_empty() {
        return Verdict::Unknown;
    }
    // Only compare within a family: an AAAA answer says nothing about the A
    // records the reference happened to return.
    let families: Vec<u8> = candidate.iter().map(|a| block(a).0).collect();
    let comparable: Vec<&&IpAddr> = reference
        .iter()
        .filter(|a| families.contains(&block(a).0))
        .collect();
    if comparable.is_empty() {
        return Verdict::Unknown;
    }

    let ref_blocks: Vec<(u8, u32)> = comparable.iter().map(|a| block(a)).collect();
    if candidate.iter().any(|a| ref_blocks.contains(&block(a))) {
        return Verdict::Passthrough;
    }
    if proxy.is_empty() {
        return Verdict::Substituted;
    }
    let proxy_blocks: Vec<(u8, u32)> = proxy.iter().map(block).collect();
    if candidate.iter().any(|a| proxy_blocks.contains(&block(a))) {
        return Verdict::Substituted;
    }
    Verdict::Sibling
}

/// How much a verdict is worth when picking a winner.
fn rank(v: Verdict) -> u8 {
    match v {
        Verdict::Substituted => 3,
        Verdict::Unknown => 2,
        Verdict::Sibling => 1,
        Verdict::Passthrough => 0,
    }
}

fn cached_liveness(addr: &IpAddr) -> Option<bool> {
    let guard = LIVENESS.lock().ok()?;
    let (alive, at) = guard.as_ref()?.get(addr)?;
    let ttl = if *alive {
        LIVENESS_TTL_ALIVE
    } else {
        LIVENESS_TTL_DEAD
    };
    (at.elapsed() < ttl).then_some(*alive)
}

fn remember_liveness(addr: IpAddr, alive: bool) {
    if let Ok(mut guard) = LIVENESS.lock() {
        guard
            .get_or_insert_with(HashMap::new)
            .insert(addr, (alive, Instant::now()));
    }
}

/// The addresses among `addrs` that will not accept a connection.
///
/// A live proxy completes the handshake in tens of milliseconds; a black hole
/// never answers at all, so the budget separates them without waiting out the
/// operating system's own retransmission schedule. Unknown-because-slow counts
/// as dead only for `LIVENESS_TTL_DEAD`, which is short on purpose.
fn dead_addrs(addrs: &[IpAddr]) -> Vec<IpAddr> {
    let mut dead = Vec::new();
    let mut unknown = Vec::new();
    for a in addrs {
        match cached_liveness(a) {
            Some(true) => {}
            Some(false) => dead.push(*a),
            None => unknown.push(*a),
        }
    }
    if unknown.is_empty() {
        return dead;
    }

    let (tx, rx) = mpsc::channel::<(IpAddr, bool)>();
    for a in &unknown {
        let tx = tx.clone();
        let addr = *a;
        thread::spawn(move || {
            let ok = std::net::TcpStream::connect_timeout(
                &SocketAddr::new(addr, LIVENESS_PORT),
                LIVENESS_BUDGET,
            )
            .is_ok();
            tx.send((addr, ok)).ok();
        });
    }
    drop(tx);

    let deadline = Instant::now() + LIVENESS_BUDGET;
    let mut answered = 0usize;
    while answered < unknown.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok((addr, alive)) => {
                answered += 1;
                remember_liveness(addr, alive);
                if !alive {
                    dead.push(addr);
                }
            }
            Err(_) => break,
        }
    }
    // Whatever did not answer inside the budget is treated as dead for now. It
    // is not written off: the next query re-probes it after LIVENESS_TTL_DEAD.
    for a in unknown {
        if cached_liveness(&a).is_none() {
            remember_liveness(a, false);
            dead.push(a);
        }
    }
    dead
}

/// Cuts unreachable addresses out of a substituted answer.
///
/// Only substituted answers are filtered. A passthrough is Google's own edge
/// and needs no vetting, and probing it would put a TCP connection on every
/// name the relay ever sees for nothing.
fn drop_dead_addrs(reply: Vec<u8>) -> Vec<u8> {
    let addrs = dns_client::answer_addrs(&reply);
    if addrs.len() < 2 {
        // With a single address there is nothing to fall through to, so
        // removing it would turn a slow answer into no answer.
        return reply;
    }
    let dead = dead_addrs(&addrs);
    if dead.is_empty() {
        return reply;
    }
    dns_client::without_addrs(&reply, &dead).unwrap_or(reply)
}

/// What is currently known about a provider's proxy addresses.
fn known_proxy_addrs(idx: usize) -> Vec<IpAddr> {
    let Ok(guard) = PROXY_SET.lock() else {
        return Vec::new();
    };
    guard
        .as_ref()
        .and_then(|m| m.get(&idx))
        .filter(|(_, at)| at.elapsed() < PROXY_SET_TTL)
        .map(|(addrs, _)| addrs.clone())
        .unwrap_or_default()
}

/// True when a provider's proxy addresses need probing again.
fn proxy_addrs_are_stale(idx: usize) -> bool {
    let Ok(guard) = PROXY_SET.lock() else {
        return false;
    };
    guard
        .as_ref()
        .and_then(|m| m.get(&idx))
        .map_or(true, |(_, at)| at.elapsed() >= PROXY_SET_TTL)
}

/// Unions freshly seen proxy addresses into what is already known.
///
/// A union rather than a replacement: a provider that rotates between several
/// proxy addresses would otherwise look like it changed its proxy on every
/// probe, and an answer served from the address the last probe missed would be
/// classified as somebody else's.
fn learn_proxy_addrs(idx: usize, addrs: Vec<IpAddr>) {
    if addrs.is_empty() {
        return;
    }
    if let Ok(mut guard) = PROXY_SET.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        let entry = map
            .entry(idx)
            .or_insert_with(|| (Vec::new(), Instant::now()));
        for a in addrs {
            if !entry.0.contains(&a) {
                entry.0.push(a);
            }
        }
        entry.1 = Instant::now();
    }
}

fn cached_choice(key: &(String, u16)) -> Option<(usize, Verdict)> {
    let guard = CHOICE.lock().ok()?;
    let map = guard.as_ref()?;
    let (idx, verdict, at) = map.get(key)?;
    (at.elapsed() < CHOICE_TTL).then_some((*idx, *verdict))
}

fn remember_choice(key: (String, u16), idx: usize, verdict: Verdict) {
    if let Ok(mut guard) = CHOICE.lock() {
        guard
            .get_or_insert_with(HashMap::new)
            .insert(key, (idx, verdict, Instant::now()));
    }
}

fn forget_choice(key: &(String, u16)) {
    if let Ok(mut guard) = CHOICE.lock() {
        if let Some(map) = guard.as_mut() {
            map.remove(key);
        }
    }
}

/// Sends `query` to every address of one provider in turn, stopping at the
/// first that answers.
fn ask_provider(provider: &Provider, query: &[u8], if_index: u32) -> Option<Vec<u8>> {
    for server in provider.v4 {
        let Ok(ip) = server.parse::<Ipv4Addr>() else {
            continue;
        };
        if let Ok(reply) = dns_client::query_raw_via(query, ip, if_index, QUERY_TIMEOUT) {
            return Some(reply);
        }
    }
    None
}

/// What one racer produced.
enum Heat {
    /// A provider's raw reply to the question the client asked.
    Provider(usize, Vec<u8>),
    /// An honest resolver's answer to the same question.
    Reference(Vec<IpAddr>),
    /// A provider's answer for `CONTROL_NAME`, i.e. its proxy address.
    Control(usize, Vec<IpAddr>),
    /// An honest resolver's answer for `CONTROL_NAME`, without which the line
    /// above cannot be believed.
    ControlReference(Vec<IpAddr>),
}

/// Asks every provider and every reference resolver at once and returns the
/// answer of the provider that actually substituted the name.
///
/// The reply is handed back as the raw bytes the provider sent, never rebuilt:
/// the relay's contract is that any record type and any EDNS option survives
/// the round trip untouched.
pub fn resolve_best(query: &[u8], if_index: u32) -> Option<(Vec<u8>, &'static str, Verdict)> {
    let qtype = dns_client::question_type(query).unwrap_or(0);
    let name = dns_client::question_name(query).unwrap_or_default();
    let key = (name, qtype);

    // Anything that is not an address lookup cannot be classified, so it goes
    // to whichever provider is already known good for this name - or the first
    // one that answers.
    let classifiable = qtype == QTYPE_A || qtype == QTYPE_AAAA;

    if let Some((idx, verdict)) = cached_choice(&key) {
        if let Some(reply) = ask_provider(&PROVIDERS[idx], query, if_index) {
            return Some((vet(reply, verdict), PROVIDERS[idx].name, verdict));
        }
        // The chosen provider went away; re-race rather than keep asking it.
        forget_choice(&key);
    }

    if !classifiable {
        let start = ROTATION.fetch_add(1, Ordering::Relaxed);
        for step in 0..PROVIDERS.len() {
            let idx = (start + step) % PROVIDERS.len();
            if let Some(reply) = ask_provider(&PROVIDERS[idx], query, if_index) {
                return Some((reply, PROVIDERS[idx].name, Verdict::Unknown));
            }
        }
        return None;
    }

    let (tx, rx) = mpsc::channel::<Heat>();
    for idx in 0..PROVIDERS.len() {
        let tx = tx.clone();
        let q = query.to_vec();
        thread::spawn(move || {
            if let Some(reply) = ask_provider(&PROVIDERS[idx], &q, if_index) {
                tx.send(Heat::Provider(idx, reply)).ok();
            }
        });
    }
    for server in REFERENCE_V4 {
        let Ok(ip) = server.parse::<Ipv4Addr>() else {
            continue;
        };
        let tx = tx.clone();
        let q = query.to_vec();
        thread::spawn(move || {
            if let Ok(reply) = dns_client::query_raw_via(&q, ip, if_index, QUERY_TIMEOUT) {
                tx.send(Heat::Reference(dns_client::answer_addrs(&reply)))
                    .ok();
            }
        });
    }

    // The control probes ride along in the same batch rather than on a timer:
    // in wall-clock they cost nothing, because everything here runs in
    // parallel, and they only run at all when something has gone stale -
    // normally once every PROXY_SET_TTL, not once per query.
    let learning = (0..PROVIDERS.len()).any(proxy_addrs_are_stale);
    if learning {
        // A different control name each round: the same one every time would be
        // a signature in a source anyone can read.
        let picked = CONTROL_NAMES[ROTATION.fetch_add(1, Ordering::Relaxed) % CONTROL_NAMES.len()];
        let control = dns_client::build_query(picked, 0x0C71);
        for idx in 0..PROVIDERS.len() {
            let tx = tx.clone();
            let q = control.clone();
            thread::spawn(move || {
                if let Some(reply) = ask_provider(&PROVIDERS[idx], &q, if_index) {
                    tx.send(Heat::Control(idx, dns_client::answer_addrs(&reply)))
                        .ok();
                }
            });
        }
        if let Ok(ip) = REFERENCE_V4[0].parse::<Ipv4Addr>() {
            let tx = tx.clone();
            thread::spawn(move || {
                if let Ok(reply) = dns_client::query_raw_via(&control, ip, if_index, QUERY_TIMEOUT)
                {
                    tx.send(Heat::ControlReference(dns_client::answer_addrs(&reply)))
                        .ok();
                }
            });
        }
    }
    // Every sender lives in a thread; the local one would otherwise keep the
    // channel open past the last answer.
    drop(tx);

    let deadline = Instant::now() + RACE_BUDGET;
    let mut reference: Vec<IpAddr> = Vec::new();
    let mut replies: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut control: Vec<(usize, Vec<IpAddr>)> = Vec::new();
    let mut control_reference: Vec<IpAddr> = Vec::new();
    let mut got_reference = false;
    let mut got_control_reference = false;

    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(Heat::Reference(addrs)) => {
                reference.extend(addrs);
                got_reference = true;
            }
            Ok(Heat::Provider(idx, reply)) => replies.push((idx, reply)),
            Ok(Heat::Control(idx, addrs)) => control.push((idx, addrs)),
            Ok(Heat::ControlReference(addrs)) => {
                control_reference = addrs;
                got_control_reference = true;
            }
            // Everyone finished, or nobody is left to answer.
            Err(_) => break,
        }

        // A control answer counts as a proxy address only when it differs from
        // what the honest resolver says for the same name. Without that check a
        // provider that quietly stopped proxying the control name would teach
        // the relay that Cloudflare's addresses are its proxy.
        if got_control_reference {
            while let Some((idx, addrs)) = control.pop() {
                if classify(&addrs, &control_reference, &[]) == Verdict::Substituted {
                    learn_proxy_addrs(idx, addrs);
                }
            }
        }

        // Waiting for the control probes is only worth it while they can still
        // change a verdict. Once they are in - or were never started - the
        // first clear winner ends the race.
        let still_learning = learning && !got_control_reference;
        if got_reference && !replies.is_empty() && !still_learning {
            if let Some(hit) = pick(&replies, &reference, Verdict::Substituted) {
                remember_choice(key, replies[hit].0, Verdict::Substituted);
                let (idx, reply) = replies.swap_remove(hit);
                return Some((
                    vet(reply, Verdict::Substituted),
                    PROVIDERS[idx].name,
                    Verdict::Substituted,
                ));
            }
        }
        if replies.len() == PROVIDERS.len() && got_reference && !still_learning {
            break;
        }
    }

    if replies.is_empty() {
        return None;
    }
    // Nothing substituted. Hand back the best of what arrived anyway - an
    // unsubstituted answer still resolves the name, and refusing to answer
    // would only push Windows onto the direct fallback for the same result.
    let best = best_of(&replies, &reference);
    let verdict = classify(
        &dns_client::answer_addrs(&replies[best].1),
        &reference,
        &known_proxy_addrs(replies[best].0),
    );
    remember_choice(key, replies[best].0, verdict);
    let (idx, reply) = replies.swap_remove(best);
    Some((vet(reply, verdict), PROVIDERS[idx].name, verdict))
}

/// Filters a reply before it goes back to the client, but only when it is a
/// substitution - that is the only case where the addresses belong to a third
/// party rather than to Google.
fn vet(reply: Vec<u8>, verdict: Verdict) -> Vec<u8> {
    if verdict == Verdict::Substituted {
        drop_dead_addrs(reply)
    } else {
        reply
    }
}

/// One address per provider that currently **substitutes** `name`, measured now.
///
/// This is what the NRPT fallback list must be built from. A provider that
/// returns the genuine Google address for a name has no business being a
/// fallback resolver for it: the moment the relay is a little slow (a cold
/// start is ~170 ms), Windows takes that fast genuine answer instead and caches
/// it for its full TTL, so the region error comes back intermittently for
/// minutes. Measured on a real machine: xbox-dns in `daily-cloudcode-pa`'s
/// fallback list handed out 172.217/16 on roughly one query in eight.
///
/// Probed sequentially - a handful of queries at rule-setup time, not on the
/// hot path - and bound to `if_index` so a tunnel does not make every provider
/// look like a passthrough.
pub fn substituting_addrs(name: &str, if_index: u32) -> Vec<&'static str> {
    let query = dns_client::build_query(name, 0x6767);

    let mut reference: Vec<IpAddr> = Vec::new();
    for server in REFERENCE_V4 {
        if let Ok(ip) = server.parse::<Ipv4Addr>() {
            if let Ok(reply) = dns_client::query_raw_via(&query, ip, if_index, QUERY_TIMEOUT) {
                reference.extend(dns_client::answer_addrs(&reply));
            }
        }
    }

    let mut out = Vec::new();
    for (idx, provider) in PROVIDERS.iter().enumerate() {
        let Some(reply) = ask_provider(provider, &query, if_index) else {
            continue;
        };
        let addrs = dns_client::answer_addrs(&reply);
        if classify(&addrs, &reference, &known_proxy_addrs(idx)) == Verdict::Substituted {
            if let Some(first) = provider.v4.first() {
                out.push(*first);
            }
        }
    }
    out
}

/// Resolves `name` the same way, for callers that want addresses rather than a
/// packet - `hosts_pin` writes literals, not DNS messages.
///
/// The verdict comes back with them so the caller can refuse to pin an answer
/// that was never substituted: freezing a genuine Google address into `hosts`
/// buys nothing and goes stale the moment Google rotates its edge.
pub fn resolve_a_best(name: &str, if_index: u32) -> Option<(Vec<Ipv4Addr>, &'static str, Verdict)> {
    // The id only has to be echoed back; `query_raw_via` matches on it.
    let query = dns_client::build_query(name, 0x5A5A);
    let (reply, provider, verdict) = resolve_best(&query, if_index)?;
    let addrs: Vec<Ipv4Addr> = dns_client::answer_addrs(&reply)
        .into_iter()
        .filter_map(|a| match a {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect();
    if addrs.is_empty() {
        return None;
    }
    Some((addrs, provider, verdict))
}

/// Index of the first reply with exactly `want`, in rotated provider order.
fn pick(replies: &[(usize, Vec<u8>)], reference: &[IpAddr], want: Verdict) -> Option<usize> {
    let start = ROTATION.load(Ordering::Relaxed);
    let mut best: Option<usize> = None;
    for i in 0..replies.len() {
        // Rotate over provider indices so a tie does not always go to the same
        // provider, then map back to the position in `replies`.
        let wanted_provider = (start + i) % PROVIDERS.len();
        let Some(pos) = replies.iter().position(|(idx, _)| *idx == wanted_provider) else {
            continue;
        };
        let verdict = classify(
            &dns_client::answer_addrs(&replies[pos].1),
            reference,
            &known_proxy_addrs(wanted_provider),
        );
        if verdict == want {
            best = Some(pos);
            break;
        }
    }
    if best.is_some() {
        ROTATION.fetch_add(1, Ordering::Relaxed);
    }
    best
}

/// Highest-ranked reply, ties broken by rotation.
fn best_of(replies: &[(usize, Vec<u8>)], reference: &[IpAddr]) -> usize {
    let start = ROTATION.fetch_add(1, Ordering::Relaxed);
    let mut best = 0usize;
    let mut best_rank = 0u8;
    for i in 0..replies.len() {
        let wanted_provider = (start + i) % PROVIDERS.len();
        let Some(pos) = replies.iter().position(|(idx, _)| *idx == wanted_provider) else {
            continue;
        };
        let r = rank(classify(
            &dns_client::answer_addrs(&replies[pos].1),
            reference,
            &known_proxy_addrs(wanted_provider),
        ));
        if r > best_rank {
            best_rank = r;
            best = pos;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    #[test]
    fn every_provider_has_at_least_one_address() {
        assert!(!PROVIDERS.is_empty());
        for p in PROVIDERS {
            assert!(!p.v4.is_empty(), "{} has no IPv4 address", p.name);
            for a in p.v4 {
                assert!(a.parse::<Ipv4Addr>().is_ok(), "{} is not an address", a);
            }
        }
    }

    /// The NRPT rule takes one address per provider, so a provider outage falls
    /// through to a different service rather than to its own dead sibling.
    #[test]
    fn the_fallback_list_is_one_address_per_provider() {
        let fallback = fallback_v4();
        assert_eq!(fallback.len(), PROVIDERS.len());
        for (i, p) in PROVIDERS.iter().enumerate() {
            assert_eq!(fallback[i], p.v4[0]);
        }
    }

    /// A reference resolver must never be a provider: it exists to show what an
    /// unsubstituted answer looks like.
    #[test]
    fn reference_resolvers_are_not_providers() {
        let providers: Vec<&str> = PROVIDERS
            .iter()
            .flat_map(|p| p.v4.iter().copied())
            .collect();
        for r in REFERENCE_V4 {
            assert!(!providers.contains(r), "{} is on both lists", r);
        }
    }

    /// The proxy addresses the three providers were measured handing out. In
    /// production these are learned at runtime from `CONTROL_NAME`; here they
    /// stand in for what that probe would have found.
    fn learned_proxies() -> Vec<IpAddr> {
        vec![
            v4("87.228.47.204"),
            v4("45.88.174.254"),
            v4("37.230.192.51"),
        ]
    }

    #[test]
    fn the_same_netblock_is_a_passthrough() {
        // What xbox-dns now answers for cloudcode-pa: Google's own edge, a
        // different host inside the same /16 the reference gave.
        let candidate = [v4("172.217.113.4")];
        let reference = [v4("172.217.114.4"), v4("172.217.112.4")];
        assert_eq!(
            classify(&candidate, &reference, &learned_proxies()),
            Verdict::Passthrough
        );
    }

    #[test]
    fn a_proxy_address_is_a_substitution() {
        let google = [v4("172.217.118.4")];
        for proxy in learned_proxies() {
            assert_eq!(
                classify(&[proxy], &google, &learned_proxies()),
                Verdict::Substituted,
                "{:?} is a measured proxy address",
                proxy
            );
        }
    }

    /// The false positive the proxy set exists to kill: two different Google
    /// netblocks are not a substitution. Nothing about the addresses themselves
    /// says so - only knowing what the provider's proxy looks like does.
    #[test]
    fn another_google_netblock_is_only_a_sibling() {
        assert_eq!(
            classify(
                &[v4("173.194.220.95")],
                &[v4("64.233.163.95")],
                &learned_proxies()
            ),
            Verdict::Sibling
        );
        assert!(rank(Verdict::Sibling) < rank(Verdict::Substituted));
    }

    /// Before the control probe has ever run there is nothing to recognise a
    /// proxy by, so "differs from the honest answer" is taken at face value -
    /// the behaviour the tool had before, which never prefers a passthrough.
    #[test]
    fn without_a_learned_proxy_any_difference_counts() {
        assert_eq!(
            classify(&[v4("173.194.220.95")], &[v4("64.233.163.95")], &[]),
            Verdict::Substituted
        );
        // Still not enough to call an identical answer substituted.
        assert_eq!(
            classify(&[v4("172.217.113.4")], &[v4("172.217.114.4")], &[]),
            Verdict::Passthrough
        );
    }

    /// A DPI-stubbed reference must not turn every answer into a substitution.
    #[test]
    fn a_stubbed_reference_is_no_reference() {
        let stub = [v4("8.6.112.0"), v4("8.47.69.0")];
        assert_eq!(
            classify(&[v4("172.217.118.4")], &stub, &learned_proxies()),
            Verdict::Unknown
        );
        assert_eq!(
            classify(&[v4("87.228.47.204")], &stub, &learned_proxies()),
            Verdict::Unknown
        );
    }

    #[test]
    fn nothing_to_compare_is_unknown() {
        assert_eq!(classify(&[], &[v4("8.8.8.8")], &[]), Verdict::Unknown);
        assert_eq!(classify(&[v4("87.228.47.204")], &[], &[]), Verdict::Unknown);
        // An AAAA answer against an A-only reference says nothing.
        let v6: IpAddr = "2a00:ab00:1233:26::50".parse::<IpAddr>().unwrap();
        assert_eq!(
            classify(&[v6], &[v4("172.217.118.4")], &[]),
            Verdict::Unknown
        );
    }

    #[test]
    fn a_substitution_outranks_everything_else() {
        assert!(rank(Verdict::Substituted) > rank(Verdict::Unknown));
        assert!(rank(Verdict::Unknown) > rank(Verdict::Sibling));
        assert!(rank(Verdict::Sibling) > rank(Verdict::Passthrough));
    }

    /// The reason the whole module exists: the answer that broke the tool must
    /// be recognised as not-a-substitution, so the next provider gets a turn.
    #[test]
    fn the_regression_that_broke_the_tool_is_detected() {
        let xbox_cloudcode = [v4("172.217.113.4")];
        let google = [v4("172.217.114.4")];
        assert_ne!(
            classify(&xbox_cloudcode, &google, &learned_proxies()),
            Verdict::Substituted
        );
    }

    /// The union is what makes a rotating provider recognisable: geohide serves
    /// its proxy from three addresses in three unrelated /16s, so one probe only
    /// ever sees part of the set.
    #[test]
    fn learned_proxy_addresses_accumulate() {
        let idx = PROVIDERS.len() + 41; // a slot no real provider uses
        learn_proxy_addrs(idx, vec![v4("95.182.120.241")]);
        learn_proxy_addrs(idx, vec![v4("37.230.192.51"), v4("95.182.120.241")]);
        let known = known_proxy_addrs(idx);
        assert_eq!(known.len(), 2, "duplicates must not pile up: {:?}", known);
        assert!(known.contains(&v4("37.230.192.51")));

        // An answer served from the address the first probe missed is still
        // recognised as that provider's proxy.
        assert_eq!(
            classify(&[v4("37.230.192.51")], &[v4("172.217.118.4")], &known),
            Verdict::Substituted
        );
    }

    /// The control names are the one place this tool announces itself to a
    /// provider, and the source is public. Several, from unrelated operators,
    /// so no single upstream change - or a rule aimed at this tool - takes the
    /// whole learning mechanism out.
    #[test]
    fn control_names_are_several_and_not_one_operator() {
        assert!(
            CONTROL_NAMES.len() >= 3,
            "one control name is a signature, not a probe"
        );
        let non_google = CONTROL_NAMES
            .iter()
            .filter(|n| !n.contains("google."))
            .count();
        assert!(
            non_google >= 2,
            "the set must survive a Google-side change: {:?}",
            CONTROL_NAMES
        );
        // The DPI on the ISP link stubs this one, so its reference is unusable.
        assert!(!CONTROL_NAMES.contains(&"grok.com"));
    }

    /// An empty learning round must not overwrite what is already known, or a
    /// provider that failed to answer the control probe once would lose its set.
    #[test]
    fn an_empty_probe_does_not_erase_the_set() {
        let idx = PROVIDERS.len() + 42;
        learn_proxy_addrs(idx, vec![v4("87.228.47.204")]);
        learn_proxy_addrs(idx, vec![]);
        assert_eq!(known_proxy_addrs(idx), vec![v4("87.228.47.204")]);
    }

    /// Live: what the NRPT fallback list will be built from for each routed
    /// name. `daily-cloudcode-pa` must come back with geohide only - the bug
    /// was xbox-dns/comss (which return genuine Google for it) sitting in that
    /// list and leaking. Run VPN-off.
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn substituting_addrs_excludes_passthrough_providers() {
        for name in [
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "antigravity-unleash.goog",
        ] {
            let subs = substituting_addrs(name, 0);
            println!("{:<38} substituted by {:?}", name, subs);
            // Whatever is returned must be a real provider address, never a
            // reference resolver - a reference in the fallback would be a leak.
            for s in &subs {
                assert!(
                    !REFERENCE_V4.contains(s),
                    "{} is a reference resolver, not a substituter",
                    s
                );
            }
        }
    }

    /// Live end-to-end: races the real providers and prints what each answered.
    /// Must run with the VPN off, or every provider sees a foreign client and
    /// substitutes nothing.
    #[test]
    #[ignore = "needs a live network; run with --ignored"]
    fn races_the_real_providers() {
        for name in [
            "generativelanguage.googleapis.com",
            "cloudcode-pa.googleapis.com",
        ] {
            let mut query = vec![0x77, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            for label in name.split('.') {
                query.push(label.len() as u8);
                query.extend_from_slice(label.as_bytes());
            }
            query.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);

            match resolve_best(&query, 0) {
                Some((reply, provider, verdict)) => {
                    println!(
                        "{:<38} {:?} via {} -> {:?}",
                        name,
                        verdict,
                        provider,
                        dns_client::answer_addrs(&reply)
                    );
                }
                None => println!("{:<38} no provider answered", name),
            }
        }
    }
}
