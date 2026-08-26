use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::utils::powershell;

// Which CloudCode host the client talks to, and why that is the whole fix.
//
// The region gate lives on the CloudCode API. `cloudcode-pa.googleapis.com` was
// substituted by the unblock resolvers until they dropped it, and their proxies
// refuse it by SNI, so that host cannot be reached through a permitted region
// any more (kb/dns.md). `daily-cloudcode-pa.googleapis.com` is the *same
// service* - its 401 names `service: cloudcode-pa.googleapis.com` - it is still
// substituted by geohide.ru, and geohide's proxy accepts its SNI. So the fix is
// to send the client at the host that still has a route.
//
// Nothing here patches a binary. Each surface already has a supported way to
// choose the endpoint:
//
// - Desktop passes `--cloud_code_endpoint https://daily-cloudcode-pa...` as a
//   literal in app.asar. Already on the working host; nothing to do.
// - IDE builds the argument from `getCloudCodeUrl()`, which returns
//   `cloudCodeUrlOverride` first if the `jetski.cloudCodeUrl` setting is set,
//   and otherwise the production host for any account without GCP terms - i.e.
//   every ordinary user. That setting is what we write.
// - CLI reads the `CLOUD_CODE_URL` environment variable ("UpdateEndpointURL
//   called with CLOUD_CODE_URL: %q" in agy.exe).
//
// Being configuration rather than a patch matters twice over: an app update
// cannot silently undo it the way it undoes the binary rename (G2), and a
// revert is a key removal rather than a byte-level restore.

/// The CloudCode host that still has a substituted route.
pub const DAILY_ENDPOINT: &str = "https://daily-cloudcode-pa.googleapis.com";

/// IDE setting that overrides the CloudCode base URL.
pub const IDE_SETTING: &str = "jetski.cloudCodeUrl";

/// Environment variable the CLI reads for the same purpose.
pub const CLI_ENV_VAR: &str = "CLOUD_CODE_URL";

/// What a run did, so the caller can say it out loud rather than change the
/// user's configuration silently.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The setting was written or corrected.
    Applied,
    /// Already pointing at the right host.
    AlreadySet,
    /// This build has no such setting - a future IDE may rename or drop it, and
    /// writing a key nothing reads would look like success.
    Unsupported,
}

/// Where the IDE keeps its user settings.
///
/// Derived from `product.json` rather than hardcoded: the folder is named after
/// `nameShort`, so a rebranded or renamed build still resolves correctly.
pub fn ide_settings_path(install: &Path) -> Option<PathBuf> {
    let product = install.join("resources").join("app").join("product.json");
    let text = fs::read_to_string(product).ok()?;
    let name = Regex::new(r#""nameShort"\s*:\s*"([^"]+)""#)
        .ok()?
        .captures(&text)?
        .get(1)?
        .as_str()
        .to_string();
    let appdata = std::env::var("APPDATA").ok()?;
    Some(
        PathBuf::from(appdata)
            .join(name)
            .join("User")
            .join("settings.json"),
    )
}

/// True when this IDE build actually reads the override.
fn build_reads_the_setting(install: &Path) -> bool {
    let main_js = install
        .join("resources")
        .join("app")
        .join("out")
        .join("main.js");
    fs::read_to_string(main_js).map_or(false, |src| src.contains(IDE_SETTING))
}

/// Rewrites `key` to `value`, leaving every other byte of the file alone.
///
/// A settings file is JSONC - comments and trailing commas are legal - and it
/// is the user's, not ours. Parsing and re-serialising would silently drop
/// their comments and reorder their keys, so this edits the text in place, the
/// same rule `hosts_pin` follows for the hosts file.
fn upsert_key(text: &str, key: &str, value: &str) -> Result<String, String> {
    let existing = Regex::new(&format!(r#""{}"\s*:\s*"[^"]*""#, regex::escape(key)))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    let entry = format!("\"{}\": \"{}\"", key, value);

    if existing.is_match(text) {
        return Ok(existing.replace(text, entry.as_str()).into_owned());
    }
    if text.trim().is_empty() {
        return Ok(format!("{{\n    {}\n}}\n", entry));
    }

    let cut = text
        .rfind('}')
        .ok_or_else(|| "settings.json без закрывающей скобки".to_string())?;
    let head = text[..cut].trim_end();
    let mut out = String::with_capacity(text.len() + entry.len() + 8);
    out.push_str(head);
    // An empty object needs no separator; anything else does, unless the user
    // already left a trailing comma.
    if !head.ends_with('{') && !head.ends_with(',') {
        out.push(',');
    }
    out.push_str("\n    ");
    out.push_str(&entry);
    out.push('\n');
    out.push_str(&text[cut..]);
    Ok(out)
}

/// Drops `key`, taking the separating comma with it so the file stays valid.
fn remove_key(text: &str, key: &str) -> Result<String, String> {
    let escaped = regex::escape(key);
    // As a later entry it carries a comma in front of it; as the only or first
    // entry, the comma (if any) follows.
    let trailing = Regex::new(&format!(r#",\s*"{}"\s*:\s*"[^"]*""#, escaped))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    if trailing.is_match(text) {
        return Ok(trailing.replace(text, "").into_owned());
    }
    let alone = Regex::new(&format!(r#""{}"\s*:\s*"[^"]*"\s*,?\s*"#, escaped))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    Ok(alone.replace(text, "").into_owned())
}

/// Points this IDE install at the endpoint that still resolves to a proxy.
pub fn apply_ide(install: &Path) -> Result<Outcome, String> {
    if !build_reads_the_setting(install) {
        return Ok(Outcome::Unsupported);
    }
    let path = ide_settings_path(install)
        .ok_or_else(|| "не удалось определить папку настроек IDE".to_string())?;

    // A missing file is normal on a fresh install; an unreadable one is not.
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("не прочитать {}: {}", path.display(), e)),
    };
    if text.contains(&format!("\"{}\": \"{}\"", IDE_SETTING, DAILY_ENDPOINT)) {
        return Ok(Outcome::AlreadySet);
    }

    let updated = upsert_key(&text, IDE_SETTING, DAILY_ENDPOINT)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    }
    fs::write(&path, updated).map_err(|e| format!("не записать {}: {}", path.display(), e))?;
    Ok(Outcome::Applied)
}

/// Undoes `apply_ide`. A file we never wrote to is left alone.
pub fn remove_ide(install: &Path) -> Result<(), String> {
    let Some(path) = ide_settings_path(install) else {
        return Ok(());
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(());
    };
    if !text.contains(IDE_SETTING) {
        return Ok(());
    }
    let updated = remove_key(&text, IDE_SETTING)?;
    fs::write(&path, updated).map_err(|e| format!("не записать {}: {}", path.display(), e))
}

/// Sets the CLI's endpoint variable for the current user.
///
/// Written through .NET rather than `setx`, which silently truncates a value at
/// 1024 characters and would rewrite the rest of the environment block.
pub fn apply_cli() -> Result<Outcome, String> {
    if current_cli_endpoint().as_deref() == Some(DAILY_ENDPOINT) {
        return Ok(Outcome::AlreadySet);
    }
    let script = format!(
        "[Environment]::SetEnvironmentVariable('{}','{}','User')",
        CLI_ENV_VAR, DAILY_ENDPOINT
    );
    powershell(&script).ok_or_else(|| "не удалось записать переменную среды".to_string())?;
    Ok(Outcome::Applied)
}

/// Removes the variable, but only when it still holds the value we wrote: a
/// user (or another tool) may have pointed it somewhere themselves.
pub fn remove_cli() -> Result<(), String> {
    if current_cli_endpoint().as_deref() != Some(DAILY_ENDPOINT) {
        return Ok(());
    }
    let script = format!(
        "[Environment]::SetEnvironmentVariable('{}',$null,'User')",
        CLI_ENV_VAR
    );
    powershell(&script).ok_or_else(|| "не удалось удалить переменную среды".to_string())?;
    Ok(())
}

/// Variables that point a Go client at the local fallback proxy.
///
/// `HTTPS_PROXY` is what `net/http` reads, and the language server is a Go
/// program - which is the whole reason no binary patch is needed to route it.
pub const PROXY_ENV_VAR: &str = "HTTPS_PROXY";
pub const NO_PROXY_ENV_VAR: &str = "NO_PROXY";
/// Node keeps its own bundled trust store and does not read the Windows one, so
/// installing the CA as a system root is not enough: Antigravity's extension
/// host is Node, it calls the gate host itself, and it answered `self signed
/// certificate in certificate chain` until this was set. Points at the same
/// per-machine CA that is already in the user's root store, so it widens nothing
/// that was not already trusted.
pub const NODE_CA_ENV_VAR: &str = "NODE_EXTRA_CA_CERTS";
/// Loopback never goes through the proxy: the language server serves its own
/// gRPC on 127.0.0.1 and talks to the extension host there.
const NO_PROXY_VALUE: &str = "127.0.0.1,localhost,::1";

/// Routes this user's Go clients through the local proxy.
///
/// Set for the whole user rather than one process because the language server is
/// launched by the IDE, not by us - there is no parent to inject an environment
/// into. That breadth is the cost of the design, and the reason the proxy
/// tunnels everything it does not carry straight through instead of failing:
/// anything else on the machine that picks the variable up keeps working.
pub fn apply_proxy(url: &str, ca_path: &str) -> Result<Outcome, String> {
    if current_env(PROXY_ENV_VAR).as_deref() == Some(url) {
        return Ok(Outcome::AlreadySet);
    }
    set_env(PROXY_ENV_VAR, Some(url))?;
    set_env(NO_PROXY_ENV_VAR, Some(NO_PROXY_VALUE))?;
    // The relay route terminates no TLS and installs no CA, so it needs no
    // `NODE_EXTRA_CA_CERTS`; only the legacy carrier route passes a real path.
    if !ca_path.is_empty() {
        set_env(NODE_CA_ENV_VAR, Some(ca_path))?;
    }
    Ok(Outcome::Applied)
}

/// Removes them, but only while they still hold what we wrote - a user may have
/// a proxy of their own, and taking that away would be worse than any bug here.
pub fn remove_proxy(url: &str, ca_path: &str) -> Result<(), String> {
    // Every variable is judged and removed on its own, and nothing stops at the
    // first failure. A half-removed proxy is worse than either state: the value
    // left behind names a loopback port whose listener the revert has just
    // deleted, so every program that honours it loses the network. That was
    // reported from a real machine as "не работает выход в интернет".
    let mut trouble: Vec<String> = Vec::new();

    if current_env(PROXY_ENV_VAR).is_some_and(|v| is_our_proxy_value(&v, url)) {
        if let Err(e) = set_env(PROXY_ENV_VAR, None) {
            trouble.push(e);
        }
    }
    if current_env(NO_PROXY_ENV_VAR).as_deref() == Some(NO_PROXY_VALUE) {
        if let Err(e) = set_env(NO_PROXY_ENV_VAR, None) {
            trouble.push(e);
        }
    }
    if let Err(e) = clear_node_ca(ca_path) {
        trouble.push(e);
    }

    if trouble.is_empty() {
        Ok(())
    } else {
        Err(trouble.join("; "))
    }
}

/// Whether an `HTTPS_PROXY` value is one this tool wrote.
///
/// Compared on the **address**, not on the exact string. A value that has been
/// through a settings dialog, a shell or another tool's rewrite can differ from
/// what we wrote by a trailing slash or the case of the scheme and still be
/// ours - and an exact comparison used to bail on that, leaving the variable
/// pointing at a port that no longer answers.
///
/// Safe because the address is loopback and a fixed port that only this tool
/// listens on: a proxy the user chose for themselves never names it. Their own
/// value is left alone, which matters more than removing ours.
fn is_our_proxy_value(value: &str, url: &str) -> bool {
    let strip = |s: &str| {
        s.trim()
            .trim_end_matches('/')
            .to_ascii_lowercase()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string()
    };
    let ours = strip(url);
    // Equality, not `contains`: a test caught `socks5://127.0.0.1:53129x`
    // passing a substring check, and `…:531290` would have too. Removing a
    // proxy that is not ours is the worse of the two failures here.
    !ours.is_empty() && strip(value) == ours
}

/// Drops `NODE_EXTRA_CA_CERTS` if it still holds `ca_path`, leaving a value the
/// user set themselves alone.
///
/// Separate from `remove_proxy` because an *upgrade* has to drop the old CA
/// without turning the proxy off: a machine coming from the carrier route
/// (<= 2.9.1_27) already has `HTTPS_PROXY` pointing here, so `apply_proxy`
/// returns `AlreadySet` and never reaches this. Leaving it behind would keep
/// every Node process on the machine trusting a CA nothing uses any more -
/// harmless today, and exactly the kind of leftover that is impossible to
/// explain a year from now.
pub fn clear_node_ca(ca_path: &str) -> Result<(), String> {
    if current_env(NODE_CA_ENV_VAR).as_deref() == Some(ca_path) {
        set_env(NODE_CA_ENV_VAR, None)?;
    }
    Ok(())
}


fn set_env(name: &str, value: Option<&str>) -> Result<(), String> {
    let literal = match value {
        Some(v) => format!("'{}'", v),
        None => "$null".to_string(),
    };
    let script = format!(
        "[Environment]::SetEnvironmentVariable('{}',{},'User')",
        name, literal
    );
    powershell(&script).ok_or_else(|| format!("не удалось записать {}", name))?;
    Ok(())
}

fn current_env(name: &str) -> Option<String> {
    let out = powershell(&format!(
        "[Environment]::GetEnvironmentVariable('{}','User')",
        name
    ))?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn current_cli_endpoint() -> Option<String> {
    let out = powershell(&format!(
        "[Environment]::GetEnvironmentVariable('{}','User')",
        CLI_ENV_VAR
    ))?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug users hit: a revert that left `HTTPS_PROXY` naming a port it had
    /// just deleted, so nothing on the machine could reach the network. Part of
    /// it was an exact string comparison - a value that had been through a
    /// settings dialog or another tool came back with a trailing slash or a
    /// different case and was not recognised as ours.
    #[test]
    fn our_proxy_value_is_recognised_however_it_was_written_back() {
        let url = "http://127.0.0.1:53129";
        for shape in [
            "http://127.0.0.1:53129",
            "http://127.0.0.1:53129/",
            "HTTP://127.0.0.1:53129",
            "  http://127.0.0.1:53129  ",
            "127.0.0.1:53129",
            "https://127.0.0.1:53129",
        ] {
            assert!(is_our_proxy_value(shape, url), "should be ours: {:?}", shape);
        }
    }

    /// The other half, and the more important one: a proxy the user chose for
    /// themselves must survive our revert untouched. Removing someone else's
    /// proxy is a worse failure than leaving ours behind.
    #[test]
    fn a_proxy_the_user_chose_is_never_removed() {
        let url = "http://127.0.0.1:53129";
        for theirs in [
            "http://127.0.0.1:1371",
            "http://proxy.example.com:8080",
            "http://10.0.0.1:53129",
            "socks5://127.0.0.1:53129x",
            "",
        ] {
            assert!(
                !is_our_proxy_value(theirs, url),
                "must be left alone: {:?}",
                theirs
            );
        }
    }

    const REAL: &str = "{\n    \"workbench.colorTheme\": \"Solarized Dark\",\n    \"securecoder.enabled\": true\n}";

    #[test]
    fn the_key_is_added_and_the_rest_kept_byte_for_byte() {
        let out = upsert_key(REAL, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert!(
            out.contains("\"jetski.cloudCodeUrl\": \"https://daily-cloudcode-pa.googleapis.com\"")
        );
        // Every line the user had must survive, unchanged apart from the comma
        // that now separates it from ours.
        assert!(out.contains("\"workbench.colorTheme\": \"Solarized Dark\""));
        assert!(out.contains("\"securecoder.enabled\": true"));
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{}",
            out
        );
    }

    #[test]
    fn writing_twice_changes_nothing_the_second_time() {
        let once = upsert_key(REAL, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        let twice = upsert_key(&once, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert_eq!(once, twice);
    }

    /// A value the user (or an older build) left behind must be corrected, not
    /// duplicated - two entries for one key is invalid JSON.
    #[test]
    fn a_stale_value_is_replaced_not_duplicated() {
        let stale = REAL.replace(
            "\"securecoder.enabled\": true",
            "\"securecoder.enabled\": true,\n    \"jetski.cloudCodeUrl\": \"https://cloudcode-pa.googleapis.com\"",
        );
        let out = upsert_key(&stale, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert_eq!(out.matches(IDE_SETTING).count(), 1);
        assert!(out.contains(DAILY_ENDPOINT));
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{}",
            out
        );
    }

    #[test]
    fn an_empty_or_missing_file_becomes_a_valid_object() {
        for text in ["", "   \n"] {
            let out = upsert_key(text, IDE_SETTING, DAILY_ENDPOINT).expect("created");
            let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
            assert_eq!(parsed[IDE_SETTING], DAILY_ENDPOINT);
        }
    }

    #[test]
    fn an_empty_object_gets_no_stray_comma() {
        let out = upsert_key("{}", IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{}",
            out
        );
        assert!(!out.contains("{,"));
    }

    /// The user's own trailing comma is legal JSONC and must not produce two.
    #[test]
    fn a_trailing_comma_is_not_doubled() {
        let out =
            upsert_key("{\n    \"a\": \"b\",\n}", IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert!(!out.contains(",,"), "{}", out);
    }

    #[test]
    fn a_file_without_a_closing_brace_is_refused() {
        assert!(upsert_key("not json at all", IDE_SETTING, DAILY_ENDPOINT).is_err());
    }

    #[test]
    fn removal_restores_valid_json_without_our_key() {
        for original in [REAL, "{}", "{\n    \"a\": \"b\"\n}"] {
            let with = upsert_key(original, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
            let without = remove_key(&with, IDE_SETTING).expect("removed");
            assert!(!without.contains(IDE_SETTING), "{}", without);
            assert!(
                serde_json::from_str::<serde_json::Value>(&without).is_ok(),
                "{}",
                without
            );
        }
    }

    /// Removing ours must not take the user's settings with it.
    #[test]
    fn removal_keeps_everything_else() {
        let with = upsert_key(REAL, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        let without = remove_key(&with, IDE_SETTING).expect("removed");
        let parsed: serde_json::Value = serde_json::from_str(&without).expect("valid json");
        assert_eq!(parsed["workbench.colorTheme"], "Solarized Dark");
        assert_eq!(parsed["securecoder.enabled"], true);
    }

    #[test]
    fn removing_a_key_that_is_not_there_is_a_no_op() {
        assert_eq!(remove_key(REAL, IDE_SETTING).expect("no-op"), REAL);
    }

    /// The endpoint has to be the host that is actually still substituted; the
    /// production one is exactly what stopped working.
    #[test]
    fn the_endpoint_is_the_daily_host() {
        assert!(DAILY_ENDPOINT.starts_with("https://daily-cloudcode-pa."));
        assert!(!DAILY_ENDPOINT.contains("sandbox"));
    }

    /// Against the real install: the two things unit tests cannot check are
    /// whether the settings path resolves to the folder the IDE actually reads,
    /// and whether this build still carries the setting at all.
    #[test]
    #[ignore = "needs a real Antigravity IDE install; run with --ignored"]
    fn finds_the_real_ide_settings_file() {
        let install = PathBuf::from(std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA"))
            .join("Programs")
            .join("Antigravity IDE");
        if !install.exists() {
            println!("no IDE install at {}", install.display());
            return;
        }
        let path = ide_settings_path(&install).expect("settings path");
        println!("settings: {} (exists: {})", path.display(), path.exists());
        println!(
            "build reads {}: {}",
            IDE_SETTING,
            build_reads_the_setting(&install)
        );
        assert!(
            path.ends_with("User\\settings.json"),
            "unexpected shape: {}",
            path.display()
        );
        assert!(
            build_reads_the_setting(&install),
            "this IDE build has no {} - the override would be a no-op",
            IDE_SETTING
        );
    }
}
