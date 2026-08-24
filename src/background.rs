use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::dns_forwarder;
use crate::utils::{no_window, powershell};

// Keeping the DNS relay alive across reboots.
//
// A scheduled task rather than a real service: a Windows service has to
// implement StartServiceCtrlDispatcher and a control handler or the SCM kills
// the process after ~30 seconds, which is a protocol to maintain for exactly
// the same result. A logon-triggered task is a plain background process, and
// enable/disable is one cmdlet each.
//
// Registered through the ScheduledTasks cmdlets, not schtasks.exe: the defaults
// of the latter are wrong here in two ways that only surface on a laptop weeks
// later - a task is stopped when the machine goes on battery, and it is killed
// after a 72-hour execution limit. Both are switched off explicitly below.
//
// It also restarts on failure. The relay is compiled with `panic = "abort"`, so
// any thread that goes down takes the whole process with it - and with it the
// DNS the routed names depend on, until the next logon. A restart policy is the
// only backstop available for that, since the panic cannot be caught.

const TASK_NAME: &str = "AG Unlocker DNS";
const EXE_NAME: &str = "ag_dns.exe";
/// Hidden flag that turns the unlocker into the relay. Handled before any UI.
pub const FORWARDER_FLAG: &str = "--dns-forwarder";

/// ProgramData, **not** LOCALAPPDATA. Measured on a real machine: a scheduled
/// task launching anything out of `%LOCALAPPDATA%` fails with 0x80070002, and a
/// stock `ping.exe` copied there fails identically - it is an anti-persistence
/// heuristic (a task autostarting an exe from AppData is the classic malware
/// shape), not something about our binary. The same probe from ProgramData and
/// Program Files starts cleanly.
pub fn install_dir() -> PathBuf {
    PathBuf::from(env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()))
        .join("AGUnlocker")
}

pub fn installed_exe() -> PathBuf {
    install_dir().join(EXE_NAME)
}

/// True when the logon task exists. Says nothing about whether the relay is
/// running right now - `is_running` answers that.
pub fn is_enabled() -> bool {
    let cmd = format!(
        "if (Get-ScheduledTask -TaskName '{}' -ErrorAction SilentlyContinue) {{ 'yes' }} else {{ 'no' }}",
        TASK_NAME
    );
    powershell(&cmd).map_or(false, |o| {
        String::from_utf8_lossy(&o.stdout).trim() == "yes"
    })
}

pub fn is_running() -> bool {
    let mut cmd = Command::new("tasklist");
    cmd.args(["/FI", &format!("IMAGENAME eq {}", EXE_NAME), "/NH"]);
    no_window(&mut cmd).output().map_or(false, |o| {
        String::from_utf8_lossy(&o.stdout).contains(EXE_NAME)
    })
}

fn stop_process() {
    let mut cmd = Command::new("taskkill");
    cmd.args(["/F", "/IM", EXE_NAME]);
    no_window(&mut cmd).output().ok();
}

/// Copies this exe next to its log and registers the logon task. The copy is
/// what makes autostart survive the user moving or deleting the download; it is
/// removed again by `disable`.
pub fn enable() -> Result<(), String> {
    let src = env::current_exe().map_err(|e| format!("не найден путь к exe: {}", e))?;
    let dir = install_dir();
    let dst = installed_exe();

    fs::create_dir_all(&dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    // The file cannot be replaced while the previous relay holds it open.
    stop_process();
    if src != dst {
        fs::copy(&src, &dst).map_err(|e| format!("не скопировать exe: {}", e))?;
    }

    // S4U is what keeps the logon silent. A task action run under the default
    // Interactive principal is handed a *visible* console (measured), so the
    // relay flashes a window on every logon during the moment before it can
    // call FreeConsole. S4U runs it outside any interactive session - same
    // user, no password stored, and the console it gets is hidden. It needs the
    // "log on as a batch job" right, so a machine that refuses falls back to the
    // old principal rather than ending up with no task at all.
    let cmd = format!(
        "Stop-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue; \
         $a=New-ScheduledTaskAction -Execute '{exe}' -Argument '{flag}'; \
         $t=New-ScheduledTaskTrigger -AtLogOn; \
         $s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries \
              -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew \
              -ExecutionTimeLimit ([TimeSpan]::Zero) \
              -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1); \
         $d='Antigravity Unlocker: локальный DNS-релей'; \
         try {{ \
           $p=New-ScheduledTaskPrincipal -UserId \"$env:USERDOMAIN\\$env:USERNAME\" \
                -LogonType S4U -RunLevel Limited; \
           Register-ScheduledTask -TaskName '{task}' -Action $a -Trigger $t -Settings $s \
                -Principal $p -Description $d -Force -ErrorAction Stop | Out-Null }} \
         catch {{ \
           Register-ScheduledTask -TaskName '{task}' -Action $a -Trigger $t -Settings $s \
                -Description $d -Force -ErrorAction Stop | Out-Null }}; \
         Start-ScheduledTask -TaskName '{task}'",
        exe = dst.display(),
        flag = FORWARDER_FLAG,
        task = TASK_NAME
    );

    let out = powershell(&cmd).ok_or_else(|| "не удалось запустить PowerShell".to_string())?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            "не удалось зарегистрировать задачу".to_string()
        } else {
            stderr
        });
    }
    // Stamped here rather than left to the relay: the answer has to be right the
    // moment the upgrade finishes, not a second later when the new process gets
    // around to writing it, or the menu redraws still saying "outdated".
    dns_forwarder::record_version();

    // Registering the task is not the same as the relay running. It is a console
    // process that exits 1 when it cannot bind 127.0.0.53:53, and the previous
    // one can still be holding the socket for a moment after `stop_process()`
    // returned - the task then sits at Ready with LastTaskResult 1 and there is
    // no relay, while this function has already reported success. Observed
    // exactly once, which is once more than a silent one should happen.
    for attempt in 0..RELAY_START_TRIES {
        thread::sleep(RELAY_START_SETTLE);
        if is_running() {
            return Ok(());
        }
        if attempt + 1 < RELAY_START_TRIES {
            powershell(&format!("Start-ScheduledTask -TaskName '{}'", TASK_NAME));
        }
    }
    Err("задача создана, но релей не запустился".to_string())
}

/// How long to give the relay to appear before trying again. Generous enough for
/// a UPX-packed exe to unpack and bind, short enough not to stall the menu.
const RELAY_START_SETTLE: Duration = Duration::from_millis(1200);
const RELAY_START_TRIES: usize = 3;

fn same_file_bytes(a: &Path, b: &Path) -> bool {
    match (fs::read(a), fs::read(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// True when the installed relay is byte for byte this build.
///
/// Without this check an upgrade is a no-op: a task exists and a process is
/// alive, so `ensure_running` would leave the *previous* exe installed. That is
/// how a build that fixes a background bug would keep reproducing it - the
/// running relay is still the old one.
fn installed_copy_is_current() -> bool {
    match env::current_exe() {
        Ok(src) => same_file_bytes(&src, &installed_exe()),
        Err(_) => false,
    }
}

/// True when a relay is installed and it is an older generation than this build
/// ships - the case the user has to be told about, because the relay keeps
/// running from `%ProgramData%` across reboots and a newer unlocker on its own
/// changes nothing about it.
///
/// Deliberately two cheap filesystem calls and no PowerShell: the menu redraws
/// around this, and `is_enabled()` costs a few hundred milliseconds. The exe
/// being there is what makes "no version file" mean "a relay from before
/// versioning" rather than "no relay at all".
pub fn relay_is_outdated() -> bool {
    installed_exe().exists() && dns_forwarder::installed_version() < dns_forwarder::RELAY_VERSION
}

/// Brings the relay up, reinstalling it whenever the installed copy is not this
/// build. Cheap when everything is already current, so the patch flow can call
/// it every time.
pub fn ensure_running() -> Result<(), String> {
    if is_enabled() && is_running() && installed_copy_is_current() {
        return Ok(());
    }
    enable()
}

pub fn disable() -> Result<(), String> {
    let cmd = format!(
        "Stop-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue; \
         Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false -ErrorAction SilentlyContinue",
        task = TASK_NAME
    );
    powershell(&cmd);
    stop_process();
    fs::remove_file(installed_exe()).ok();
    fs::remove_file(dns_forwarder::log_path()).ok();
    fs::remove_file(dns_forwarder::version_path()).ok();
    // Both only succeed while the directory is empty, which is what we want.
    fs::remove_dir(install_dir()).ok();
    fs::remove_dir(dns_forwarder::log_dir()).ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exe must not sit under the user profile: a scheduled task cannot
    /// launch anything from there on a machine with anti-persistence heuristics.
    #[test]
    fn the_relay_is_installed_outside_the_user_profile() {
        let exe = installed_exe();
        assert_eq!(exe.parent(), Some(install_dir().as_path()));

        let program_data = env::var("ProgramData").unwrap_or_default();
        assert!(!program_data.is_empty());
        assert!(exe.starts_with(&program_data), "got {}", exe.display());

        if let Ok(local) = env::var("LOCALAPPDATA") {
            assert!(
                !exe.starts_with(&local),
                "the task would refuse to start it"
            );
        }
    }

    /// The upgrade path depends on spotting a stale installed copy.
    #[test]
    fn a_differing_installed_copy_is_detected() {
        let dir = env::temp_dir().join("ag_relay_copy_test");
        fs::create_dir_all(&dir).expect("temp dir");
        let (a, b) = (dir.join("a.bin"), dir.join("b.bin"));

        fs::write(&a, b"build-one").unwrap();
        fs::write(&b, b"build-one").unwrap();
        assert!(
            same_file_bytes(&a, &b),
            "identical files must compare equal"
        );

        fs::write(&b, b"build-two").unwrap();
        assert!(!same_file_bytes(&a, &b), "a new build must be spotted");

        // A missing installation counts as "not current", so it gets installed.
        assert!(!same_file_bytes(&a, &dir.join("nothing-here.bin")));

        fs::remove_dir_all(&dir).ok();
    }

    /// The log goes the other way round - the relay runs unelevated and cannot
    /// write next to an exe an administrator installed.
    #[test]
    fn the_log_stays_in_the_user_profile() {
        let log = dns_forwarder::log_path();
        let local = env::var("LOCALAPPDATA").unwrap_or_default();
        assert!(!local.is_empty());
        assert!(log.starts_with(&local), "got {}", log.display());
        assert_eq!(log.parent(), Some(dns_forwarder::log_dir().as_path()));
        assert_ne!(log.parent(), Some(install_dir().as_path()));
    }
}
