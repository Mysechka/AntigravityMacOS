use std::env;
use std::io::{self, Write};
use std::process::Command;

/// Suppresses the console Windows would otherwise create for a console
/// subsystem child.
///
/// This matters because the DNS relay calls `FreeConsole()` and so has no
/// console of its own: every helper it spawns gets a brand new one, which is a
/// black window flashing on the user's screen (measured - the `conhost.exe`
/// count goes up by one per spawn). Output is read through pipes, so nothing
/// needs a window. Not applied to the `color` call in `console_style`, which
/// deliberately acts on the console it is attached to.
#[cfg(target_os = "windows")]
pub fn no_window(cmd: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW)
}

#[cfg(not(target_os = "windows"))]
pub fn no_window(cmd: &mut Command) -> &mut Command {
    cmd
}

/// Runs a PowerShell snippet and hands back the raw output. Shared by the DNS
/// and routing code, which is all cmdlet-driven.
pub fn powershell(script: &str) -> Option<std::process::Output> {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    no_window(&mut cmd).output().ok()
}

pub fn clear_screen() {
    // VT is enabled at startup, so the escape sequence works everywhere and
    // avoids spawning a cmd.exe just to clear the screen.
    print!("\x1b[2J\x1b[3J\x1b[1;1H");
    io::stdout().flush().ok();
}

/// True when the host terminal renders OSC 8 hyperlinks (Windows Terminal and
/// most modern emulators). The legacy conhost window does not, so links are
/// printed as plain text there and opened through the menu instead.
pub fn supports_hyperlinks() -> bool {
    env::var("WT_SESSION").is_ok()
        || env::var("TERM_PROGRAM").is_ok()
        || env::var("ConEmuANSI").map(|v| v == "ON").unwrap_or(false)
}

// Format a URL for display. On terminals that support it the text becomes a
// real hyperlink (Ctrl+Click); elsewhere it stays a readable, selectable URL.
pub fn link(url: &str, text: &str) -> String {
    if supports_hyperlinks() {
        format!(
            "\x1b[94;4m\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\\x1b[0m\x1b[92m",
            url, text
        )
    } else {
        format!("\x1b[94;4m{}\x1b[0m\x1b[92m", text)
    }
}

// Open a URL in the system default browser (Windows: cmd /c start "" <url>).
pub fn open_url(url: &str) {
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
            .ok();
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("xdg-open").arg(url).status().ok();
    }
}

/// Prints a prompt and returns the trimmed line the user typed.
pub fn prompt(label: &str) -> String {
    print!("{}", label);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);
    input.trim().to_string()
}

/// Hint shown next to any printed link, telling the user how to follow it.
pub fn open_hint(keyword: &str) -> String {
    if supports_hyperlinks() {
        format!(
            "(Ctrl+клик по ссылке, либо введите '{}' чтобы открыть в браузере)",
            keyword
        )
    } else {
        format!("(введите '{}' чтобы открыть в браузере)", keyword)
    }
}

pub fn mask_path(path: &str) -> String {
    let mut result = path.to_string();
    if let Ok(local) = env::var("LOCALAPPDATA") {
        result = result.replace(&local, "%LOCALAPPDATA%");
    }
    if let Ok(appdata) = env::var("APPDATA") {
        result = result.replace(&appdata, "%APPDATA%");
    }
    if let Ok(userprofile) = env::var("USERPROFILE") {
        result = result.replace(&userprofile, "%USERPROFILE%");
    }
    result
}

/// A path short enough to sit in a progress line: the last few components,
/// with anything above them elided.
///
/// `mask_path` replaces the profile directories with their variable names, which
/// keeps a log honest but still runs long. This is for the screen, where the
/// only question is "which of my installs is this".
pub fn short_path(path: &str) -> String {
    // Written as a code point so no tool that rewrites escapes can turn one
    // separator into two, or none.
    const SEP: char = '\u{5C}';
    let parts: Vec<&str> = path.split(SEP).filter(|p| !p.is_empty()).collect();
    if parts.len() <= 3 {
        return path.to_string();
    }
    let sep = SEP.to_string();
    format!("...{}{}", sep, parts[parts.len() - 3..].join(&sep))
}

#[cfg(target_os = "windows")]
pub fn is_admin() -> bool {
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
    }
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(target_os = "windows"))]
pub fn is_admin() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces the relay's situation - a process with no console of its own -
    /// and checks what a spawned helper gets.
    ///
    /// Counting `conhost.exe` is not the measurement to make here:
    /// `CREATE_NO_WINDOW` still gives the child a console, it just never shows
    /// it. So this asks the child directly whether its console window is
    /// visible. Detaches the console of the test process, so run it alone.
    #[test]
    #[ignore = "detaches the console and spawns processes; run alone with --ignored"]
    fn a_helper_spawned_without_a_console_shows_no_window() {
        const SCRIPT: &str = "Add-Type -Name W -Namespace N -MemberDefinition '\
            [DllImport(\"kernel32.dll\")] public static extern System.IntPtr GetConsoleWindow();\
            [DllImport(\"user32.dll\")] public static extern bool IsWindowVisible(System.IntPtr h);'; \
            $h=[N.W]::GetConsoleWindow(); \
            if ($h -eq [System.IntPtr]::Zero) { 'no-console' } \
            elseif ([N.W]::IsWindowVisible($h)) { 'VISIBLE' } else { 'hidden' }";

        let ask = |flagged: bool| -> String {
            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT]);
            let out = if flagged {
                no_window(&mut cmd).output()
            } else {
                cmd.output()
            };
            out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "spawn failed".to_string())
        };

        crate::dns_forwarder::detach_console();

        let bare = ask(false);
        let flagged = ask(true);
        println!("without the flag: {}\nwith the flag:    {}", bare, flagged);

        assert_eq!(bare, "VISIBLE", "the bug should reproduce without the flag");
        assert_ne!(flagged, "VISIBLE", "CREATE_NO_WINDOW must hide the console");
    }
}

pub fn print_results(successes: &[String], failures: &[String]) {
    println!(
        "\n{}",
        "============================================================"
    );
    println!("{}", "ИТОГИ:");
    if !successes.is_empty() {
        println!("{}", "Успешно разблокированы:");
        for s in successes {
            println!("  {} {}", "[+]", s);
        }
    }
    if !failures.is_empty() {
        println!("{}", "Ошибки:");
        for f in failures {
            println!("  \x1b[33m[-] {}\x1b[0m\x1b[92m", f);
        }
    }
    println!(
        "{}",
        "============================================================"
    );
    println!("{}", "Чтобы вернуться в главное меню, нажмите Enter");
    let mut wait = String::new();
    io::stdin().read_line(&mut wait).unwrap();
}
