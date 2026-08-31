#!/usr/bin/env bash
# Antigravity Unlocker - Linux launcher.
#
# Runs as the normal user - NO sudo. The phase-2 region route is entirely
# unprivileged: the language server that carries the gate lives in
# ~/.local/share (user-writable), the local proxy is a systemd *user* unit, and
# HTTPS_PROXY is a user drop-in. That is also what makes "right-click > Run as a
# Program" work without a password prompt. A system-wide /opt install would need
# root to patch, but the per-user copy is the one the app actually runs.
#
# If there is no terminal (a bare double-click / "Run as a Program"), it reopens
# itself inside one so the menu has somewhere to draw.
set -u

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(cd "$(dirname "$SELF")" && pwd)"
BIN="$DIR/ag_unlocker"
chmod +x "$BIN" 2>/dev/null || true

if [ ! -x "$BIN" ]; then
    echo "Не найден исполняемый файл: $BIN" >&2
    echo "Если папка на общей шаре VM (/mnt/hgfs, /media/sf_*), скопируйте её в" >&2
    echo "домашнюю папку или запустите install.sh — оттуда запуск невозможен (noexec)." >&2
    read -r -p "Нажмите Enter для выхода..." _ || true
    exit 1
fi

# No controlling terminal -> relaunch inside a terminal emulator.
if [ ! -t 1 ]; then
    for T in x-terminal-emulator gnome-terminal konsole xfce4-terminal tilix xterm; do
        if command -v "$T" >/dev/null 2>&1; then
            case "$T" in
                gnome-terminal | tilix) exec "$T" -- "$SELF" "$@" ;;
                *) exec "$T" -e "$SELF" "$@" ;;
            esac
        fi
    done
    # No terminal emulator found: fall through and hope stdout is visible.
fi

exec "$BIN" "$@"
