#!/usr/bin/env bash
# Antigravity Unlocker - macOS installer
# Copies binary to ~/Library/Application Support/ag-unlocker and creates
# a ~/Applications/Antigravity Unlocker.command launcher.
# Automatically strips com.apple.quarantine attribute to prevent Gatekeeper blockage.
set -eu

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="$(cd "$SRC/.." && pwd)"

# Find the binary in macos dir, parent root, or target/release
BIN=""
for cand in "$SRC/ag_unlocker" "$PARENT/ag_unlocker" "$PARENT/target/release/ag_unlocker"; do
    if [ -f "$cand" ]; then
        BIN="$cand"
        break
    fi
done

APP_DIR="$HOME/Library/Application Support/ag-unlocker"
mkdir -p "$APP_DIR" "$HOME/Applications"

if [ -n "$BIN" ]; then
    cp -f "$BIN" "$APP_DIR/ag_unlocker"
    chmod 0755 "$APP_DIR/ag_unlocker"
    # Clear quarantine if downloaded from web/archive
    xattr -d com.apple.quarantine "$APP_DIR/ag_unlocker" 2>/dev/null || true
fi

cp -f "$SRC/launch.sh" "$APP_DIR/launch.sh"
chmod 0755 "$APP_DIR/launch.sh"

# Create a macOS command wrapper in ~/Applications
WRAPPER="$HOME/Applications/Antigravity Unlocker.command"
cat >"$WRAPPER" <<EOF
#!/usr/bin/env bash
exec "$APP_DIR/launch.sh" "\$@"
EOF
chmod 0755 "$WRAPPER"
xattr -d com.apple.quarantine "$WRAPPER" 2>/dev/null || true

echo
echo "============================================================"
echo " Antigravity Unlocker установлен для macOS"
echo "============================================================"
echo " Расположение: $APP_DIR"
echo " Ярлык для запуска создан в: $WRAPPER"
echo
echo " Вы также можете запустить его из Терминала:"
echo "   $APP_DIR/launch.sh"
echo "============================================================"
echo
read -r -p "Нажмите Enter для выхода..." _ || true
