#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUST_ROOT="$ROOT/rust"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

[ "$(uname -s)" = "Linux" ] || fail "this verifier must run on Kylin/Linux"
[ -r /etc/os-release ] || fail "/etc/os-release is unavailable"

# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-} ${NAME:-}" in
    *[Kk]ylin*|*麒麟*) ;;
    *) fail "this verifier requires Kylin Advanced Server OS" ;;
esac

if [ "${CLAW_REQUIRE_LOONGARCH:-0}" = "1" ]; then
    case "$(uname -m)" in
        loongarch64|loong64) ;;
        *) fail "LoongArch verification requested, found architecture: $(uname -m)" ;;
    esac
fi

require_command cargo
require_command unshare
require_command mount
require_command sh
require_command systemctl
require_command systemd-run
require_command journalctl
require_command ss
require_command nft
require_command dnf
require_command rpm

printf 'Checking Kylin/Linux sandbox prerequisites...\n'
[ -r /proc/self/status ] || fail "/proc/self/status is unavailable"
grep -q '^Seccomp:' /proc/self/status || fail "kernel does not expose Seccomp status"
[ -r /sys/fs/cgroup/cgroup.controllers ] || fail "cgroup v2 is not mounted"
grep -qw overlay /proc/filesystems || fail "OverlayFS is unavailable"

unshare --user --map-root-user --pid --mount --net --fork true \
    || fail "PID/MNT/NET/USER namespace isolation is unavailable"

if command -v capsh >/dev/null 2>&1; then
    capsh --drop=all -- -c 'test "$(capsh --print | sed -n "s/^Current: //p")" = "="' \
        || fail "capability drop verification failed"
else
    fail "capsh is required to verify capability dropping"
fi

printf 'Running requirement-focused Rust tests...\n'
cd "$RUST_ROOT"
cargo test -p os-sense --lib -- --test-threads=1
cargo test -p ops-plugin-sdk --lib -- --test-threads=1
cargo test -p plugins --lib -- --test-threads=1
cargo test -p runtime permissions --lib -- --test-threads=1
cargo test -p runtime permission_enforcer --lib -- --test-threads=1
cargo test -p runtime sandbox --lib -- --test-threads=1
cargo test -p runtime mcp --lib -- --test-threads=1
cargo test -p tools --lib -- --test-threads=1

printf 'PASS: Kylin 4.1/4.2/4.3 requirement checks completed.\n'
