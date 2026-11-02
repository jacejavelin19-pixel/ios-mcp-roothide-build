#!/bin/sh
# Run in a scratch directory with signed mcp-memory and memory-manager-device-test.
set -eu
helper=${1:-./mcp-memory}
target=${2:-./memory-manager-device-test}
address_file=$(mktemp "${TMPDIR:-/tmp}/mcp-target.XXXXXX")
target_pid=
cleanup() {
    if [ -n "$target_pid" ]; then kill "$target_pid" 2>/dev/null || true; wait "$target_pid" 2>/dev/null || true; fi
    rm -f "$address_file"
}
trap cleanup EXIT HUP INT TERM
"$target" --target > "$address_file" &
target_pid=$!
attempt=0
while [ ! -s "$address_file" ] && [ "$attempt" -lt 20 ]; do
    sleep 0.1
    attempt=$((attempt + 1))
done
address=$(cat "$address_file")
case "$address" in ''|*[!0-9]*) echo "Target did not report an address" >&2; exit 1;; esac
end=$((address + 8))
first=$("$helper" read "$target_pid" "$address" 8)
found=$("$helper" search "$target_pid" "$address" "$end" 8N68mnhWNBI=)
written=$("$helper" write "$target_pid" "$address" EDJUdpi63P4=)
second=$("$helper" read "$target_pid" "$address" 8)
printf '%s\n%s\n%s\n%s\n' "$first" "$found" "$written" "$second"
printf '%s' "$first" | grep -q '8N68mnhWNBI='
printf '%s' "$second" | grep -q 'EDJUdpi63P4='
printf '%s' "$found" | grep -q '"matches":\["0x'
printf '%s' "$written" | grep -q '"written":8'
echo 'PASS memory helper cross-process read/write/search'
