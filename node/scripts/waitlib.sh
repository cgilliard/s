# waitlib.sh — waits for the node's scripts (sourced, after T is set to
# the script's directory in tmp/).  No wait has a deadline: a machine
# that is slower but getting on (the miners' and the OS's output under $T
# still growing) is waited for, however long; a step fails only when
# nothing under $T has changed for its idle window, which is a stall.
# The CI job's own time limit is the backstop for a run that keeps
# printing and gets nowhere.

WNAME=$(basename "$0")

# wprogress — how much the test's logs hold: the miners' and the OS's
# output (*.out) and the miners' own logs (*.log), all under $T.
# WPROGRESS, if set: a command whose output stands for the progress
# instead (a script sets it where the logs grow regardless, a miner
# mining throughout, and only some of what they hold is the awaited).
wprogress() {
	if [ -n "${WPROGRESS:-}" ]; then eval "$WPROGRESS"; return; fi
	find "$T" -type f \( -name '*.out' -o -name '*.log' \) -exec cat {} + 2>/dev/null | wc -c
}

# wdump — the end of each of the test's logs, on stderr: a failed wait
# shows why wherever the script runs (CI's own step after it may be
# folded away).
wdump() {
	for f in $(find "$T" -type f \( -name '*.out' -o -name '*.log' \) | sort); do
		echo "== $f (last 40 lines)" >&2; tail -40 "$f" >&2
		# the OS's console: what is not the node's verbose lines too (the
		# shell's, wm's, the kernel's), which the node's would push out of
		# the last 40 (wm's start or its error, early on)
		if [ "$(basename "$f")" = os.out ]; then
			echo "== $f (not the node's lines, last 40)" >&2; grep -v '^node: ' "$f" | tail -40 >&2
		fi
	done
}

# wait_for FILE REGEX IDLE WHAT — until REGEX (extended) is in FILE; fails
# when nothing under $T has grown for IDLE seconds, or when FILE itself is
# still empty after IDLE seconds, and at least WEMPTY (300 s by default):
# a QEMU that never started printing, while miners mining elsewhere under
# $T kept the other logs growing (a CI run waited out its whole 50 minutes
# so). Not the step's own window alone: a QEMU started beside a miner
# proving on every core printed nothing for the shell's 60 s on CI
# (nametest at e70b01d), though it boots in under a second idle.
wait_for() {
	wf_last=$(wprogress); wf_idle=0; wf_empty=0
	wf_elim=${WEMPTY:-300}; [ "$3" -le "$wf_elim" ] || wf_elim=$3
	until grep -qE "$2" "$1" 2>/dev/null; do
		[ "$wf_idle" -lt "$3" ] || { echo "$WNAME: $4: nothing new for $3 s" >&2; wdump; exit 1; }
		if [ -s "$1" ]; then wf_empty=0; else wf_empty=$((wf_empty + 2)); fi
		[ "$wf_empty" -le "$wf_elim" ] || { echo "$WNAME: $4: $1 still empty after $wf_elim s" >&2; wdump; exit 1; }
		sleep 2
		wf_now=$(wprogress)
		if [ "$wf_now" != "$wf_last" ]; then wf_last=$wf_now; wf_idle=0; else wf_idle=$((wf_idle + 2)); fi
	done
}

# wait_own FILE REGEX IDLE WHAT — wait_for, but only FILE's growth counts
# as progress: for a step whose program says what it is doing (the
# node's verbose lines while it syncs), so that a stall there fails
# rather than waiting on other programs' logs (a miner logging every
# block kept prooftest waiting out its job's 60 minutes on a node that
# never synced).
wait_own() {
	wo_prev=${WPROGRESS:-}
	WPROGRESS="wc -c < '$1' 2>/dev/null || echo 0"
	wait_for "$@"
	WPROGRESS=$wo_prev
}

# wait_os FILE REGEX IDLE WHAT — wait_for in the OS's console, only
# its lines that are not the node's counting as progress: for what the
# OS's other programs say (wm serving), which the node's verbose lines
# would otherwise keep waiting for (prooftest on CI: wm never said it
# served, and the node's lines kept the 60 s window from running out).
wait_os() {
	wo_prev=${WPROGRESS:-}
	WPROGRESS="grep -vc '^node: ' '$1' 2>/dev/null || echo 0"
	wait_for "$@"
	WPROGRESS=$wo_prev
}

# wait_blocks FILE REGEX LOG N WHAT — until REGEX is in FILE; fails once
# LOG (a miner's output) has told N more blocks than when the wait began
# without it: a step that should take a block or two, bounded by the
# chain's own clock, which a busy log cannot stretch (pooltest on CI
# waited out its job for a transaction never mined, the miner's log
# growing all the while); or when nothing under $T has grown for 600 s.
wait_blocks() {
	wk_0=$(grep -c 'is the tip at height' "$3" 2>/dev/null || true); wk_last=$(wprogress); wk_idle=0
	until grep -qE "$2" "$1" 2>/dev/null; do
		wk_n=$(grep -c 'is the tip at height' "$3" 2>/dev/null || true)
		[ $((wk_n - wk_0)) -lt "$4" ] || { echo "$WNAME: $5: not in $4 blocks" >&2; wdump; exit 1; }
		[ "$wk_idle" -lt 600 ] || { echo "$WNAME: $5: nothing new for 600 s" >&2; wdump; exit 1; }
		sleep 2
		wk_now=$(wprogress)
		if [ "$wk_now" != "$wk_last" ]; then wk_last=$wk_now; wk_idle=0; else wk_idle=$((wk_idle + 2)); fi
	done
}

# wait_while_busy IDLE WHAT CONDITION... — until CONDITION (a command)
# succeeds; fails as wait_for does.
wait_while_busy() {
	wb_max=$1; wb_what=$2; shift 2
	wb_last=$(wprogress); wb_idle=0
	until "$@"; do
		[ "$wb_idle" -lt "$wb_max" ] || { echo "$WNAME: $wb_what: nothing new for $wb_max s" >&2; wdump; exit 1; }
		sleep 2
		wb_now=$(wprogress)
		if [ "$wb_now" != "$wb_last" ]; then wb_last=$wb_now; wb_idle=0; else wb_idle=$((wb_idle + 2)); fi
	done
}
