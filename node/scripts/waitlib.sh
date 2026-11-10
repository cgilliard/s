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
wprogress() {
	find "$T" -type f \( -name '*.out' -o -name '*.log' \) -exec cat {} + 2>/dev/null | wc -c
}

# wait_for FILE REGEX IDLE WHAT — until REGEX (extended) is in FILE; fails
# when nothing under $T has grown for IDLE seconds.
wait_for() {
	wf_last=$(wprogress); wf_idle=0
	until grep -qE "$2" "$1" 2>/dev/null; do
		[ "$wf_idle" -lt "$3" ] || { echo "$WNAME: $4: nothing new for $3 s" >&2; exit 1; }
		sleep 2
		wf_now=$(wprogress)
		if [ "$wf_now" != "$wf_last" ]; then wf_last=$wf_now; wf_idle=0; else wf_idle=$((wf_idle + 2)); fi
	done
}

# wait_while_busy IDLE WHAT CONDITION... — until CONDITION (a command)
# succeeds; fails as wait_for does.
wait_while_busy() {
	wb_max=$1; wb_what=$2; shift 2
	wb_last=$(wprogress); wb_idle=0
	until "$@"; do
		[ "$wb_idle" -lt "$wb_max" ] || { echo "$WNAME: $wb_what: nothing new for $wb_max s" >&2; exit 1; }
		sleep 2
		wb_now=$(wprogress)
		if [ "$wb_now" != "$wb_last" ]; then wb_last=$wb_now; wb_idle=0; else wb_idle=$((wb_idle + 2)); fi
	done
}
