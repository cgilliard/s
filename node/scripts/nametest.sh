#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# nametest.sh — paytest.sh's names part (docs/GUI_WALLET.md, phase 2): its
# setup (tabminer mining, the node, wm, a wallet paid 2.5), then the names
# checks; see paytest.sh.
# Usage: scripts/nametest.sh
PART=names exec sh "$(dirname "$0")/paytest.sh"
