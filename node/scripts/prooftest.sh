#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# prooftest.sh — paytest.sh's proofs part (docs/GUI_WALLET.md, phase 2): its
# setup (tabminer mining, the node, wm, a wallet paid 2.5), then the proofs
# checks; see paytest.sh.
# Usage: scripts/prooftest.sh
PART=proofs exec sh "$(dirname "$0")/paytest.sh"
