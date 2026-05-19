#!/usr/bin/env bash
# Pre-deploy duplicate-key check.
# Usage:  ./scripts/check-dupes.sh <file.js>  [<file.js> ...]
# Exit:   0=clean, 1=dupes found, 2=usage error
set -u
if [ $# -lt 1 ]; then
  echo "usage: $0 <file.js> [<file.js> ...]" >&2
  exit 2
fi
DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$DIR/check-dupes.js"
RC=0
for f in "$@"; do
  node "$SCRIPT" "$f" || RC=$?
done
exit $RC
