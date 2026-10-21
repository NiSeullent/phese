#!/bin/sh
# Build from this trusted checkout. No network fetches or implicit package installs.
set -eu
PHSE_CHECKOUT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec /usr/bin/python3 -I -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from phese.setup import bootstrap_main; raise SystemExit(bootstrap_main())' "$PHSE_CHECKOUT" "$@"
