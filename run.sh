#!/usr/bin/env bash
# Build (if needed) and launch pentest-tui.
set -e
cd "$(dirname "$0")"
export PATH="$HOME/go-sdk/go/bin:$PATH"
go build -o web .
exec ./web "$@"
