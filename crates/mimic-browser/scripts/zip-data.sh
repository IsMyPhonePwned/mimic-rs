#!/usr/bin/env bash
# Create clamav-db.zip from www/data/ for mimic-browser.
# The browser fetches /data/clamav-db.zip on the fly and extracts signature files.
# Run from crates/mimic-browser:  ./scripts/zip-data.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$(cd "$SCRIPT_DIR/../www/data" && pwd)"
ZIP_PATH="$DATA_DIR/clamav-db.zip"

if [[ ! -d "$DATA_DIR" ]]; then
  echo "Data directory not found: $DATA_DIR"
  exit 1
fi

cd "$DATA_DIR"
# Exclude diff/sign/txt to keep zip smaller; include .cvd .cld and other sig files
zip -r -q clamav-db.zip . -x '*.sign' -x '*.cdiff' -x '*.txt' -x 'clamav-db.zip'
echo "Created $ZIP_PATH ($(du -h "$ZIP_PATH" | cut -f1))"
