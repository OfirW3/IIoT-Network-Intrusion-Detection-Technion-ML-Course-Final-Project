#!/usr/bin/env bash
set -e

# Create the data directories in the project root (one level above bash_scripts)
BASE_DIR="../data"
PCAP_DIR="$BASE_DIR/pcaps"
RAW_DIR="$BASE_DIR/raw_csvs"
CLEAN_DIR="$BASE_DIR/cleaned_csvs"

mkdir -p "$PCAP_DIR" "$RAW_DIR" "$CLEAN_DIR"

echo "Created (or verified) directories:"
echo "  $PCAP_DIR"
echo "  $RAW_DIR"
echo "  $CLEAN_DIR"