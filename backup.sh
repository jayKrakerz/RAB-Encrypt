#!/usr/bin/env bash
# Usage: ./backup.sh
# Add to crontab: 0 2 * * * /path/to/backup.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$SCRIPT_DIR/backups"
DB="$SCRIPT_DIR/requests.db"
mkdir -p "$BACKUP_DIR"
TS=$(date +%Y%m%d_%H%M%S)
sqlite3 "$DB" ".backup $BACKUP_DIR/requests_$TS.db"
# Keep only the 30 most recent backups
ls -t "$BACKUP_DIR"/requests_*.db 2>/dev/null | tail -n +31 | xargs rm -f
COUNT=$(ls -1 "$BACKUP_DIR"/requests_*.db 2>/dev/null | wc -l | tr -d ' ')
echo "[$TS] Backup complete. $COUNT backup(s) stored in $BACKUP_DIR"
