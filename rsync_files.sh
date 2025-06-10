#!/bin/bash

# ----------- CONFIG -----------
LOG_FILE="/app01/secops_code/avtest_pre_rerun_review/pre_rerun_review/rsync_upload.log"
REMOTE_HOST="t3tools.akamai.com"
REMOTE_BASE="/app01/opt/splunk/var/log/avtest_pre_rerun_review"
LOCAL_BASE="/app01/secops_code/avtest_pre_rerun_review/pre_rerun_review/data_files"
# ------------------------------

# List of files to sync (just file names)
FILES=(
    "current_blacklist.csv"
    "already_exists_but_allowed.csv"
    "detection_sources.csv"
    "etp_action_id_totals.csv"
    "filtered_and_malicious.csv"
    "low_detections.csv"
    "ptlds.csv"
    "total_allowed_carrier_traffic.csv"
    "total_carrier_traffic.csv"
    "total_detected_carrier_traffic.csv"
    "total_detected_etp_traffic.csv"
    "total_etp_traffic.csv"
    "unpopular_and_allowed.csv"
)

echo "$(date '+%Y-%m-%d %H:%M:%S') - ▶️ Starting rsync batch upload" >> "$LOG_FILE"

for FILE in "${FILES[@]}"; do
    SRC="$LOCAL_BASE/$FILE"
    DEST="$REMOTE_HOST:$REMOTE_BASE/$FILE"
    if [[ -f "$SRC" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Uploading $FILE" >> "$LOG_FILE"
        rsync -azq "$SRC" "$DEST" >> "$LOG_FILE" 2>&1
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ⚠️ File not found: $SRC" >> "$LOG_FILE"
    fi
done

echo "$(date '+%Y-%m-%d %H:%M:%S') - ✅ All rsync jobs finished" >> "$LOG_FILE"
