#!/bin/bash

# *** Create SVM models from training data. ***
#
# This script is run automatically after device_classifier 
# has been launched in training mode.
#
# It can be also run as a standalone script, but it is not recommended.
# See README for more details.

WD="$PWD/libsvm"
GLOBAL_DB="$WD/dataset/db.svm"
LOCAL_DB="${GLOBAL_DB}.tmp"
ORIG_DB="${GLOBAL_DB}.orig"
TOOLS="$WD/tools/"

if [ ! -f "$GLOBAL_DB.gz" ]; then
    echo "Error: Training dataset $GLOBAL_DB missing."
    echo "Try restoring file from $ORIG_DB or reinstall the module."
    exit 1
fi

if [ ! -d "$WD" -o ! -d "$TOOLS" ]; then
    echo "Error: Libsvm library corrupted. Please reinstall the module."
    exit 1
fi

if [ ! -e "${GLOBAL_DB}.orig.gz" ]; then
    cp "$GLOBAL_DB.gz" "${GLOBAL_DB}.orig.gz"
fi

gzip -d "$GLOBAL_DB.gz"

if [ ! -f "$LOCAL_DB" ]; then
    echo "Warning: No new training data available. You should run device_classifier in training mode at first."
else
    cat "$LOCAL_DB" >> "$GLOBAL_DB"
    rm "$LOCAL_DB"
fi

cd "$TOOLS"
"./binary.py" "$GLOBAL_DB" # train multi-label classifier

gzip "$GLOBAL_DB"

echo "Done!"
exit 0