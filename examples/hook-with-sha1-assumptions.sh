#!/bin/sh
# deploy helper
rev=$(git rev-parse HEAD)
short=$(echo "$rev" | cut -c1-40)
if [ "${#rev}" -eq 40 ]; then echo ok; fi
if [ "$oldrev" = "0000000000000000000000000000000000000000" ]; then echo new branch; fi
echo "$rev" | grep -E '^[0-9a-f]{40}$'
git diff 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD
git log --abbrev=40 -1
# pinned action, not a finding:
# uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
