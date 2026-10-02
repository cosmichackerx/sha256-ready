#!/bin/sh
# Works with SHA-1 and SHA-256 repositories: no length assumptions.
rev=$(git rev-parse HEAD)
short=$(git rev-parse --short "$rev")
zero=$(git hash-object --stdin </dev/null | tr 0-9a-f 0)
git rev-parse --verify --quiet "$rev^{commit}" >/dev/null && echo "ok $short $zero"
