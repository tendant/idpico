#!/usr/bin/env bash
# Fail if any tracked file is binary, except the embedded icons. Correctness
# must not rest on data nobody can review, and build artifacts must never be
# committed (make ci and CI run this). Uses git's own classification
# (`git ls-files --eol`: i/-text is binary in the index).
set -euo pipefail
cd "$(dirname "$0")/.."

allow='^internal/http/static/(favicon\.ico|icon\.png)$'
bad=0
while IFS= read -r line; do
	f=${line#*$'\t'}
	[[ "$f" =~ $allow ]] && continue
	echo "binary file tracked: $f" >&2
	bad=1
done < <(git ls-files --eol | awk -F'\t' '$1 ~ /^i\/-text/ {print}')
if [ "$bad" != 0 ]; then
	echo "Remove it (git rm --cached <file>) and add an ignore rule; see CLAUDE.md." >&2
	exit 1
fi
echo "no binary files tracked (icons excepted)"
