#!/bin/bash

rc=0

UNTRACKED=$(git ls-files -o --exclude-standard)
if [ -n "$UNTRACKED" ]; then
  echo "Found untracked files:"
  echo "$UNTRACKED"
  rc=1
fi

if ! git diff --exit-code; then
  rc=1
fi

exit $rc
