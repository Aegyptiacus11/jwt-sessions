#!/usr/bin/env bash
# ci.yml runs on its own and inside release.yml. The two must not share a concurrency group,
# or one cancels the other; nor may
# it be release.yml's own group, which would hold the run up on itself.
set -euo pipefail

cd "$(dirname "$0")/../workflows"
# the group of workflow $1 in a run of the workflow named $2, on main
group() {
  local line
  line="$(grep -E '^  group: ' "$1")"
  line="${line#  group: }"
  line="${line//'${{ github.workflow }}'/$2}"
  echo "${line//'${{ github.ref }}'/refs/heads/main}"
}

alone="$(group ci.yml ci)"
called="$(group ci.yml release)"
release="$(group release.yml release)"
if [ "$alone" = "$called" ] || [ "$called" = "$release" ] || [ "$alone" = "$release" ]; then
  echo "::error::shared concurrency group: ci $alone, ci in a release $called, release $release"
  exit 1
fi
echo "ok: $alone, $called, $release"
