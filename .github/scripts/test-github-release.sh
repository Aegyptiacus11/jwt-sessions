#!/usr/bin/env bash
# The tests of github-release.sh, with a gh that writes down how it was called (in a new
# temporary directory, left there).
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/github-release.sh"
work="$(mktemp -d)"
mkdir "$work/bin"
printf '#!/usr/bin/env bash\nprintf "%%s|" "$@"\nexit "${GH_EXIT:-0}"\n' > "$work/bin/gh"
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH"
cd "$work"
touch a.whl

failed=0
# expect <exit code> <text the output must have> <what is tested> <arguments...>
expect() {
  local code="$1" text="$2" what="$3" got=0 out
  shift 3
  out="$("$script" "$@" 2>&1)" || got=$?
  if [ "$got" -eq "$code" ] && [[ "$out" == *"$text"* ]]; then
    echo "ok: $what"
  else
    echo "FAILED: $what: exit code $got (expected $code), output: $out"
    failed=1
  fi
}

call="release|create|"
expect 0 "${call}v1.2.3|--verify-tag|--title|sample 1.2.3|--generate-notes|" "a release" sample v1.2.3
expect 0 "--generate-notes|a.whl|" "a release with a file, not a pre-release" sample v1.2.3 a.whl
expect 0 "--generate-notes|--prerelease|" "a pre-release of a crate" sample v1.2.3-rc.1
expect 0 "--generate-notes|--prerelease|a.whl|" "a pre-release of a Python package" sample v1.2.3rc1 a.whl
expect 1 "no file b.whl" "a file that is not there" sample v1.2.3 b.whl
expect 1 "is not v and a version" "a tag that is not a version" sample main
expect 2 "usage" "no tag" sample
GH_EXIT=4 expect 4 "$call" "gh fails" sample v1.2.3

exit "$failed"
