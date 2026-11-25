#!/usr/bin/env bash
# github-release.sh <name> <tag> [file...]: the GitHub Release of a version just published,
# with notes from the pull requests merged since the last one, and the files attached. A
# version that is not numbers and dots only (0.2.0-rc.1, 0.2.0rc1) is marked a pre-release.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "::error::usage: github-release.sh <name> <tag> [file...]"
  exit 2
fi
name="$1" tag="$2"
shift 2
version="${tag#v}"
if ! [[ "$tag" =~ ^v[0-9] ]]; then
  echo "::error::$tag is not v and a version"
  exit 1
fi
for file in "$@"; do
  if [ ! -f "$file" ]; then
    echo "::error::no file $file to attach"
    exit 1
  fi
done

pre=()
if [[ "$version" =~ [^0-9.] ]]; then pre=(--prerelease); fi
gh release create "$tag" --verify-tag --title "$name $version" --generate-notes "${pre[@]}" "$@"
