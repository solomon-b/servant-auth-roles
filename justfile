# List available recipes.
default:
    @just --list

# Run the test suite.
test:
    cabal test

# Format all Haskell sources under src/ and test/ in place.
format:
    ormolu --mode inplace $(find src test -name '*.hs')

# Format only the Haskell sources changed in the working tree.
format-changed:
    #!/usr/bin/env bash
    set -euo pipefail
    files=$( { git diff --name-only HEAD -- '*.hs'; git ls-files --others --exclude-standard -- '*.hs'; } \
        | sort -u \
        | while IFS= read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done )
    if [ -z "$files" ]; then
        echo "No changed Haskell files to format."
        exit 0
    fi
    echo "$files"
    echo "$files" | xargs ormolu --mode inplace
