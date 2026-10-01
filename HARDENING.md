<!-- markdownlint-disable -->

# Hardening Report: check-spelling--gh-program-downloader/v0.0.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **check-spelling--gh-program-downloader/v0.0.5** was hardened automatically. 2 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### github-env-injection (severity: high)

In gh-program-downloader, the `get_destination()` function writes `$destination` (sourced from the `inputs.destination` env var, set as `destination: ${{ inputs.destination }}` in action.yml) directly to `$GITHUB_OUTPUT` without sanitization: `echo "path=$destination" >> "$GITHUB_OUTPUT"`. An attacker-controlled value containing newlines could inject arbitrary key=value pairs into the output context. The required sanitization step (`printf '%s' "$destination" | tr -d '\n\r'`) is absent.

Similarly, `maybe_extract_artifact()` writes `realpath "$(dirname "$destination")" >> "$GITHUB_PATH"` — the same unsanitized `$destination` (from `inputs.destination`) flows into `$GITHUB_PATH`, allowing newline injection to add arbitrary entries to the runner's PATH.

Locations:

- `gh-program-downloader:248`
- `gh-program-downloader:278`

### script-injection (severity: high)

Sub-rule (b): Unquoted shell variable expansion of untrusted data in gh-program-downloader.

1. `os=$(echo ${os:-$(uname -s)}|tr A-Z a-z)` — the variable `$os` is set from `inputs.os` (via `env: os: ${{ inputs.os }}` in action.yml) and is expanded unquoted inside the command substitution. An attacker-supplied value with shell metacharacters (spaces, globs, etc.) will be subject to word splitting and pathname expansion before being passed to `echo`.

2. `arch=$(echo ${arch:-$(uname -m)}|tr A-Z a-z)` — same issue with `$arch` sourced from `inputs.arch` (via `env: arch: ${{ inputs.arch }}`). Both should be double-quoted: `echo "${os:-$(uname -s)}"` and `echo "${arch:-$(uname -m)}"`.

Locations:

- `gh-program-downloader:72`
- `gh-program-downloader:79`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed four issues in hardened/action/gh-program-downloader:
1. (script-injection, line 72) Quoted the os variable expansion: `echo "${os:-$(uname -s)}"` to prevent word splitting/glob expansion of attacker-controlled input.
2. (script-injection, line 79) Quoted the arch variable expansion: `echo "${arch:-$(uname -m)}"` for the same reason.
3. (github-env-injection, line 248) In get_destination(), added sanitization: `safe_destination=$(printf '%s' "$destination" | tr -d '\n\r')` before writing `path=$safe_destination` to $GITHUB_OUTPUT.
4. (github-env-injection, line 278) In maybe_extract_artifact(), added sanitization: `safe_path=$(realpath "$(dirname "$destination")" | tr -d '\n\r')` before writing to $GITHUB_PATH using printf to avoid trailing newline issues.

