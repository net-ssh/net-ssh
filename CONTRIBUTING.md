# Contributing to net-ssh

Run the unit tests with `bundle exec rake test` and the linter with `bundle exec rubocop`; see [README.md](README.md) and [DEVELOPMENT.md](DEVELOPMENT.md) for integration tests and debugging tips.

## Changelog

Don't edit `CHANGES.txt`. Instead, add a fragment file to `changelog.d/` in your PR; the release's version bump (`rake vbump:*`) moves all fragments into a new `=== <version>` section at the top of `CHANGES.txt` and deletes them.

A fragment is named `<number>.<type>.txt`, where `<number>` is the PR number (so open the PR first, then add the fragment), and contains a single UTF-8 paragraph: the entry as it should read in `CHANGES.txt`, without the bullet or prefix. Lines are joined, so it can be wrapped. If it doesn't end with a reference list such as `[#985, #1056]`, `[GHSA-xxxx-xxxx-xxxx]` or `[CVE-2024-12345, #1060]`, ` [#<number>]` is appended; write the list yourself to reference issues or advisories too.

| Type                | Written as                     | Use for                                                      |
| ------------------- | ------------------------------ | ------------------------------------------------------------ |
| `breaking-security` | `* BREAKING: Security: <text>` | an incompatible change made for security                     |
| `breaking`          | `* BREAKING: <text>`           | an incompatible change                                       |
| `security`          | `* Security: <text>`           | a security fix or hardening                                  |
| `change`            | `* <text>`                     | any other user-visible fix or feature                        |
| `none`              | nothing                        | PRs with no user-visible change (tests, CI, docs, refactors) |

Examples:

```sh
rake "changelog:new[1058,change,Session#exec! now returns the exit status]"
# changelog.d/1058.change.txt -> * Session#exec! now returns the exit status [#1058]

echo 'Removed the `:paranoid` option; use `:verify_host_key` [#1050]' > changelog.d/1050.breaking.txt
echo 'Reject packet lengths above 256 KB, as OpenSSH does [GHSA-pfqh-p9vh-wx4p]' > changelog.d/1060.security.txt
echo 'Custom verifiers must implement `verify_signature` [#1050]' > changelog.d/1050.breaking-security.txt
touch changelog.d/1061.none.txt
```

For several entries from one PR add a suffix: `1050.breaking.txt`, `1050.breaking.2.txt` (`changelog:new` picks the next free one).

In a release section, entries are grouped as `BREAKING: Security:`, `BREAKING:`, `Security:`, then the rest; within a group fragments are ordered by number, newest first, followed by any hand-written entries from an `=== Unreleased` section in their written order. A final release with nothing to report still gets a `=== <version>` section saying `No changes since <previous version>.`

`rake changelog:check` validates the fragments and the `=== Unreleased` section, and `rake changelog:preview` prints the section the next release would add. CI fails a PR that edits `CHANGES.txt` or doesn't add or modify a `changelog.d/<PR number>.<type>.txt` fragment, unless it only touches `changelog.d/` or a maintainer adds the `skip-changelog` label; Dependabot PRs are skipped.
