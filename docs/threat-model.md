# Threat model

This document covers what ChainWatch trusts, what it does not trust, and what it sends off the
machine. It describes the code as it is in this repository. It is not a security audit.

## What ChainWatch does with the project

ChainWatch reads `package-lock.json` and the optional `chainwatch.yaml`. It sends package names
and versions to the OSV API and reads the advisories that come back. It writes a report and may
write an advisory cache. It does not install packages, run install scripts, run `npm`, or execute
any code from the project. The source tree has no process-spawning calls, so this is a property
of the code and not only of the design.

## Trust boundaries

| Input                                            | Trust                                                                                  | Handling                                                                                                                                                                          |
| ------------------------------------------------ | -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `package-lock.json`                              | Untrusted. Any contributor or dependency update can change it.                         | Parsed with a size limit (`MAX_LOCKFILE_BYTES`). Only lockfile versions 2 and 3 are accepted. Entries are read as data and never evaluated.                                       |
| `chainwatch.yaml`                                | Trusted as user input, but still validated.                                            | Strict schema: unknown keys are an error, so a typo cannot silently disable a check. Invalid config exits 2.                                                                      |
| OSV responses                                    | Untrusted. The service is external and its records can be incomplete or wrong.         | Each response is validated with Zod before use. A response that does not match the schema is treated as a failed lookup, and the scan exits 3 instead of reporting zero findings. |
| Advisory cache file                              | Untrusted. The file lives in a user-writable directory and can be edited or corrupted. | Validated with the same schema on load. A corrupt file is ignored (a cache miss) and the report says so.                                                                          |
| Advisory text (summaries, aliases, URLs)         | Untrusted. It comes from OSV.                                                          | Terminal output escapes control characters (`printable()` in `src/reports/text.ts`). HTML output escapes every value and renders only `https:` links as anchors.                  |
| Saved scan files given to `report` and `explain` | Untrusted. A file may have been edited.                                                | Read through a strict schema (`scanResultSchema`). An invalid file exits 2 with `INVALID_REPORT`. The report command makes no network calls.                                      |

## Privacy

Advisory lookups send the names and versions of registry packages in the lockfile to
`https://api.osv.dev` (the default `CHAINWATCH_OSV_URL`). They do not send the project path,
the configuration, the report, or any file contents. Git, file, and tarball dependencies are not
looked up, so their names are not sent.

Users who cannot send dependency names to a third party can use `--offline`, which reads only the
local cache and makes no request. A scan with an empty cache in offline mode exits 3, so the
result is never mistaken for a clean one.

## Output safety

- **Terminal.** Control characters in advisory or package text are printed as escape sequences,
  so a crafted summary cannot move the cursor, change the title, or hide lines.
- **HTML.** Every interpolated value is escaped. The page sets a Content Security Policy of
  `default-src 'none'; style-src 'unsafe-inline'`, so it cannot load scripts, images, or
  fonts from anywhere. Links are emitted only for `https:` URLs. Other schemes such as
  `javascript:`, `data:`, and `http:` are printed as plain text.
- **JSON.** The output follows a generated schema (`docs/schema/scan-result.schema.json`).
  Consumers should still treat string values as data.

## Cache integrity

The cache is an optimization. It is not a source of truth, and it cannot make a finding
disappear unless the user edits it. Entries carry a fetch time and expire after
`advisories.cacheTtlSeconds` (default 3600). A stale entry is counted in the report, and the
JSON result records the oldest cached fetch time. A corrupt file is discarded and the scan
continues with live lookups. `--no-cache` uses an in-memory cache and never reads or writes disk.

The cache directory is the OS user cache directory unless `CHAINWATCH_CACHE_DIR` is set.

## Policy and exceptions

The policy is a local decision. Exceptions (`policy.ignore`) are visible in the configuration
and must have an expiry date. An exception stops applying on its expiry day. The report then warns
about it and the finding counts again. Anyone who can edit `chainwatch.yaml` can accept risk, so
the file should be reviewed like any other change to CI settings.

## Failure modes that must not look like success

- OSV unreachable, timed out, or returning bad data: exit 3, "NOT a clean result".
- Offline with no cached data for some packages: exit 3.
- Non-registry dependencies: listed as not checked, and the scan is not clean.
- Exit 3 outranks exit 1, so a partial scan cannot be read as a policy pass or as a policy fail.

## Limitations

- **No reachability.** A finding means the installed version is in an advisory's range. It does
  not show that the vulnerable code is loaded or called.
- **npm only.** Only `package-lock.json` versions 2 and 3 are read. Yarn, pnpm, and Bun lockfiles
  are not supported.
- **Registry packages only.** Git, file, and tarball dependencies are listed but not checked.
- **Depends on OSV.** Coverage, accuracy, and timeliness are those of OSV. ChainWatch does not
  query GitHub Advisory Database or other sources directly.
- **Lockfile is the source.** ChainWatch cannot see what is actually installed in `node_modules`.
  A lockfile that does not match the installed tree gives a wrong picture.
- **No signature or provenance checks.** ChainWatch does not verify package tarballs, signatures,
  or publisher identity.
- **Single user.** The cache and config are per user. The tool does not manage shared
  credentials, because it has none.
- **Not published.** Builds come from source. The package distribution path is covered in the
  plan and has not been released.
