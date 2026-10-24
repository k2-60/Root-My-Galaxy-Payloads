# Adopted a55x PR #303 payload and ksud

Reference copy of the device-tested PR #303 material, kept so our custom-build
target sources at `src/targets/a55x-A556EXXUEDZE4/` remain the untouched
fallback.

- Source: PR #303, commit `84b01fe` (upstream `BuSung-dev/Root-My-Galaxy-Payloads`)
- Device: SM-A556E / a55x / A556EXXUEDZE4, kernel 6.1.157-android14-11

## Served files (this fork, k2-60 feed)

Both are byte-identical to the files shipped in PR #303.

| Repo path | Size | SHA-256 |
| --- | --- | --- |
| `artifacts/a55x-A556EXXUEDZE4/cve-2026-43499-app.so` | 104128 | `dc44017e386f5b4296b868e82c58684b1bf0060a66a8b8f209859be658d70720` |
| `kernelsu/ksud-a55x-A556EXXUEDZE4-kdp` | 4780056 | `dc3eb02640492a8d6f78f8515c6ae5c75ddbfa593f53cd0f3efdfc82a29c4219` |

The `ksud` is byte-identical to `kernelsu/ksud-e2s-S926BXXUEDZDR-kdp`
(the e2s 6.1 ksud); only the filename follows our target naming convention.

## Reference sources

- `target.h` — PR #303 a55x target, build label
  `a55x-A556EXXUEDZE4-app-production-slide8-fops8`
- `p0_fingerprint.h` — PR #303 a55x fingerprint (identical to our src copy)
- `SM-A556E-A556EXXUEDZE4.md` — PR #303 port record

## Build note

The `-app-production-slide8-fops8` variant label is only compiled when the
build defines `APP_PAYLOAD=1`. Without it, the same `target.h` builds the
`a55x-A556EXXUEDZE4-root-umh` label. The served `.so` was built with
`APP_PAYLOAD=1`.

## Feed

`support/targets-v3.json` serves this payload and ksud from the fork's raw
URLs, with `requiresFreshP0Session: true` so the app starts a fresh P0
session before running the payload.
