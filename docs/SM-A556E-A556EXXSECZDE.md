# SM-A556E A556EXXSECZDE target record (CZDE retarget)

**STATUS: HARDWARE-UNTESTED (retarget).** This is a re-derivation of the
CZB5 profile against the CZDE kernel after the May 2026 OTA. The offline
derivation, build gates and KernelSU carry-over gates are complete; no
exploit execution has been exercised on the device since the OTA.

## The OTA event

The device (SM-A556E/DS) took the CZDE OTA:

```text
from: A556EXXSDCZB5 (security patch 2026-02-05, build stamp Fri Feb 13 05:13:45 UTC 2026)
to:   A556EXXSECZDE (security patch 2026-05-05, build stamp Wed May  6 05:27:12 UTC 2026)
AP:   AP_A556EXXSECZDE_A556EXXSECZDE_MQB109426533_REV00_user_low_ship_MULTI_CERT_meta_OS16.tar.md5
BL:   BL_A556EXXSECZDE_A556EXXSECZDE_MQB109426533_REV00_user_low_ship_MULTI_CERT.tar.md5
      (8376433 B, sha256 23153427efd4e75706bd89f9ee99deba6f8b94b3483f0bfedb07cd27ed3869a2)
display build: BP2A.250605.031.A3.A556EXXSECZDE
fingerprint: samsung/a55xnsxx/essi:16/BP2A.250605.031.A3/A556EXXSECZDE:user/release-keys
      (read from the OTA package's own SYSTEM/build.prop, meta-data/fota.zip)
kernel release: 6.1.138-android14-11 — UNCHANGED by the OTA
```

Kernel binary: CZB5 sha `539ffceadf296ed89b38bd5a292e91f05da56b4d04d83e449c8823f2604f322a`
→ CZDE sha `6d61ac43c4e952c3d319a3d89b9d217e8a38f65ef203515a9fa0c1d3800a82e1`
(same size 37,452,288 B; ~14% of bytes differ, largest run 5126 B). The
stale CZB5 feed entry was therefore suspended (interlock commit `64d414c`)
and this retarget re-adds it as `a55x-A556EXXSECZDE`.

## Delta derivation — what actually changed

Full evidence: `/media/k3nt/Data/4aDEV/a55-firmware/czde/`
(`offsets.md`, `p0_derivation.md`, `p0_fingerprint.h`, `symbols/`,
`disasm-evidence.txt`, `btf-dumps.txt`, `derive.log`).

1. **BTF byte-identical.** The raw BTF blob extracted from the CZDE Image
   is byte-identical to the CZB5 blob (direct `cmp` of both 5,854,051-B
   blobs; sha256
   `8eecaed122adf4394f4d60b31cfba05402cf275d6b18dcdebbd0f25ce35b9a99`).
   ALL struct-layout macros carry: compact `rt_mutex_waiter` 11-qword
   (0x58) confirmed again, `file_operations` 0x110, `skb_shared_info`
   0x158 → `SKB_DATA_DELTA −0xe80`, and the whole `CFG_*/WQ_*/PWQ_*/…`
   set.
2. **All symbol macros unchanged.** The nm diff (1,405 of 108,657 symbols
   moved) is confined to a KVM/vsock-area patch; no exploit-relevant
   symbol moved. 24 symbol VAs re-verified against `czde/symbols/vmlinux.nm`
   (list in the target README), plus the ashmem_fops member pointers and
   the misc/boot-id data qwords re-read from the CZDE `.data`.
3. **One derived macro changed:** `SLIDE_NFULNL_LOGGER_NAME_OFF`
   `0x0160845c → 0x01608454` (rodata string `nfnetlink_log` shifted −8;
   `nfulnl_logger.name` qword @ file 0x21b29d8 now stores
   `ffffffc009608454`).
4. **`SLIDE_PSELECT_WORD_SHIFT = 5` re-verified on the CZDE binary** —
   every frame measured fresh (`offsets.md` §5): pselect chain sum 0x2b0 →
   write window at E−0x260, futex chain sum 0x2d0 → `&rt_waiter` at
   E−0x238, gap 0x28/8 = 5. Identical to the CZB5 measurement.
5. **P0 re-derived, same values.** The bootloader CHANGED (sboot.bin
   decompressed sha `f70ac2cf…` vs CZB5 `df335844…`), so the P0 constants
   were re-derived from the new sboot rather than copied: handoff epilogue
   `entry = 0x80000000 + text_offset` with Image `text_offset == 0` →
   `P0_PHYS_OFFSET 0x80000000`, `P0_KERNEL_PHYS_LOAD 0x80000000`
   (`p0_derivation.md` §2).
6. **Fingerprint table regenerated** from the CZDE Image at probe
   `0x1f0000` (`verified 32 rows and 256 source qwords`): **4 of 32 rows
   differ** (slides 0x160000/0x170000/0x180000/0x190000), verified three
   ways (`p0_derivation.md` §5); example real change: Image[0x90000] = mov
   w6,#0x13;nop → ret;mrs x8,tpidrro_el0. The new table is
   `src/targets/a55x-A556EXXSECZDE/p0_fingerprint.h`.

## Exploit payload build (CZDE)

```text
artifacts/a55x-A556EXXSECZDE/cve-2026-43499-app.so
size: 104128 (assert ≤ 104128 PASS → truncate)
SHA-256: fcfc880052adcc6cdd8e22eaf5157637d3624e2842ddf1c729f8c4d536d81b0d
```

Binary spot-verify, all PASS (method: compare against a fresh same-pipeline
CZB5 rebuild — the rebuild reproduced the shipped CZB5 artifact sha
byte-exactly, so the baseline is the identical compiler/pipeline):

- (a) `prepare_slide_pselect_fdsets` words[] = 11 compact entries
  (`cmp x22, #0x108` loop bound, stride 0x18 = 11 × 24 B), words_per_set 5.
- (b) `slide_pselect_put_waiter_word`: `add w4, w4, #0x5` (shift 5).
- (c) rodata string `slide downstream verification armed` present.
- (d) embedded label `a55x-A556EXXSECZDE-app-physical-p0-oracle` present.

The CZDE .so differs from the CZB5 .so only in the 4 regenerated
fingerprint rows, the variant label string (relocated by string-merge; all
other strings identical in content and order) and the adrp/add immediates
that reference the moved string — no logic changes (102 of 11400
disassembly lines differ, all immediate updates).

## KernelSU carry-over — KO gates re-run against the CZDE ELF

The Phase 3 KO (`vermagic 6.1.138-android14-11`, unchanged by the OTA) is
NOT rebuilt; the three gates re-run against
`/media/k3nt/Data/4aDEV/a55-firmware/czde/symbols/vmlinux.elf`
(base `ffffffc008000000`):

**(a) check_symbol** — `KernelSU/kernel/check_symbol
kernelsu/android14-6.1_kernelsu-a55x-A556EXXSDCZB5-kdp.ko
czde/symbols/vmlinux.elf`:

```text
(no output) EXIT=0
```

**(b) target symvers** — venv pyelftools
`extract_target_symvers.py czde/symbols/vmlinux.elf`:

```text
wrote 15333 exact target CRCs
```

**(c) audit** — `audit_module_against_target.py <ko>
czde/symbols/vmlinux.elf czde-symvers --manual-relocation`:

```text
undefined symbols: 202
module version entries: 0
missing from target symbol table: 0
symbols resolved from kallsyms rather than target exports: 47
undefined symbols intentionally without module CRC: 202
target CRC mismatches: 0
```

Required: missing **0** ✓, version entries **0** ✓, CRC mismatches **0** ✓.
Gate output is verbatim identical to the Phase 3 CZB5 gates. → **the KO
carries over for CZDE** as byte-identical copies (`cmp` clean):

```text
kernelsu/android14-6.1_kernelsu-a55x-A556EXXSECZDE-kdp.ko
  size: 398336, sha256 272572768ed3c95a51fe599c8d26532cf7e7eb2d96ebebc0d5e5f8ce1d03daf8
kernelsu/ksud-a55x-A556EXXSECZDE-kdp
  size: 4767304, sha256 a2fd9854d1f8fd6cf166ae255201fafb8746c0bafe2c697520a89948e5bcd5b8
```

If a future CZx OTA changes the kernel release or the export surface, these
gates re-run first; a CRC-mismatch outcome would mean the next wave is a
DDK rebuild of the module.

## Models narrowed to SM-A556E (deliberate)

The `a55x-A556EXXSECZDE` feed entry carries `models: ["SM-A556E"]` ONLY.
The CZB5 entry had covered SM-A5560/B/E/S/V. The CZDE AP is the E-variant
build; the OTA-cycle kernels of the other regional variants were not
analyzed, so they stay OUT of the entry until their kernel binaries are
derived the same way. SM-A556E is the model this derivation is anchored to
(the device under test). Kernel version matching stays `["6.1.138"]`
(unchanged version string on the E-variant after the OTA).

## PROVISIONAL values

Unchanged from the CZB5 record and carried by the retarget:

- `SLIDE_TRACEFS_EVENT_ID = 106` — offline derivation only; inputs
  re-verified on CZDE (`__TRACE_LAST_TYPE = 20`, event_index 86). Confirm
  live with `cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id`.
- `SLIDE_PSELECT_WORD_SHIFT = 5` — frame-sum re-verified on the CZDE
  binary; the one on-device validation run remains the open item (same
  caveat as CZB5; CZDE adds no new risk — identical frames).

Nothing here proves a CZDE device run; treat the
`a55x-A556EXXSECZDE` exploit payload and KernelSU pair as
hardware-untested on CZDE until the first on-device validation.

## Support feed entry

`support/targets-v3.json` re-adds (after interlock commit `64d414c`
removed the stale CZB5 entry):

```json
{
  "payloadId": "a55x-A556EXXSECZDE",
  "displayName": "Galaxy A55 5G | Kernel 6.1.138 (CZDE)",
  "models": ["SM-A556E"],
  "kernelVersions": ["6.1.138"],
  "exploit": {
    "url": "https://raw.githubusercontent.com/k2-60/Root-My-Galaxy-Payloads/main/artifacts/a55x-A556EXXSECZDE/cve-2026-43499-app.so",
    "size": 104128
  },
  "kernelsu": {
    "url": "https://raw.githubusercontent.com/k2-60/Root-My-Galaxy-Payloads/main/kernelsu/ksud-a55x-A556EXXSECZDE-kdp",
    "size": 4767304
  }
}
```
