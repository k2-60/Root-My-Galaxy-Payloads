# SM-A556E A556EXXSDCZB5 target record

**STATUS: HARDWARE-UNTESTED.** All values below are offline derivations from
the firmware image (Phase 2) and offline build gates (Phase 3). The two
PROVISIONAL values must be confirmed by the app's on-device native probe
before any real run. No exploit execution, KernelSU load, or root path has
been exercised on an A55 device.

## Firmware identity

```text
model: SM-A556E (SM-A556E/DS retail; Build.MODEL "SM-A556E")
device: a55x
display build: BP2A.250605.031.A3.A556EXXSDCZB5
fingerprint: samsung/a55xnsxx/essi:16/BP2A.250605.031.A3/A556EXXSDCZB5:user/release-keys
AP member: AP_A556EXXSDCZB5_A556EXXSDCZB5_MQB106572313_REV00_user_low_ship_MULTI_CERT_meta_OS16
security patch: 2026-02-05
Android: 16
kernel release: 6.1.138-android14-11 (live `uname -r`, no build suffix)
ABI: arm64-v8a
page size: 4096
raw Image: 37,452,288 bytes (text_offset == 0, image_size 0x2630000, flags 0xa)
```

The support feed entry covers the models that share this exact
`6.1.138` kernel build; automatic selection matches the exact
`Build.MODEL` and three-part kernel version.

### Models covered, and models deliberately omitted

Included in `models` (each verified against external model registries and
firmware listings):

- `SM-A556B` — Europe/global (also listed as `a55xnaeea` / `a55xnaxx` device codes).
- `SM-A556E` — Asia/Africa/Latin America global dual-SIM model; this is the
  model the `A556EXXSDCZB5` AP firmware itself targets, and the SM-A556E/DS
  the Phase 2/3 work was derived from.
- `SM-A5560` — China/Hong Kong/Taiwan (`a55xzh`).
- `SM-A556S` — Korea, sold as the SK Telecom-exclusive Galaxy Quantum5
  (firmware family `A556SKS*`, e.g. `A556SKSS8DZF2`).
- `SM-A556V` — regional variant listed in the Galaxy A55 model table
  (Wikipedia infobox model list).

Omitted (no evidence of existence — do not add without firmware proof):

- `SM-A556U` / `SM-A556U1` — the Galaxy A55 was not launched in the USA
  (Samsung US statement, March 2024: "We will not be carrying the Galaxy A55
  5G at this time"), so no U/U1 hardware exists.
- `SM-A556W` — the A55 was not launched in Canada either.
- `SM-A556N` — no Korean LG U+/generic N firmware or retail listing exists;
  the Korean device is the SKT-exclusive Quantum5 (`SM-A556S`) only.
- `SM-A556Q` — no firmware database, vendor page, or model registry lists an
  A556Q; the repo's own A556-family sibling entry (A56) also has no Q variant.

## Target derivation (Phase 2)

The local `boot.img` was unpacked and the raw Image recovered to
`kernel.bin` (37,452,288 bytes); symbols and types were recovered with
vmlinux-to-elf to:

```text
vmlinux.elf
vmlinux.btf  (raw BTF blob, header 24 B, types region [24, 3461192), strings to end; 5,854,051 bytes)
vmlinux.nm   (112,470 symbols)
```

The BTF blob is embedded in the raw Image at file offset `0x179ede8`
(magic `9feb`, header size 24 verified in place).

IDA was kept at imagebase 0. Runtime kernel addresses are therefore
`KIMAGE_TEXT_BASE + kaslr_slide + *_OFF`.

Important target constants:

```text
KIMAGE_TEXT_BASE: 0xffffffc008000000
P0_PAGE_OFFSET:   0xffffff8000000000
P0_PHYS_OFFSET:   0x80000000
DIRECT_MAP_BASE:  0xffffff8000000000
VMEMMAP_START:    0xfffffffe00000000
SKB_DATA_DELTA:   -0xe80
sched_blocked_reason tracepoint id: 106 (PROVISIONAL, see below)
worker_thread post-schedule caller offset: 0x000db0c4
```

Symbol counts: 112,470 recovered kernel symbols (vmlinux.nm); 15,333 exact
target CRCs extracted into the build's `Module.symvers`; the module audit
resolves 202 undefined symbols (47 from kallsyms rather than target exports)
with zero missing and zero CRC mismatches (gate (e) below).

All `*_OFF` symbol-address macros were recomputed and verified from
`vmlinux.nm` VAs minus `KIMAGE_TEXT_BASE`; struct-member macros come from the
A55 BTF (corrected spec-compliant BTF walker, cross-checked against
`pahole -F btf`); `ASHMEM_MISC_FOPS_OFF` was verified from `.data` bytes
(`ashmem_miscs` miscdevice `fops` slot holds `0xffffffc00931ffb8` =
`ashmem_fops`).

### memfd-ashmem finding

The A55 kernel carries both the real ashmem driver and a memfd-based ashmem
shim (`memfd_ashmem_shim_ioctl` @ `0x397a70`,
`memfd_ashmem_shim_compat_ioctl` @ `0x397e84`, `memfd_file` @
`ffffffc0096c84e0`). The `/dev/ashmem` miscdevice registered via
`ashmem_miscs` points at the **real `ashmem_fops`** (verified from `.data`
bytes: the fops slot holds `0xffffffc00931ffb8` = `ashmem_fops`), so the
exploit's ashmem fd dispatches through the real `ashmem_*` functions — NOT
the shim. The shim serves the `memfd_create` path; the runtime check is
`is_ashmem_file` @ `ffffffc008cc83c0`. No shim functions are mapped into the
fops macros.

## P0 derivation

Bootloader `BL_A556EXXSDCZB5_A556EXXSDCZB5_MQB106572313_REV00_user_low_ship_MULTI_CERT.tar.md5`
was extracted to sboot.bin (lz4), sha256
`df33584470e46c5e9efb4fd742f5b9b0262ec7d7220136d41383924cdfae586a`.

sboot disassembly evidence (PORTING.md §4 method): the only adrp pair reaching
the `Starting kernel...\n` string (file offset `0x17d190`) is at
`0x3013c`/`0x30140`, and the boot-handoff epilogue is

```text
adrp/ldr of the Image text_offset variable (0x47ccf8)
mov w9, #-0x80000000        ; w9 = 0x80000000
add x8, x8, x9              ; entry = 0x80000000 + text_offset
blr x8                      ; jump to kernel
```

sboot is linked VA == file offset, and `0x47ccf8` is `.bss` whose only writer
is the EL3 `smc #0` monitor call (function id `0xC200101C`) storing
`(SMC x2 & 0x1f) << 16` — text_offset in 64-KiB units. The A55 Image header
itself has `text_offset == 0`, so the kernel entry (load + 0) is `0x80000000`:

```c
#define P0_PHYS_OFFSET      0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
```

The P0 oracle fingerprint table maps the actual slide to bytes read at raw
offset `P0_ORACLE_PROBE_OFFSET - slide`. `P0_ORACLE_PROBE_OFFSET = 0x1f0000`
— the same value the S24 FE reference used; probe == max slide candidate ⇒
smallest valid probe. Bounds verified against the 37,452,288-byte Image:
minimum read offset `0x000000` ≥ 0, maximum read offset `0x1f0e08` =
2,036,744 < 37,452,288, every probed 4-KiB page inside the image for all 32
slides. `tools/generate_p0_fingerprint.pl` ran with output
"verified 32 rows and 256 source qwords at probe 0x1f0000"; the generated
table is checked in as `src/targets/a55x-A556EXXSDCZB5/p0_fingerprint.h`.
Without the `PROBE_OFFSET - slide` conversion the raw sample is misread as
the slide and the fops direct-map verification reads zero.

## Exploit payload build

The A55 app-domain payload was built as
`artifacts/a55x-A556EXXSDCZB5/cve-2026-43499-app.so` (NDK r28b
`aarch64-linux-android35-clang`, `-DAPP_PAYLOAD=1 -fPIC -Oz`,
target header `targets/a55x-A556EXXSDCZB5/target.h`, sections gc'ed and the
file truncated to the exact release size):

```text
size: 104128
SHA-256: 0ae23ffddf2abea3d84e9bb74252c06ef961db89184cca55e2794e05f8865bdf
```

No hardware execution has been attempted for this profile.

## KernelSU build record

KernelSU was built from tag `v3.2.5`, commit
`b0bc817b4e966aa6aa830834eaf6ef765d821d40`, with the repository Samsung
KDP/RKP/DEFEX patch applied cleanly (no rejects, no fuzz).

The module was built in:

```text
ghcr.io/ylarod/ddk-min:android14-6.1-20260313
RepoDigest sha256:1dd6ac340b627a90a4031d6d0df6b129d8cc949b139fb56032c898f023d3d5d3
```

The digest matches the repo's pinned e3q DDK digest exactly. The image's clang
(`Android (10087095, +pgo, +bolt, +lto, -mlgo, based on r487747c) clang
version 17.0.2 … d9f89f4d16663d5012e5c09495f3b30ece3d2362`) is an exact match
for the target's `CONFIG_CC_VERSION_TEXT`.

The DDK release was overridden to the exact target release:

```text
vermagic: 6.1.138-android14-11 SMP preempt mod_unload modversions aarch64
```

The target config (extracted from the Image with `extract-ikconfig`,
byte-identical to the live `/proc/config.gz` from the connected device) has:

```text
CONFIG_MODULES=y
CONFIG_MODVERSIONS=y
CONFIG_MODULE_SIG_ALL unset (=n)
CONFIG_MODULE_SIG_FORCE unset (=n) (CONFIG_MODULE_SIG=y, CONFIG_MODULE_SIG_PROTECT=y)
CONFIG_TRIM_UNUSED_KSYMS unset (=n)
CONFIG_KALLSYMS_ALL=y
CONFIG_KDP=y
CONFIG_RKP=y
CONFIG_SECURITY_DEFEX=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_LTO_NONE=y
CONFIG_CFI_CLANG=y
CONFIG_SHADOW_CALL_STACK=y
```

For this Exynos target, the A55 module is built with:

```text
CONFIG_KSU=m CONFIG_KSU_SAMSUNG_KDP=y CONFIG_KSU_SAMSUNG_RKP=y \
CONFIG_KSU_SAMSUNG_DEFEX=y CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y \
KCFLAGS=-DCONFIG_DEBUG_INFO_BTF_MODULES=1 CC=clang
```

`CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y` makes KernelSU refuse `ksu_patch_text()`
live writes instead of entering `stop_machine`; the syscall-table dispatcher
falls through to the Samsung RKP kretprobe/kprobe fallback and selinux-hide
slot patches fail closed instead of triggering Samsung EL2. Evidence: the e1s
6.1 Exynos and A56 Exynos precedents and README lines 62–70 (Exynos EL2
live-text-patching panics); a55x is Exynos 1480 with RKP/KDP — same risk class.

The five offline gates, verbatim:

**(a) vermagic byte-exact** — `modinfo -F vermagic kernel/kernelsu.ko`:

```text
6.1.138-android14-11 SMP preempt mod_unload modversions aarch64
```

`[ "$V" = "$T" ]` → `GATE_A_PASS_BYTE_EXACT` (target string identical,
char-for-char).

**(b) check_symbol vs recovered ELF** —
`kernel/check_symbol kernel/kernelsu.ko /tmp/a55-firmware/symbols/vmlinux.elf`:

```text
(no output) EXIT=0
```

Checker is not a no-op — negative control
`./check_symbol ./kernelsu.ko /bin/true` →
`Error: No symbol table found in /bin/true`, EXIT=1.

**(c) sections** — `readelf -SW kernel/kernelsu.ko | grep -E '__versions|\.symtab|\.strtab'`
(post-strip):

```text
  [44] __versions        PROGBITS        0000000000000000 021ac0 000000 00   A  0   0  8
  [48] .symtab           SYMTAB          0000000000000000 0463a8 0105a8 18     50 2365  8
  [50] .strtab           STRTAB          0000000000000000 056b4c 004b3b 00      0   0  1
```

`__versions` size **0** ✓; .symtab/.strtab retained ✓.

**(d) target symvers** —
`extract_target_symvers.py /tmp/a55-firmware/symbols/vmlinux.elf Module.symvers`:

```text
wrote 15333 exact target CRCs to /media/k3nt/Data/4aDEV/kernelsu-build/Module.symvers
```

Byte-identical (`cmp` clean) to a repeat extraction — reproducible.

**(e) audit** —
`audit_module_against_target.py kernel/kernelsu.ko /tmp/a55-firmware/symbols/vmlinux.elf Module.symvers --manual-relocation`:

```text
undefined symbols: 202
module version entries: 0
missing from target symbol table: 0
symbols resolved from kallsyms rather than target exports: 47
undefined symbols intentionally without module CRC: 202
target CRC mismatches: 0
```

Required: missing-from-target **0** ✓, version entries **0** ✓, CRC
mismatches **0** ✓.

The stripped standalone KO is:

```text
kernelsu/android14-6.1_kernelsu-a55x-A556EXXSDCZB5-kdp.ko
size: 398336
SHA-256: 272572768ed3c95a51fe599c8d26532cf7e7eb2d96ebebc0d5e5f8ce1d03daf8
```

The Android/AArch64 `ksud` binary embeds the A55 KO as
`android14-6.1_kernelsu.ko` (rust-embed, flate-compressed; embed slot
sha256-identical to the stripped .ko; asset size marker 398336 present in the
binary) and reports KernelSU version code `32525`:

```text
kernelsu/ksud-a55x-A556EXXSDCZB5-kdp
size: 4767304
SHA-256: a2fd9854d1f8fd6cf166ae255201fafb8746c0bafe2c697520a89948e5bcd5b8
```

## PROVISIONAL values (must be confirmed by the on-device native probe before any real run)

- `SLIDE_TRACEFS_EVENT_ID = 106` — offline derivation only:
  BTF `enum trace_type` last entry `__TRACE_LAST_TYPE = 20` plus zero-based
  `event_index = (__event_sched_blocked_reason − __start_ftrace_events)/8 = 86`
  → 20 + 86 = 106. Same method (and same result) as the S24 FE port.
  Confirm live with
  `cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id`.
- `SLIDE_PSELECT_WORD_SHIFT = 5` — VERIFIED by frame-sum derivation
  (write-window analysis `phase2-ww/write-window-analysis.md`,
  adversarially verified in `phase2-ww/verify/verification.md`):
  pselect chain writes `stack_fds[0]` at E−0x260, futex chain reads
  `&rt_waiter` at E−0x238; gap 0x28 = 5 qwords → shift 5 (waiter qword 0
  = first qword of the write set). Method cross-checked against the
  hardware-confirmed S24U convention (their gap 0x18 = 3 qwords
  reproduces their confirmed shift 3). Applied together with the layout
  fix: A55 BTF `rt_mutex_waiter` is the compact 11-qword layout (tree
  0x00, pi tree 0x18, task 0x30, lock 0x38, wake_state 0x40, prio 0x44,
  deadline 0x48, ww_ctx 0x50, size 0x58; kernel write/read sites
  cross-checked), so `COMPACT_RT_MUTEX_WAITER 1` + the dm3q compact
  `FAKE_WAITER_*` set replace the wrong 14-qword legacy set. Waiter
  words 0-9 land on g5-g14; ww_ctx (g15) is intentionally unplaced
  (the `cannot place ww_ctx` warning is expected — ww_ctx must stay
  NULL for a futex waiter). Campaign evidence: 5 deep runs, 0/5 windows
  (window=0) at shift 0 with the legacy branch compiled — the miss
  signature that motivated this fix.

Nothing here proves the module loads on the A55; all gates are offline checks
against the recovered vmlinux.elf and the extracted config. Treat the
A556EXXSDCZB5 exploit payload and KernelSU pair as hardware-untested.

## Support feed entry

`support/targets-v3.json` carries the new `a55x-A556EXXSDCZB5` entry with
`exploit.size = 104128` and `kernelsu.size = 4767304`. The `url` fields keep
the canonical upstream path pattern
(`raw.githubusercontent.com/BuSung-dev/Root-My-Galaxy-Payloads/main/…`)
exactly as the other entries: the payload fork is a GitHub fork of the same
repo name, so after the user forks and pushes, the raw URLs keep the same
path shape under the fork's account. The app build is patched to the fork by
a later step; the feed file itself intentionally carries the canonical path.
`requiresFreshP0Session` is not set for this profile (default `false`,
matching the A56 Exynos sibling); flip it to `true` only if on-device testing
shows slide discovery and exploitation must share one payload process.
