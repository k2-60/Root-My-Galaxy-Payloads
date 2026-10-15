# a55x-A556EXXSECZDE

Samsung Galaxy A55 (SM-A556E/DS, Exynos S5E8845 / "erd8845"), firmware
`A556EXXSECZDE` (AP member
`AP_A556EXXSECZDE_A556EXXSECZDE_MQB109426533_REV00_user_low_ship_MULTI_CERT_meta_OS16`,
security patch 2026-05-05, display build
`BP2A.250605.031.A3.A556EXXSECZDE`).

This target REPLACES `a55x-A556EXXSDCZB5` for the SM-A556E device after the
May 2026 CZDE OTA. It is a retarget, not a new derivation: the CZB5 profile
is carried and re-verified against the CZDE kernel, with exactly one
symbol-offset change.

- Build fingerprint (from the CZDE OTA's own `SYSTEM/build.prop`,
  `meta-data/fota.zip` in the AP tar):
  `samsung/a55xnsxx/essi:16/BP2A.250605.031.A3/A556EXXSECZDE:user/release-keys`
- Kernel: `6.1.138-android14-11` (unchanged version from CZB5), raw Image
  37,452,288 bytes (`/media/k3nt/Data/4aDEV/a55-firmware/czde/kernel.bin`),
  `text_offset == 0`, image_size `0x2630000`, flags `0xa`.
- KASLR / virtual base: `KIMAGE_TEXT_BASE = 0xffffffc008000000` (unchanged).
- Evidence tree: `/media/k3nt/Data/4aDEV/a55-firmware/czde/`
  (`offsets.md`, `p0_derivation.md`, `p0_fingerprint.h`, `symbols/vmlinux.*`,
  `kernel.bin`, `disasm-evidence.txt`, `btf-dumps.txt`).

## What changed vs CZB5 (the whole delta)

| Macro | CZB5 | CZDE | Evidence |
| --- | --- | --- | --- |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | `0x0160845c` | **`0x01608454`** (−8) | rodata string `nfnetlink_log` moved −8; `nfulnl_logger.name` qword @ file `0x21b29d8` now stores `ffffffc009608454` (pointer hunt hits exactly one location) |
| everything else | — | unchanged | see the cross-check record below |

- **BTF: BYTE-IDENTICAL** to CZB5 — direct `cmp` of the two extracted blobs
  (`/tmp/a55-firmware/symbols/vmlinux.btf` vs `czde/symbols/vmlinux.btf`,
  both 5,854,051 B, sha256
  `8eecaed122adf4394f4d60b31cfba05402cf275d6b18dcdebbd0f25ce35b9a99`).
  Every struct-layout macro (`FAKE_*` compact `rt_mutex_waiter` 11-qword
  size 0x58, `CFG_*`, `WQ_*`/`PWQ_*`/`POOL_*`/`WORK_*`, `STRUCT_PAGE_*`,
  `PIPE_*`, `FOPS_*` `file_operations` 0x110) carries over 1:1.
  `SKB_DATA_DELTA = -0xe80` recomputed from the identical
  `skb_shared_info` 0x158.
- **Kernel binary differs ~14% of bytes** (CZB5 sha
  `539ffceadf296ed89b38bd5a292e91f05da56b4d04d83e449c8823f2604f322a` → CZDE
  `6d61ac43c4e952c3d319a3d89b9d217e8a38f65ef203515a9fa0c1d3800a82e1`, same
  size), but the nm diff is confined to a KVM/vsock-area patch — **no
  exploit-relevant symbol moved**.
- **P0 unchanged**: `P0_PHYS_OFFSET 0x80000000`, `P0_KERNEL_PHYS_LOAD
  0x80000000` — re-derived from the NEW CZDE sboot (the bootloader changed:
  decompressed sha `f70ac2cf…` vs CZB5 `df335844…`), handoff epilogue
  byte-identical shape, Image `text_offset == 0`. See `p0_derivation.md`.
- **`p0_fingerprint.h` regenerated** from the CZDE Image at probe
  `0x1f0000` (`verified 32 rows and 256 source qwords`); **4 of 32 rows
  differ** (slides `0x160000`/`0x170000`/`0x180000`/`0x190000`), verified
  three ways in `p0_derivation.md` §5.
- `SLIDE_PSELECT_WORD_SHIFT = 5` **re-verified on the CZDE binary**: every
  pselect/futex frame measured fresh from `czde/symbols/vmlinux.elf`;
  `(0x260 − 0x238)/8 = 5` — all frames byte-identical to the CZB5
  measurement (`offsets.md` §5).
- `COMPACT_RT_MUTEX_WAITER 1` + compact `FAKE_WAITER_*` set carry (BTF
  identical). `APP_ACCEPT_SCHED_TRIGGER 1` carries (exploit constant).

## Cross-check record (CZDE re-verification, 2026-10-15)

Every macro value in this `target.h` was re-verified against the CZDE
evidence before building; the diff table says all but one are unchanged and
the check confirms it.

Symbol-address macros — verified against `czde/symbols/vmlinux.nm`
(expected VA = `KIMAGE_TEXT_BASE + OFF`, all 24 OK):

`call_usermodehelper_exec_work` ffffffc0080d37a8 · `system_unbound_wq`
ffffffc00a1aae60 · `noop_llseek` ffffffc00839c6c8 ·
`generic_file_splice_read` ffffffc0083ea1fc · `configfs_read_iter`
ffffffc008469d74 · `configfs_bin_write_iter` ffffffc00846a2a4 ·
`ashmem_fops` ffffffc00931ffb8 · `kmalloc_caches` ffffffc0096bf898 ·
`anon_pipe_buf_ops` ffffffc009199790 · `init_task` ffffffc00a1bf700 ·
`root_task_group` ffffffc00a3c4d40 · `selinux_state` ffffffc00a4991a8
(+ BTF `enforcing` @ 0x0 → `SELINUX_ENFORCING_OFF 0x024991a8`) ·
`nfulnl_logger` ffffffc00a1b29d8 · `sysctl_bootid` ffffffc00a53f3d8 ·
`__start_ftrace_events` ffffffc00a16a9a0 ·
`__event_sched_blocked_reason` ffffffc00a16ac50 (gap 0x2b0/8 = 86 →
event id 20 + 86 = 106) · `worker_thread` ffffffc0080db024 ·
`ashmem_llseek` ffffffc008cc83dc · `ashmem_ioctl` ffffffc008cc8544 ·
`compat_ashmem_ioctl` ffffffc008cc8e7c · `ashmem_mmap` ffffffc008cc8ed4 ·
`ashmem_open` ffffffc008cc90f4 · `ashmem_release` ffffffc008cc917c ·
`ashmem_show_fdinfo` ffffffc008cc929c.

Data-qword macros — re-read from `czde/kernel.bin`:

- `ASHMEM_MISC_FOPS_OFF 0x02338630`: the fops slot of `ashmem_miscs` entry 1
  holds `ffffffc00931ffb8` = `ashmem_fops`; name ptr → `"ashmem"`, minor
  `0x00ff`. (The CZB5 doc's "verified at 0x2338640" line was an erratum —
  the true value in BOTH builds is 0x02338630, which this target.h
  inherits correctly.)
- All 8 `ASHMEM_*` function-pointer slots re-read from `ashmem_fops` @
  file `0x131ffb8` — each matches its `nm` symbol (table in `offsets.md` §2).
- `SLIDE_NFULNL_LOGGER_NAME_OFF`: qword @ `0x21b29d8` stores
  `ffffffc009608454`; string @ `0x1608454` reads `"nfnetlink_log"`.
- `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF 0x022f2e38`: data slot stores
  `ffffffc00a53f3d8` = `sysctl_bootid`.

Disasm — `SLIDE_TRACEFS_WORKER_CALLER_OFF 0x000db0c4`: llvm-objdump on the
CZDE ELF shows `bl schedule` (ffffffc0090a14a8) at `ffffffc0080db0c0`,
next instruction `ffffffc0080db0c4`.

BTF-arg macros — the two raw BTF blobs are byte-identical (direct `cmp`),
so `FAKE_*` (rt_mutex_waiter 0x58, 11 qwords), `FOPS_*`
(file_operations 0x110), `CFG_*`, `WQ_*`/`PWQ_*`/`POOL_*`/`WORK_*`,
`STRUCT_PAGE_*`, `PIPE_*` carry 1:1; spot sizes re-dumped from the CZDE
blob in `czde/btf-dumps.txt`.

## Build record

`make TARGET=a55x-A556EXXSECZDE ANDROID_NDK_HOME=…android-ndk-r28b release`
(NDK r28b `aarch64-linux-android35-clang`, `-DAPP_PAYLOAD=1 -fPIC -Oz`,
gc-sections + icf, truncated to the release size):

```text
size: 104128 (assert ≤ 104128 PASS → truncate)
SHA-256: fcfc880052adcc6cdd8e22eaf5157637d3624e2842ddf1c729f8c4d536d81b0d
```

Binary spot-verify (vs the freshly rebuilt, byte-identical CZB5 release
build as baseline — the pipeline is deterministic: a fresh CZB5 build
reproduces the shipped artifact sha exactly):

- (a) `prepare_slide_pselect_fdsets`: compact `words[]` materialized with
  11 entries (indices 0..0xa), copy loop `cmp x22, #0x108` with stride
  `add x22, x22, #0x18` (11 × 24 B), `words_per_set = 5` passed → PASS.
- (b) `slide_pselect_put_waiter_word` @ 0x121d4: `add w4, w4, #0x5`
  (SLIDE_PSELECT_WORD_SHIFT 5) → PASS.
- (c) rodata string `slide downstream verification armed` present → PASS.
- (d) embedded label `a55x-A556EXXSECZDE-app-physical-p0-oracle` present →
  PASS.
- The CZDE .so differs from the CZB5 .so ONLY in the 4 regenerated
  fingerprint rows (.rodata, bytes match the `p0_derivation.md` §5
  example), the variant label string (relocated by the linker's string
  merge; all other strings identical in content and order), and the
  adrp/add immediates referencing the moved string. No logic changes.

## KernelSU carry-over (KO gates re-run against the CZDE ELF)

The CZDE kernel recovery gates re-run on the Phase 3 KO
(`kernelsu/android14-6.1_kernelsu-a55x-A556EXXSDCZB5-kdp.ko`, vermagic
`6.1.138-android14-11` unchanged by the OTA — the KO binary is NOT
rebuilt):

- **(a) check_symbol** — `KernelSU/kernel/check_symbol <ko>
  czde/symbols/vmlinux.elf`: no output, EXIT=0.
- **(b) target symvers** — `extract_target_symvers.py czde/symbols/vmlinux.elf`:
  `wrote 15333 exact target CRCs` (same count as the CZB5 extraction).
- **(c) audit** — `audit_module_against_target.py <ko>
  czde/symbols/vmlinux.elf czde-symvers --manual-relocation`:

```text
undefined symbols: 202
module version entries: 0
missing from target symbol table: 0
symbols resolved from kallsyms rather than target exports: 47
undefined symbols intentionally without module CRC: 202
target CRC mismatches: 0
```

Required: missing-from-target **0** ✓, version entries **0** ✓, CRC
mismatches **0** ✓. ALL GATES PASS → the KO carries over for CZDE as
byte-identical copies:

- `kernelsu/android14-6.1_kernelsu-a55x-A556EXXSECZDE-kdp.ko` (398336 B,
  sha256 `272572768ed3c95a51fe599c8d26532cf7e7eb2d96ebebc0d5e5f8ce1d03daf8`)
- `kernelsu/ksud-a55x-A556EXXSECZDE-kdp` (4767304 B, sha256
  `a2fd9854d1f8fd6cf166ae255201fafb8746c0bafe2c697520a89948e5bcd5b8`)

Both are `cp` copies of the CZB5-named files (`cmp` clean) — the module
binary is firmware-agnostic within this kernel release; only the feed/
artifact naming follows the retarget.

## Models: deliberately narrowed

The feed entry (`support/targets-v3.json`) carries `models: ["SM-A556E"]`
ONLY. The CZDE AP firmware (`A556EXXSE…`) is the E-variant build; the
kernels shipping on the other A55 regional variants (SM-A5560/B/S/V) after
this OTA cycle are UNVERIFIED — their AP packages were not analyzed, so
offering them the E-variant offsets would be a guess. Re-widen only with
per-variant kernel-binary evidence (same method as this retarget).

## PROVISIONAL values (unchanged caveat from CZB5)

- `SLIDE_TRACEFS_EVENT_ID = 106` — offline BTF derivation (inputs
  re-verified above: `__TRACE_LAST_TYPE = 20`, event_index 86); confirm
  live with `cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id`.
- `SLIDE_PSELECT_WORD_SHIFT = 5` — frame-sum re-verified on the CZDE
  binary (identical frames to the CZB5 measurement); the single on-device
  validation run is still the open item, and CZDE adds no new risk.
- The retargeted profile has had NO device run yet (the device is on CZDE
  since the OTA; the payload above is the first CZDE-matched build).
