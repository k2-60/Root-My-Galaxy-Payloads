# SM-A556E A556EXXUEDZE4 target record (UEDZE4 retarget — KernelSU KO wave)

**STATUS: HARDWARE-UNTESTED (retarget).** The exploit payload and the
KernelSU pair are derived and gated entirely offline against the UEDZE4
kernel. No adb command, device run or flash was performed in this wave.
The earlier CZDE record (`docs/SM-A556E-A556EXXSECZDE.md`) remains the
history of the prior firmware.

## Build identity

Device (SM-A556E/DS, Exynos S5E8845 / "erd8845") on **A556EXXUEDZE4**:

```text
AP:   AP_A556EXXUEDZE4_A556EXXUEDZE4_MQB109662540_REV00_user_low_ship_MULTI_CERT_meta_OS16.tar.md5
BL:   BL_A556EXXUEDZE4_A556EXXUEDZE4_MQB109662540_REV00_user_low_ship_MULTI_CERT.tar.md5
      (sboot.bin decompressed 5,260,080 B, sha256 c7f7d8f6beb19ba63bfbb92ba103dd91079699ac77eb84d6d9ae76d67b52ecf1,
      matches PR #303's provenance)
build stamp: Tue May 12 07:25:39 UTC 2026
composite build: BP4A.251205.006.A556EXXUEDZE4
display build: BP4A.251205.006.A3.A556EXXUEDZE4
fingerprint: samsung/a55xnsxx/essi:16/BP4A.251205.006/A556EXXUEDZE4:user/release-keys
security patch: 2026-05-05, One UI 8.5
kernel release: 6.1.157-android14-11
```

Kernel binary: raw Image 38,697,472 B, sha256
`0494f519c7b1abcae169d2ad598fa5c0b00c36c9d3560d7d9e15f29677593f91`,
`text_offset == 0`, image_size 0x27a0000, flags 0xa.
KASLR / virtual base: `KIMAGE_TEXT_BASE = 0xffffffc008000000`.

Evidence tree: `/media/k3nt/Data/4aDEV/a55-firmware/uedze4/`
(`offsets.md`, `disasm-evidence.txt`, `derive.py`, `derive.log`,
`btf-dumps.txt`, `p0_fingerprint.h`, `symbols/vmlinux.*`,
`ap-work/kernel.bin`, `bl-work/sboot.bin`).

## Delta derivation — what changed vs CZDE (6.1.138)

The kernel is a real rebuild (Image grew by 1,245,184 B = 0x130000; every
nm-derived symbol in the exploit macro set moved). Full table:
`uedze4/offsets.md` §1; compiled values in
`src/targets/a55x-A556EXXUEDZE4/target.h`.

Highlights:

| Macro | CZDE | UEDZE4 |
|---|---|---|
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | 0x000d37a8 | 0x000d4360 |
| `SYSTEM_UNBOUND_WQ_OFF` | 0x021aae60 | 0x022cae60 |
| `ASHMEM_FOPS_OFF` | 0x0131ffb8 | 0x013c9b50 |
| `ASHMEM_MISC_FOPS_OFF` | 0x02338630 | 0x02464430 |
| `KMALLOC_CACHES_OFF` | 0x016bf898 | 0x01792ed8 |
| `INIT_TASK_OFF` | 0x021bf700 | 0x022df700 |
| `ROOT_TASK_GROUP_OFF` | 0x023c4d40 | 0x024f4d40 |
| `SELINUX_ENFORCING_OFF` | 0x024991a8 | 0x025c92f8 |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | 0x01608454 | 0x016ca0d5 |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | 0x022f2e38 | 0x0241e878 |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | 0x000db0c4 | 0x000dbc94 |
| `SLIDE_PSELECT_WORD_SHIFT` | 5 | **3** |

### BTF — layout-identical, not byte-identical

One raw BTF blob at `0x1876a88..0x1e2a8c4` = 5,979,708 B, type_len
3,540,392, str_len 2,439,292, sha256
`c8cc2f12fa476005aba20e70aef823923d5a63a4bb861d49cf9de1d8112b3c0f`
(CZDE: 5,854,051 B, `8eecaed1…9a99`). Type IDs and the string table were
renumbered (one anonymous `android_kabi_reserved2` member is unnamed in
UEDZE4), but **every dumped struct is offset-identical to CZDE** — all
`FAKE_*`, `CFG_*`, `WQ_*`, `PWQ_*`, `POOL_*`, `WORK_*`, `STRUCT_PAGE_*`,
`PIPE_*`, `FOPS_*` macros carry unchanged, and `SKB_DATA_DELTA` stays
`-0xe80` (skb_shared_info 0x158 → round_up 64 = 0x180; 0x1000-0x180).

### Shift-3 correction (CZDE/CZB5 arithmetic slip)

`SLIDE_PSELECT_WORD_SHIFT = 3`, measured on the UEDZE4 ELF:

- pselect chain 0x10+0x30+0x20+0x90+0x1c0 = **0x2b0**;
  `stack_fds` at sp+0x50 → E−0x260.
- futex chain 0x60+0x70+0x60+0x1b0 = **0x2e0**;
  `rt_waiter` at sp+0x98 → E−0x248 (q at sp+0x8, BTF `futex_q.rt_waiter`
  +0x58, store at sp+0x60).
- `(0x260−0x248)/8 = 0x18/8 = 3`.

**The CZDE/CZB5 value 5 was an arithmetic slip**: the CZDE frame table
itself sums to 0x2e0, not the printed 0x2d0, so its correct value is also
3. The CZDE target is intentionally left untouched by this wave; the
UEDZE4 target uses 3.

### PR #303 agreement — 32/32

The `p0_fingerprint.h` table was regenerated at probe 0x1f0000
(`verified 32 rows and 256 source qwords`). 31 of 32 rows differ from
CZDE (only slide 0x1e0000 identical); the table is **row-for-row
identical to PR #303's, 32/32 rows**. All kernel-derived values also agree
with PR #303: every `ASHMEM_*`, `CONFIGFS_*`, `COPY_SPLICE_READ`,
`NOOP_LLSEEK`, `INIT_TASK`, `ROOT_TASK_GROUP`, `SELINUX_ENFORCING`,
`KMALLOC_CACHES`, `ANON_PIPE_BUF_OPS`, `CALL_USERMODEHELPER_EXEC_WORK`,
`SYSTEM_UNBOUND_WQ`, the nfulnl/boot-id pair, worker-caller 0x000dbc94,
event id 106, shift 3, `KIMAGE_TEXT_BASE`, P0 0x80000000/0x80000000 and
probe 0x1f0000.

Route/tuning differences vs PR #303 (fops/UMH 0x7000/0x7800/0x7a00,
`SKB_DATA_DELTA −0xe80`, 4-slot bank, Ksnitch tuning, fresh-P0 guard
deferred) are recorded in `src/targets/a55x-A556EXXUEDZE4/README.md`.

## Exploit payload build (UEDZE4)

```text
artifacts/a55x-A556EXXUEDZE4/cve-2026-43499-app.so
size: 104128 (pre-truncate 97008, margin 7120 → zero-pad/truncate)
SHA-256: 399039a3e0c53f840abbad989929b94f9edd56ac6275a0b17818a8355a25772a
```

Spot-verify (llvm-objdump/strings): label
`a55x-A556EXXUEDZE4-app-physical-p0-oracle`; `slide downstream
verification armed`; `cmp x22, #0x108` @0x12d10 and stride
`add x22, x22, #0x18` @0x12d38 (11 compact waiter words);
`add w0,w0,#0x3` @0x12ab4 and `add w4,w4,#0x3` @0x12b4c (shift 3);
`mov w1,#0x7000` @0x11bbc-0x11bc8; `mov w8,#0x7800` / `mov w10,#0x7a00`
@0x184c0/0x184c8; `[ksdiag]` and `[pipefix]` strings present.

## KernelSU module rebuild (this wave)

- Source: KernelSU v3.2.5 `b0bc817b`, Samsung KDP/RKP/DEFEX patch applied
  (same working tree as the CZDE wave).
- DDK image: `ghcr.io/ylarod/ddk-min:android14-6.1-20260313`, digest
  `sha256:1dd6ac340b627a90a4031d6d0df6b129d8cc949b139fb56032c898f023d3d5d3`.
- `$KDIR = /opt/ddk/kdir/android14-6.1`; release rewritten
  `6.1.166-dirty → 6.1.157-android14-11` in
  `include/generated/utsrelease.h` and `include/config/kernel.release`.
- Recipe: `make clean`; then
  `CONFIG_KSU=m CONFIG_KSU_SAMSUNG_KDP=y CONFIG_KSU_SAMSUNG_RKP=y
  CONFIG_KSU_SAMSUNG_DEFEX=y CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y
  KCFLAGS=-DCONFIG_DEBUG_INFO_BTF_MODULES=1 CC=clang make -j$(nproc)`
  → 36 objects, `LD [M] kernelsu.ko`, `BTF [M] kernelsu.ko`, in-container
  `./check_symbol kernelsu.ko $KDIR/vmlinux` silent.
- Build log: `/media/k3nt/Data/4aDEV/phase5-fork/make-uedze4-ko.log`.

`modinfo` (verbatim):

```text
filename:       /workspace/kernel/./kernelsu.ko
license:        GPL
author:         weishu
description:    Android KernelSU
import_ns:      VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver
vermagic:       6.1.157-android14-11 SMP preempt mod_unload modversions aarch64
name:           kernelsu
depends:        
parm:           norc:bool
parm:           allow_shell:bool
```

## Gates vs the UEDZE4 ELF — ALL PASS (verbatim)

Base `ffffffc008000000`; ELF `uedze4/symbols/vmlinux.elf`.

**(a) vermagic byte-exact**

```text
GOT: 6.1.157-android14-11 SMP preempt mod_unload modversions aarch64
GATE_A_PASS_BYTE_EXACT
```

**(b) check_symbol** — `KernelSU/kernel/check_symbol kernelsu.ko uedze4/symbols/vmlinux.elf`

```text
(no output) EXIT=0
```

**(c) sections (pre-strip)** — `readelf -SW kernelsu.ko | grep -E '__versions|\.symtab|\.strtab'`

```text
  [54] __versions        PROGBITS        0000000000000000 021ac0 000000 00   A  0   0  8
  [58] .symtab           SYMTAB          0000000000000000 561df8 011e08 18     60 2625  8
  [60] .strtab           STRTAB          0000000000000000 573e5a 004d5f 00      0   0  1
```

`__versions` size **0x000000 = 0** ✓; `.symtab`/`.strtab` present ✓
(post-strip re-check in the artifact section).

**(d) target symvers** — `tools/extract_target_symvers.py uedze4/symbols/vmlinux.elf Module-uedze4.symvers`

```text
wrote 15450 exact target CRCs
```

**(e) audit** — `tools/audit_module_against_target.py kernelsu.ko
uedze4/symbols/vmlinux.elf Module-uedze4.symvers --manual-relocation`

```text
undefined symbols: 202
module version entries: 0
missing from target symbol table: 0
symbols resolved from kallsyms rather than target exports: 47
undefined symbols intentionally without module CRC: 202
target CRC mismatches: 0
```

Required: missing **0** ✓, version entries **0** ✓, CRC mismatches **0** ✓.
kallsyms-resolved: **47**. No mismatch table exists (CRC-identical export
surface against the 6.1.157 ELF).

## Strip + embodiment + ksud

- `llvm-strip -d` (NDK r29) on `kernel/kernelsu.ko`.
- Pre-strip: **5,761,976 B**, sha256
  `e9aae934cdb7dfb7f5fbacf10c9df89bab28467c9a30a0587d04ab43de2c6211`.
- Post-strip: **398,336 B**, sha256
  `824f2af93a5d520ace0dd13f4f0cf8c1cc7b985b81872fa7fc5b194c6cbb1698`.
- Post-strip sections:

```text
  [44] __versions        PROGBITS        0000000000000000 021ac0 000000 00   A  0   0  8
  [48] .symtab           SYMTAB          0000000000000000 0463a8 0105a8 18     50 2365  8
  [50] .strtab           STRTAB          0000000000000000 056b4c 004b3b 00      0   0  1
```

- Stripped KO copied byte-identically (`cmp` clean) to the fixed ksud slot
  `KernelSU/userspace/ksud/bin/aarch64/android14-6.1_kernelsu.ko`.
- ksud forced-recompiled (`cargo clean -p ksud` then
  `cargo build --release --target aarch64-linux-android -p ksud`) with
  NDK r29 (`aarch64-linux-android35-clang`, `llvm-ar`,
  `LIBCLANG_PATH=<ndk>/.../lib`). Log:
  `/media/k3nt/Data/4aDEV/phase5-fork/make-uedze4-ksud.log`.
- ksud: **4,767,304 B**, sha256
  `1a602a84baa4831ea203d69d23852c05461f60b21c351c6ebc4ef8771ba7a5f3`.

Embedding evidence: rust-embed compresses on-disk assets with
`include-flate` (libflate DEFLATE). The exact libflate stream of the new
398,336-B KO (123,944 B) is present in the ksud binary at offset
**74240 — full match**; the CZDE KO's stream (123,946 B) is **absent**
(`find` = −1). The embedded asset name `android14-6.1_kernelsu.ko` is
also present.

## Artifacts published in the repo (uncommitted at doc time)

| File | Size | SHA-256 |
|---|---:|---|
| `kernelsu/android14-6.1_kernelsu-a55x-A556EXXUEDZE4-kdp.ko` | 398336 | `824f2af93a5d520ace0dd13f4f0cf8c1cc7b985b81872fa7fc5b194c6cbb1698` |
| `kernelsu/ksud-a55x-A556EXXUEDZE4-kdp` | 4767304 | `1a602a84baa4831ea203d69d23852c05461f60b21c351c6ebc4ef8771ba7a5f3` |
| `artifacts/a55x-A556EXXUEDZE4/cve-2026-43499-app.so` | 104128 | `399039a3e0c53f840abbad989929b94f9edd56ac6275a0b17818a8355a25772a` |

## Support feed entry

`support/targets-v3.json` **replaces** the `a55x-A556EXXSECZDE` entry
(that firmware is superseded on this device) with:

```json
{
  "payloadId": "a55x-A556EXXUEDZE4",
  "displayName": "Galaxy A55 5G | Kernel 6.1.157 (UEDZE4)",
  "models": ["SM-A556E"],
  "kernelVersions": ["6.1.157"],
  "exploit": {
    "url": "https://raw.githubusercontent.com/k2-60/Root-My-Galaxy-Payloads/main/artifacts/a55x-A556EXXUEDZE4/cve-2026-43499-app.so",
    "size": 104128
  },
  "kernelsu": {
    "url": "https://raw.githubusercontent.com/k2-60/Root-My-Galaxy-Payloads/main/kernelsu/ksud-a55x-A556EXXUEDZE4-kdp",
    "size": 4767304
  }
}
```

Validated: JSON parses; `CZDE_present: False`; exploit size 104128 ==
disk; ksud size 4767304 == disk; URL basenames match the repo files.

## Models narrowed to SM-A556E (deliberate)

The entry carries `models: ["SM-A556E"]` only. The UEDZE4 AP is the
E-variant build; other regional A55 variants' kernels were not derived,
so they stay out. Kernel matching is `["6.1.157"]`.

## Route geometry and pipe budget carried from CZDE

All route/tuning fixes are unchanged (`FOPS_OFF 0x7000`, UMH
0x7800/0x7a00, compact `rt_mutex_waiter` 0x58,
`APP_ACCEPT_SCHED_TRIGGER`, Ksnitch 4096/15/5, pipe budget cap, arsenal
release, drain pipes stay at creation size). The CZDE
`fs.pipe-user-pages-soft = 8192` budget model is **carried as an
assumption, not re-measured on 6.1.157**: `fs.pipe-user-pages-soft` was
not read on this firmware (no adb in this wave). The plan line
`[pipefix] plan drain=240×2 reclaim=240×26 total=6720 (budget model
L=8192)` is the first thing to confirm with a device probe.

## PROVISIONAL / hardware status

- `SLIDE_TRACEFS_EVENT_ID = 106` — unchanged, offline-derived
  (`__TRACE_LAST_TYPE = 20`, event_index 86). Confirm live with
  `cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id`.
- `SLIDE_PSELECT_WORD_SHIFT = 3` — derived from the UEDZE4 ELF frame
  sums; the on-device validation run remains the open item.
- KernelSU: all module gates above are offline gates against the recovered
  ELF. The pair is hardware-untested on UEDZE4 until a first `late-load`
  run; the exact vermagic match and zero CRC mismatch make a module
  load failure on vermagic/CRC grounds structurally unlikely, but this is
  not a device proof.
