/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

// code form https://github.com/bmax121/KernelPatch

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#include "inlinehook.h"

int syscall_inited=0;

uintptr_t *sys_call_table = 0;

uintptr_t *compat_sys_call_table = 0;

int has_syscall_wrapper = 0;

int has_config_compat = 0;

struct
{
    const char *name;
    uintptr_t addr;
} syscall_name_table[460] = {
    [0] = { "sys_io_setup", 0 },
    [1] = { "sys_io_destroy", 0 },
    [2] = { "sys_io_submit", 0 },
    [3] = { "sys_io_cancel", 0 },
    [4] = { "sys_io_getevents", 0 },
    [5] = { "sys_setxattr", 0 },
    [6] = { "sys_lsetxattr", 0 },
    [7] = { "sys_fsetxattr", 0 },
    [8] = { "sys_getxattr", 0 },
    [9] = { "sys_lgetxattr", 0 },
    [10] = { "sys_fgetxattr", 0 },
    [11] = { "sys_listxattr", 0 },
    [12] = { "sys_llistxattr", 0 },
    [13] = { "sys_flistxattr", 0 },
    [14] = { "sys_removexattr", 0 },
    [15] = { "sys_lremovexattr", 0 },
    [16] = { "sys_fremovexattr", 0 },
    [17] = { "sys_getcwd", 0 },
    [19] = { "sys_eventfd2", 0 },
    [20] = { "sys_epoll_create1", 0 },
    [21] = { "sys_epoll_ctl", 0 },
    [22] = { "sys_epoll_pwait", 0 },
    [23] = { "sys_dup", 0 },
    [24] = { "sys_dup3", 0 },
    [25] = { "sys_fcntl", 0 },
    [26] = { "sys_inotify_init1", 0 },
    [27] = { "sys_inotify_add_watch", 0 },
    [28] = { "sys_inotify_rm_watch", 0 },
    [29] = { "sys_ioctl", 0 },
    [30] = { "sys_ioprio_set", 0 },
    [31] = { "sys_ioprio_get", 0 },
    [32] = { "sys_flock", 0 },
    [33] = { "sys_mknodat", 0 },
    [34] = { "sys_mkdirat", 0 },
    [35] = { "sys_unlinkat", 0 },
    [36] = { "sys_symlinkat", 0 },
    [37] = { "sys_linkat", 0 },
    [38] = { "sys_renameat", 0 },
    [39] = { "sys_umount", 0 },
    [40] = { "sys_mount", 0 },
    [41] = { "sys_pivot_root", 0 },
    [43] = { "sys_statfs", 0 },
    [44] = { "sys_fstatfs", 0 },
    [45] = { "sys_truncate", 0 },
    [46] = { "sys_ftruncate", 0 },
    [47] = { "sys_fallocate", 0 },
    [48] = { "sys_faccessat", 0 },
    [49] = { "sys_chdir", 0 },
    [50] = { "sys_fchdir", 0 },
    [51] = { "sys_chroot", 0 },
    [52] = { "sys_fchmod", 0 },
    [53] = { "sys_fchmodat", 0 },
    [54] = { "sys_fchownat", 0 },
    [55] = { "sys_fchown", 0 },
    [56] = { "sys_openat", 0 },
    [57] = { "sys_close", 0 },
    [58] = { "sys_vhangup", 0 },
    [59] = { "sys_pipe2", 0 },
    [60] = { "sys_quotactl", 0 },
    [61] = { "sys_getdents64", 0 },
    [62] = { "sys_lseek", 0 },
    [63] = { "sys_read", 0 },
    [64] = { "sys_write", 0 },
    [65] = { "sys_readv", 0 },
    [66] = { "sys_writev", 0 },
    [67] = { "sys_pread64", 0 },
    [68] = { "sys_pwrite64", 0 },
    [69] = { "sys_preadv", 0 },
    [70] = { "sys_pwritev", 0 },
    [71] = { "sys_sendfile64", 0 },
    [72] = { "sys_pselect6", 0 },
    [73] = { "sys_ppoll", 0 },
    [74] = { "sys_signalfd4", 0 },
    [75] = { "sys_vmsplice", 0 },
    [76] = { "sys_splice", 0 },
    [77] = { "sys_tee", 0 },
    [78] = { "sys_readlinkat", 0 },
    [79] = { "sys_newfstatat", 0 },
    [80] = { "sys_newfstat", 0 },
    [81] = { "sys_sync", 0 },
    [82] = { "sys_fsync", 0 },
    [83] = { "sys_fdatasync", 0 },
    [84] = { "sys_sync_file_range", 0 },
    [85] = { "sys_timerfd_create", 0 },
    [86] = { "sys_timerfd_settime", 0 },
    [87] = { "sys_timerfd_gettime", 0 },
    [88] = { "sys_utimensat", 0 },
    [89] = { "sys_acct", 0 },
    [90] = { "sys_capget", 0 },
    [91] = { "sys_capset", 0 },
    [92] = { "sys_arm64_personality", 0 },
    [93] = { "sys_exit", 0 },
    [94] = { "sys_exit_group", 0 },
    [95] = { "sys_waitid", 0 },
    [96] = { "sys_set_tid_address", 0 },
    [97] = { "sys_unshare", 0 },
    [98] = { "sys_futex", 0 },
    [99] = { "sys_set_robust_list", 0 },
    [100] = { "sys_get_robust_list", 0 },
    [101] = { "sys_nanosleep", 0 },
    [102] = { "sys_getitimer", 0 },
    [103] = { "sys_setitimer", 0 },
    [104] = { "sys_kexec_load", 0 },
    [105] = { "sys_init_module", 0 },
    [106] = { "sys_delete_module", 0 },
    [107] = { "sys_timer_create", 0 },
    [108] = { "sys_timer_gettime", 0 },
    [109] = { "sys_timer_getoverrun", 0 },
    [110] = { "sys_timer_settime", 0 },
    [111] = { "sys_timer_delete", 0 },
    [112] = { "sys_clock_settime", 0 },
    [113] = { "sys_clock_gettime", 0 },
    [114] = { "sys_clock_getres", 0 },
    [115] = { "sys_clock_nanosleep", 0 },
    [116] = { "sys_syslog", 0 },
    [117] = { "sys_ptrace", 0 },
    [118] = { "sys_sched_setparam", 0 },
    [119] = { "sys_sched_setscheduler", 0 },
    [120] = { "sys_sched_getscheduler", 0 },
    [121] = { "sys_sched_getparam", 0 },
    [122] = { "sys_sched_setaffinity", 0 },
    [123] = { "sys_sched_getaffinity", 0 },
    [124] = { "sys_sched_yield", 0 },
    [125] = { "sys_sched_get_priority_max", 0 },
    [126] = { "sys_sched_get_priority_min", 0 },
    [127] = { "sys_sched_rr_get_interval", 0 },
    [128] = { "sys_restart_syscall", 0 },
    [129] = { "sys_kill", 0 },
    [130] = { "sys_tkill", 0 },
    [131] = { "sys_tgkill", 0 },
    [132] = { "sys_sigaltstack", 0 },
    [133] = { "sys_rt_sigsuspend", 0 },
    [134] = { "sys_rt_sigaction", 0 },
    [135] = { "sys_rt_sigprocmask", 0 },
    [136] = { "sys_rt_sigpending", 0 },
    [137] = { "sys_rt_sigtimedwait", 0 },
    [138] = { "sys_rt_sigqueueinfo", 0 },
    [139] = { "sys_rt_sigreturn", 0 },
    [140] = { "sys_setpriority", 0 },
    [141] = { "sys_getpriority", 0 },
    [142] = { "sys_reboot", 0 },
    [143] = { "sys_setregid", 0 },
    [144] = { "sys_setgid", 0 },
    [145] = { "sys_setreuid", 0 },
    [146] = { "sys_setuid", 0 },
    [147] = { "sys_setresuid", 0 },
    [148] = { "sys_getresuid", 0 },
    [149] = { "sys_setresgid", 0 },
    [150] = { "sys_getresgid", 0 },
    [151] = { "sys_setfsuid", 0 },
    [152] = { "sys_setfsgid", 0 },
    [153] = { "sys_times", 0 },
    [154] = { "sys_setpgid", 0 },
    [155] = { "sys_getpgid", 0 },
    [156] = { "sys_getsid", 0 },
    [157] = { "sys_setsid", 0 },
    [158] = { "sys_getgroups", 0 },
    [159] = { "sys_setgroups", 0 },
    [160] = { "sys_newuname", 0 },
    [161] = { "sys_sethostname", 0 },
    [162] = { "sys_setdomainname", 0 },
    [163] = { "sys_getrlimit", 0 },
    [164] = { "sys_setrlimit", 0 },
    [165] = { "sys_getrusage", 0 },
    [166] = { "sys_umask", 0 },
    [167] = { "sys_prctl", 0 },
    [168] = { "sys_getcpu", 0 },
    [169] = { "sys_gettimeofday", 0 },
    [170] = { "sys_settimeofday", 0 },
    [171] = { "sys_adjtimex", 0 },
    [172] = { "sys_getpid", 0 },
    [173] = { "sys_getppid", 0 },
    [174] = { "sys_getuid", 0 },
    [175] = { "sys_geteuid", 0 },
    [176] = { "sys_getgid", 0 },
    [177] = { "sys_getegid", 0 },
    [178] = { "sys_gettid", 0 },
    [179] = { "sys_sysinfo", 0 },
    [180] = { "sys_mq_open", 0 },
    [181] = { "sys_mq_unlink", 0 },
    [182] = { "sys_mq_timedsend", 0 },
    [183] = { "sys_mq_timedreceive", 0 },
    [184] = { "sys_mq_notify", 0 },
    [185] = { "sys_mq_getsetattr", 0 },
    [186] = { "sys_msgget", 0 },
    [187] = { "sys_msgctl", 0 },
    [188] = { "sys_msgrcv", 0 },
    [189] = { "sys_msgsnd", 0 },
    [190] = { "sys_semget", 0 },
    [191] = { "sys_semctl", 0 },
    [192] = { "sys_semtimedop", 0 },
    [193] = { "sys_semop", 0 },
    [194] = { "sys_shmget", 0 },
    [195] = { "sys_shmctl", 0 },
    [196] = { "sys_shmat", 0 },
    [197] = { "sys_shmdt", 0 },
    [198] = { "sys_socket", 0 },
    [199] = { "sys_socketpair", 0 },
    [200] = { "sys_bind", 0 },
    [201] = { "sys_listen", 0 },
    [202] = { "sys_accept", 0 },
    [203] = { "sys_connect", 0 },
    [204] = { "sys_getsockname", 0 },
    [205] = { "sys_getpeername", 0 },
    [206] = { "sys_sendto", 0 },
    [207] = { "sys_recvfrom", 0 },
    [208] = { "sys_setsockopt", 0 },
    [209] = { "sys_getsockopt", 0 },
    [210] = { "sys_shutdown", 0 },
    [211] = { "sys_sendmsg", 0 },
    [212] = { "sys_recvmsg", 0 },
    [213] = { "sys_readahead", 0 },
    [214] = { "sys_brk", 0 },
    [215] = { "sys_munmap", 0 },
    [216] = { "sys_mremap", 0 },
    [217] = { "sys_add_key", 0 },
    [218] = { "sys_request_key", 0 },
    [219] = { "sys_keyctl", 0 },
    [220] = { "sys_clone", 0 },
    [221] = { "sys_execve", 0 },
    [222] = { "sys_mmap", 0 },
    [223] = { "sys_fadvise64_64", 0 },
    [224] = { "sys_swapon", 0 },
    [225] = { "sys_swapoff", 0 },
    [226] = { "sys_mprotect", 0 },
    [227] = { "sys_msync", 0 },
    [228] = { "sys_mlock", 0 },
    [229] = { "sys_munlock", 0 },
    [230] = { "sys_mlockall", 0 },
    [231] = { "sys_munlockall", 0 },
    [232] = { "sys_mincore", 0 },
    [233] = { "sys_madvise", 0 },
    [234] = { "sys_remap_file_pages", 0 },
    [235] = { "sys_mbind", 0 },
    [236] = { "sys_get_mempolicy", 0 },
    [237] = { "sys_set_mempolicy", 0 },
    [238] = { "sys_migrate_pages", 0 },
    [239] = { "sys_move_pages", 0 },
    [240] = { "sys_rt_tgsigqueueinfo", 0 },
    [241] = { "sys_perf_event_open", 0 },
    [242] = { "sys_accept4", 0 },
    [243] = { "sys_recvmmsg", 0 },
    [260] = { "sys_wait4", 0 },
    [261] = { "sys_prlimit64", 0 },
    [262] = { "sys_fanotify_init", 0 },
    [263] = { "sys_fanotify_mark", 0 },
    [264] = { "sys_name_to_handle_at", 0 },
    [265] = { "sys_open_by_handle_at", 0 },
    [266] = { "sys_clock_adjtime", 0 },
    [267] = { "sys_syncfs", 0 },
    [268] = { "sys_setns", 0 },
    [269] = { "sys_sendmmsg", 0 },
    [270] = { "sys_process_vm_readv", 0 },
    [271] = { "sys_process_vm_writev", 0 },
    [272] = { "sys_kcmp", 0 },
    [273] = { "sys_finit_module", 0 },
    [274] = { "sys_sched_setattr", 0 },
    [275] = { "sys_sched_getattr", 0 },
    [276] = { "sys_renameat2", 0 },
    [277] = { "sys_seccomp", 0 },
    [278] = { "sys_getrandom", 0 },
    [279] = { "sys_memfd_create", 0 },
    [280] = { "sys_bpf", 0 },
    [281] = { "sys_execveat", 0 },
    [282] = { "sys_userfaultfd", 0 },
    [283] = { "sys_membarrier", 0 },
    [284] = { "sys_mlock2", 0 },
    [285] = { "sys_copy_file_range", 0 },
    [286] = { "sys_preadv2", 0 },
    [287] = { "sys_pwritev2", 0 },
    [288] = { "sys_pkey_mprotect", 0 },
    [289] = { "sys_pkey_alloc", 0 },
    [290] = { "sys_pkey_free", 0 },
    [291] = { "sys_statx", 0 },
    [292] = { "sys_io_pgetevents", 0 },
    [293] = { "sys_rseq", 0 },
    [294] = { "sys_kexec_file_load", 0 },
    [424] = { "sys_pidfd_send_signal", 0 },
    [425] = { "sys_io_uring_setup", 0 },
    [426] = { "sys_io_uring_enter", 0 },
    [427] = { "sys_io_uring_register", 0 },
    [428] = { "sys_open_tree", 0 },
    [429] = { "sys_move_mount", 0 },
    [430] = { "sys_fsopen", 0 },
    [431] = { "sys_fsconfig", 0 },
    [432] = { "sys_fsmount", 0 },
    [433] = { "sys_fspick", 0 },
    [434] = { "sys_pidfd_open", 0 },
    [435] = { "sys_clone3", 0 },
    [436] = { "sys_close_range", 0 },
    [437] = { "sys_openat2", 0 },
    [438] = { "sys_pidfd_getfd", 0 },
    [439] = { "sys_faccessat2", 0 },
    [440] = { "sys_process_madvise", 0 },
    [441] = { "sys_epoll_pwait2", 0 },
    [442] = { "sys_mount_setattr", 0 },
    [443] = { "sys_quotactl_fd", 0 },
    [444] = { "sys_landlock_create_ruleset", 0 },
    [445] = { "sys_landlock_add_rule", 0 },
    [446] = { "sys_landlock_restrict_self", 0 },
    [447] = { "sys_memfd_secret", 0 },
    [448] = { "sys_process_mrelease", 0 },
    [449] = { "sys_futex_waitv", 0 },
    [450] = { "sys_set_mempolicy_home_node", 0 },
    [451] = { "sys_cachestat", 0 },
};

struct
{
    const char *name;
    uintptr_t addr;
} compat_syscall_name_table[460] = {
    [0] = { "sys_restart_syscall", 0 },
    [1] = { "sys_exit", 0 },
    [2] = { "sys_fork", 0 },
    [3] = { "sys_read", 0 },
    [4] = { "sys_write", 0 },
    [5] = { "sys_open", 0 },
    [6] = { "sys_close", 0 },
    [8] = { "sys_creat", 0 },
    [9] = { "sys_link", 0 },
    [10] = { "sys_unlink", 0 },
    [11] = { "sys_execve", 0 },
    [12] = { "sys_chdir", 0 },
    [14] = { "sys_mknod", 0 },
    [15] = { "sys_chmod", 0 },
    [16] = { "sys_lchown16", 0 },
    [19] = { "sys_lseek", 0 },
    [20] = { "sys_getpid", 0 },
    [21] = { "sys_mount", 0 },
    [23] = { "sys_setuid16", 0 },
    [24] = { "sys_getuid16", 0 },
    [26] = { "sys_ptrace", 0 },
    [29] = { "sys_pause", 0 },
    [33] = { "sys_access", 0 },
    [34] = { "sys_nice", 0 },
    [36] = { "sys_sync", 0 },
    [37] = { "sys_kill", 0 },
    [38] = { "sys_rename", 0 },
    [39] = { "sys_mkdir", 0 },
    [40] = { "sys_rmdir", 0 },
    [41] = { "sys_dup", 0 },
    [42] = { "sys_pipe", 0 },
    [43] = { "sys_times", 0 },
    [45] = { "sys_brk", 0 },
    [46] = { "sys_setgid16", 0 },
    [47] = { "sys_getgid16", 0 },
    [49] = { "sys_geteuid16", 0 },
    [50] = { "sys_getegid16", 0 },
    [51] = { "sys_acct", 0 },
    [52] = { "sys_umount", 0 },
    [54] = { "sys_ioctl", 0 },
    [55] = { "sys_fcntl", 0 },
    [57] = { "sys_setpgid", 0 },
    [60] = { "sys_umask", 0 },
    [61] = { "sys_chroot", 0 },
    [62] = { "sys_ustat", 0 },
    [63] = { "sys_dup2", 0 },
    [64] = { "sys_getppid", 0 },
    [65] = { "sys_getpgrp", 0 },
    [66] = { "sys_setsid", 0 },
    [67] = { "sys_sigaction", 0 },
    [70] = { "sys_setreuid16", 0 },
    [71] = { "sys_setregid16", 0 },
    [72] = { "sys_sigsuspend", 0 },
    [73] = { "sys_sigpending", 0 },
    [74] = { "sys_sethostname", 0 },
    [75] = { "sys_setrlimit", 0 },
    [77] = { "sys_getrusage", 0 },
    [78] = { "sys_gettimeofday", 0 },
    [79] = { "sys_settimeofday", 0 },
    [80] = { "sys_getgroups16", 0 },
    [81] = { "sys_setgroups16", 0 },
    [83] = { "sys_symlink", 0 },
    [85] = { "sys_readlink", 0 },
    [86] = { "sys_uselib", 0 },
    [87] = { "sys_swapon", 0 },
    [88] = { "sys_reboot", 0 },
    [91] = { "sys_munmap", 0 },
    [92] = { "sys_truncate", 0 },
    [93] = { "sys_ftruncate", 0 },
    [94] = { "sys_fchmod", 0 },
    [95] = { "sys_fchown16", 0 },
    [96] = { "sys_getpriority", 0 },
    [97] = { "sys_setpriority", 0 },
    [99] = { "sys_statfs", 0 },
    [100] = { "sys_fstatfs", 0 },
    [103] = { "sys_syslog", 0 },
    [104] = { "sys_setitimer", 0 },
    [105] = { "sys_getitimer", 0 },
    [106] = { "sys_newstat", 0 },
    [107] = { "sys_newlstat", 0 },
    [108] = { "sys_newfstat", 0 },
    [111] = { "sys_vhangup", 0 },
    [114] = { "sys_wait4", 0 },
    [115] = { "sys_swapoff", 0 },
    [116] = { "sys_sysinfo", 0 },
    [118] = { "sys_fsync", 0 },
    [119] = { "sys_sigreturn", 0 },
    [120] = { "sys_clone", 0 },
    [121] = { "sys_setdomainname", 0 },
    [122] = { "sys_newuname", 0 },
    [124] = { "sys_adjtimex_time32", 0 },
    [125] = { "sys_mprotect", 0 },
    [126] = { "sys_sigprocmask", 0 },
    [128] = { "sys_init_module", 0 },
    [129] = { "sys_delete_module", 0 },
    [131] = { "sys_quotactl", 0 },
    [132] = { "sys_getpgid", 0 },
    [133] = { "sys_fchdir", 0 },
    [135] = { "sys_sysfs", 0 },
    [136] = { "sys_personality", 0 },
    [138] = { "sys_setfsuid16", 0 },
    [139] = { "sys_setfsgid16", 0 },
    [140] = { "sys_llseek", 0 },
    [141] = { "sys_getdents", 0 },
    [142] = { "sys_select", 0 },
    [143] = { "sys_flock", 0 },
    [144] = { "sys_msync", 0 },
    [145] = { "sys_readv", 0 },
    [146] = { "sys_writev", 0 },
    [147] = { "sys_getsid", 0 },
    [148] = { "sys_fdatasync", 0 },
    [150] = { "sys_mlock", 0 },
    [151] = { "sys_munlock", 0 },
    [152] = { "sys_mlockall", 0 },
    [153] = { "sys_munlockall", 0 },
    [154] = { "sys_sched_setparam", 0 },
    [155] = { "sys_sched_getparam", 0 },
    [156] = { "sys_sched_setscheduler", 0 },
    [157] = { "sys_sched_getscheduler", 0 },
    [158] = { "sys_sched_yield", 0 },
    [159] = { "sys_sched_get_priority_max", 0 },
    [160] = { "sys_sched_get_priority_min", 0 },
    [161] = { "sys_sched_rr_get_interval_time32", 0 },
    [162] = { "sys_nanosleep_time32", 0 },
    [163] = { "sys_mremap", 0 },
    [164] = { "sys_setresuid16", 0 },
    [165] = { "sys_getresuid16", 0 },
    [168] = { "sys_poll", 0 },
    [170] = { "sys_setresgid16", 0 },
    [171] = { "sys_getresgid16", 0 },
    [172] = { "sys_prctl", 0 },
    [173] = { "sys_rt_sigreturn", 0 },
    [174] = { "sys_rt_sigaction", 0 },
    [175] = { "sys_rt_sigprocmask", 0 },
    [176] = { "sys_rt_sigpending", 0 },
    [177] = { "sys_rt_sigtimedwait_time32", 0 },
    [178] = { "sys_rt_sigqueueinfo", 0 },
    [179] = { "sys_rt_sigsuspend", 0 },
    [180] = { "sys_aarch32_pread64", 0 },
    [181] = { "sys_aarch32_pwrite64", 0 },
    [182] = { "sys_chown16", 0 },
    [183] = { "sys_getcwd", 0 },
    [184] = { "sys_capget", 0 },
    [185] = { "sys_capset", 0 },
    [186] = { "sys_sigaltstack", 0 },
    [187] = { "sys_sendfile", 0 },
    [190] = { "sys_vfork", 0 },
    [191] = { "sys_getrlimit", 0 },
    [192] = { "sys_aarch32_mmap2", 0 },
    [193] = { "sys_aarch32_truncate64", 0 },
    [194] = { "sys_aarch32_ftruncate64", 0 },
    [195] = { "sys_stat64", 0 },
    [196] = { "sys_lstat64", 0 },
    [197] = { "sys_fstat64", 0 },
    [198] = { "sys_lchown", 0 },
    [199] = { "sys_getuid", 0 },
    [200] = { "sys_getgid", 0 },
    [201] = { "sys_geteuid", 0 },
    [202] = { "sys_getegid", 0 },
    [203] = { "sys_setreuid", 0 },
    [204] = { "sys_setregid", 0 },
    [205] = { "sys_getgroups", 0 },
    [206] = { "sys_setgroups", 0 },
    [207] = { "sys_fchown", 0 },
    [208] = { "sys_setresuid", 0 },
    [209] = { "sys_getresuid", 0 },
    [210] = { "sys_setresgid", 0 },
    [211] = { "sys_getresgid", 0 },
    [212] = { "sys_chown", 0 },
    [213] = { "sys_setuid", 0 },
    [214] = { "sys_setgid", 0 },
    [215] = { "sys_setfsuid", 0 },
    [216] = { "sys_setfsgid", 0 },
    [217] = { "sys_getdents64", 0 },
    [218] = { "sys_pivot_root", 0 },
    [219] = { "sys_mincore", 0 },
    [220] = { "sys_madvise", 0 },
    [221] = { "sys_fcntl64", 0 },
    [224] = { "sys_gettid", 0 },
    [225] = { "sys_aarch32_readahead", 0 },
    [226] = { "sys_setxattr", 0 },
    [227] = { "sys_lsetxattr", 0 },
    [228] = { "sys_fsetxattr", 0 },
    [229] = { "sys_getxattr", 0 },
    [230] = { "sys_lgetxattr", 0 },
    [231] = { "sys_fgetxattr", 0 },
    [232] = { "sys_listxattr", 0 },
    [233] = { "sys_llistxattr", 0 },
    [234] = { "sys_flistxattr", 0 },
    [235] = { "sys_removexattr", 0 },
    [236] = { "sys_lremovexattr", 0 },
    [237] = { "sys_fremovexattr", 0 },
    [238] = { "sys_tkill", 0 },
    [239] = { "sys_sendfile64", 0 },
    [240] = { "sys_futex_time32", 0 },
    [241] = { "sys_sched_setaffinity", 0 },
    [242] = { "sys_sched_getaffinity", 0 },
    [243] = { "sys_io_setup", 0 },
    [244] = { "sys_io_destroy", 0 },
    [245] = { "sys_io_getevents_time32", 0 },
    [246] = { "sys_io_submit", 0 },
    [247] = { "sys_io_cancel", 0 },
    [248] = { "sys_exit_group", 0 },
    [250] = { "sys_epoll_create", 0 },
    [251] = { "sys_epoll_ctl", 0 },
    [252] = { "sys_epoll_wait", 0 },
    [253] = { "sys_remap_file_pages", 0 },
    [256] = { "sys_set_tid_address", 0 },
    [257] = { "sys_timer_create", 0 },
    [258] = { "sys_timer_settime32", 0 },
    [259] = { "sys_timer_gettime32", 0 },
    [260] = { "sys_timer_getoverrun", 0 },
    [261] = { "sys_timer_delete", 0 },
    [262] = { "sys_clock_settime32", 0 },
    [263] = { "sys_clock_gettime32", 0 },
    [264] = { "sys_clock_getres_time32", 0 },
    [265] = { "sys_clock_nanosleep_time32", 0 },
    [266] = { "sys_aarch32_statfs64", 0 },
    [267] = { "sys_aarch32_fstatfs64", 0 },
    [268] = { "sys_tgkill", 0 },
    [269] = { "sys_utimes_time32", 0 },
    [270] = { "sys_aarch32_fadvise64_64", 0 },
    [272] = { "sys_pciconfig_read", 0 },
    [273] = { "sys_pciconfig_write", 0 },
    [274] = { "sys_mq_open", 0 },
    [275] = { "sys_mq_unlink", 0 },
    [276] = { "sys_mq_timedsend_time32", 0 },
    [277] = { "sys_mq_timedreceive_time32", 0 },
    [278] = { "sys_mq_notify", 0 },
    [279] = { "sys_mq_getsetattr", 0 },
    [280] = { "sys_waitid", 0 },
    [281] = { "sys_socket", 0 },
    [282] = { "sys_bind", 0 },
    [283] = { "sys_connect", 0 },
    [284] = { "sys_listen", 0 },
    [285] = { "sys_accept", 0 },
    [286] = { "sys_getsockname", 0 },
    [287] = { "sys_getpeername", 0 },
    [288] = { "sys_socketpair", 0 },
    [289] = { "sys_send", 0 },
    [290] = { "sys_sendto", 0 },
    [291] = { "sys_recv", 0 },
    [292] = { "sys_recvfrom", 0 },
    [293] = { "sys_shutdown", 0 },
    [294] = { "sys_setsockopt", 0 },
    [295] = { "sys_getsockopt", 0 },
    [296] = { "sys_sendmsg", 0 },
    [297] = { "sys_recvmsg", 0 },
    [298] = { "sys_semop", 0 },
    [299] = { "sys_semget", 0 },
    [300] = { "sys_old_semctl", 0 },
    [301] = { "sys_msgsnd", 0 },
    [302] = { "sys_msgrcv", 0 },
    [303] = { "sys_msgget", 0 },
    [304] = { "sys_old_msgctl", 0 },
    [305] = { "sys_shmat", 0 },
    [306] = { "sys_shmdt", 0 },
    [307] = { "sys_shmget", 0 },
    [308] = { "sys_old_shmctl", 0 },
    [309] = { "sys_add_key", 0 },
    [310] = { "sys_request_key", 0 },
    [311] = { "sys_keyctl", 0 },
    [312] = { "sys_semtimedop_time32", 0 },
    [314] = { "sys_ioprio_set", 0 },
    [315] = { "sys_ioprio_get", 0 },
    [316] = { "sys_inotify_init", 0 },
    [317] = { "sys_inotify_add_watch", 0 },
    [318] = { "sys_inotify_rm_watch", 0 },
    [319] = { "sys_mbind", 0 },
    [320] = { "sys_get_mempolicy", 0 },
    [321] = { "sys_set_mempolicy", 0 },
    [322] = { "sys_openat", 0 },
    [323] = { "sys_mkdirat", 0 },
    [324] = { "sys_mknodat", 0 },
    [325] = { "sys_fchownat", 0 },
    [326] = { "sys_futimesat_time32", 0 },
    [327] = { "sys_fstatat64", 0 },
    [328] = { "sys_unlinkat", 0 },
    [329] = { "sys_renameat", 0 },
    [330] = { "sys_linkat", 0 },
    [331] = { "sys_symlinkat", 0 },
    [332] = { "sys_readlinkat", 0 },
    [333] = { "sys_fchmodat", 0 },
    [334] = { "sys_faccessat", 0 },
    [335] = { "sys_pselect6_time32", 0 },
    [336] = { "sys_ppoll_time32", 0 },
    [337] = { "sys_unshare", 0 },
    [338] = { "sys_set_robust_list", 0 },
    [339] = { "sys_get_robust_list", 0 },
    [340] = { "sys_splice", 0 },
    [341] = { "sys_aarch32_sync_file_range2", 0 },
    [342] = { "sys_tee", 0 },
    [343] = { "sys_vmsplice", 0 },
    [344] = { "sys_move_pages", 0 },
    [345] = { "sys_getcpu", 0 },
    [346] = { "sys_epoll_pwait", 0 },
    [347] = { "sys_kexec_load", 0 },
    [348] = { "sys_utimensat_time32", 0 },
    [349] = { "sys_signalfd", 0 },
    [350] = { "sys_timerfd_create", 0 },
    [351] = { "sys_eventfd", 0 },
    [352] = { "sys_aarch32_fallocate", 0 },
    [353] = { "sys_timerfd_settime32", 0 },
    [354] = { "sys_timerfd_gettime32", 0 },
    [355] = { "sys_signalfd4", 0 },
    [356] = { "sys_eventfd2", 0 },
    [357] = { "sys_epoll_create1", 0 },
    [358] = { "sys_dup3", 0 },
    [359] = { "sys_pipe2", 0 },
    [360] = { "sys_inotify_init1", 0 },
    [361] = { "sys_preadv", 0 },
    [362] = { "sys_pwritev", 0 },
    [363] = { "sys_rt_tgsigqueueinfo", 0 },
    [364] = { "sys_perf_event_open", 0 },
    [365] = { "sys_recvmmsg_time32", 0 },
    [366] = { "sys_accept4", 0 },
    [367] = { "sys_fanotify_init", 0 },
    [368] = { "sys_fanotify_mark", 0 },
    [369] = { "sys_prlimit64", 0 },
    [370] = { "sys_name_to_handle_at", 0 },
    [371] = { "sys_open_by_handle_at", 0 },
    [372] = { "sys_clock_adjtime32", 0 },
    [373] = { "sys_syncfs", 0 },
    [374] = { "sys_sendmmsg", 0 },
    [375] = { "sys_setns", 0 },
    [376] = { "sys_process_vm_readv", 0 },
    [377] = { "sys_process_vm_writev", 0 },
    [378] = { "sys_kcmp", 0 },
    [379] = { "sys_finit_module", 0 },
    [380] = { "sys_sched_setattr", 0 },
    [381] = { "sys_sched_getattr", 0 },
    [382] = { "sys_renameat2", 0 },
    [383] = { "sys_seccomp", 0 },
    [384] = { "sys_getrandom", 0 },
    [385] = { "sys_memfd_create", 0 },
    [386] = { "sys_bpf", 0 },
    [387] = { "sys_execveat", 0 },
    [388] = { "sys_userfaultfd", 0 },
    [389] = { "sys_membarrier", 0 },
    [390] = { "sys_mlock2", 0 },
    [391] = { "sys_copy_file_range", 0 },
    [392] = { "sys_preadv2", 0 },
    [393] = { "sys_pwritev2", 0 },
    [394] = { "sys_pkey_mprotect", 0 },
    [395] = { "sys_pkey_alloc", 0 },
    [396] = { "sys_pkey_free", 0 },
    [397] = { "sys_statx", 0 },
    [398] = { "sys_rseq", 0 },
    [399] = { "sys_io_pgetevents", 0 },
    [400] = { "sys_migrate_pages", 0 },
    [401] = { "sys_kexec_file_load", 0 },
    [403] = { "sys_clock_gettime", 0 },
    [404] = { "sys_clock_settime", 0 },
    [405] = { "sys_clock_adjtime", 0 },
    [406] = { "sys_clock_getres", 0 },
    [407] = { "sys_clock_nanosleep", 0 },
    [408] = { "sys_timer_gettime", 0 },
    [409] = { "sys_timer_settime", 0 },
    [410] = { "sys_timerfd_gettime", 0 },
    [411] = { "sys_timerfd_settime", 0 },
    [412] = { "sys_utimensat", 0 },
    [413] = { "sys_pselect6_time64", 0 },
    [414] = { "sys_ppoll_time64", 0 },
    [416] = { "sys_io_pgetevents", 0 },
    [417] = { "sys_recvmmsg_time64", 0 },
    [418] = { "sys_mq_timedsend", 0 },
    [419] = { "sys_mq_timedreceive", 0 },
    [420] = { "sys_semtimedop", 0 },
    [421] = { "sys_rt_sigtimedwait_time64", 0 },
    [422] = { "sys_futex", 0 },
    [423] = { "sys_sched_rr_get_interval", 0 },
    [424] = { "sys_pidfd_send_signal", 0 },
    [425] = { "sys_io_uring_setup", 0 },
    [426] = { "sys_io_uring_enter", 0 },
    [427] = { "sys_io_uring_register", 0 },
    [428] = { "sys_open_tree", 0 },
    [429] = { "sys_move_mount", 0 },
    [430] = { "sys_fsopen", 0 },
    [431] = { "sys_fsconfig", 0 },
    [432] = { "sys_fsmount", 0 },
    [433] = { "sys_fspick", 0 },
    [434] = { "sys_pidfd_open", 0 },
    [435] = { "sys_clone3", 0 },
    [436] = { "sys_close_range", 0 },
    [437] = { "sys_openat2", 0 },
    [438] = { "sys_pidfd_getfd", 0 },
    [439] = { "sys_faccessat2", 0 },
    [440] = { "sys_process_madvise", 0 },
    [441] = { "sys_epoll_pwait2", 0 },
    [442] = { "sys_mount_setattr", 0 },
    [443] = { "sys_quotactl_fd", 0 },
    [444] = { "sys_landlock_create_ruleset", 0 },
    [445] = { "sys_landlock_add_rule", 0 },
    [446] = { "sys_landlock_restrict_self", 0 },
    [448] = { "sys_process_mrelease", 0 },
    [449] = { "sys_futex_waitv", 0 },
    [450] = { "sys_set_mempolicy_home_node", 0 },
    [451] = { "sys_cachestat", 0 },
};

struct user_arg_ptr
{
    union
    {
        const char __user *const __user *native;
    } ptr;
};

struct user_arg_ptr_compat
{
    bool is_compat;
    union
    {
        const char __user *const __user *native;
        const compat_uptr_t __user *compat;
    } ptr;
};

// actually, a0 is true if it is compat
__attribute__((no_sanitize("cfi")))  static __always_inline 
const char __user *get_user_arg_ptr(void *a0, void *a1, int nr)
{
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) size = 4; // compat
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    char __user **upptr = memdup_user(native, size);
    if (IS_ERR(upptr)) return ERR_PTR((long)upptr);

    char __user *uptr;
    if (size == 8) {
        uptr = *upptr;
    } else {
        uptr = (char __user *)(unsigned long)*(int32_t *)upptr;
    }
    kfree(upptr);
    return uptr;
}


__attribute__((no_sanitize("cfi")))  static __always_inline 
int set_user_arg_ptr(void *a0, void *a1, int nr, uintptr_t val)
{
    uintptr_t valp = (uintptr_t)&val;
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) {
            size = 4; // compat
            valp += 4;
        }
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    int cplen = copy_to_user((void *)native, (void *)valp, size);
    return cplen == size ? 0 : cplen;
}

typedef long (*warp_raw_syscall_f)(const struct pt_regs *regs);
typedef long (*raw_syscall0_f)(void);
typedef long (*raw_syscall1_f)(long arg0);
typedef long (*raw_syscall2_f)(long arg0, long arg1);
typedef long (*raw_syscall3_f)(long arg0, long arg1, long arg2);
typedef long (*raw_syscall4_f)(long arg0, long arg1, long arg2, long arg3);
typedef long (*raw_syscall5_f)(long arg0, long arg1, long arg2, long arg3, long arg4);
typedef long (*raw_syscall6_f)(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

long raw_syscall0(long nr);
long raw_syscall1(long nr, long arg0);
long raw_syscall2(long nr, long arg0, long arg1);
long raw_syscall3(long nr, long arg0, long arg1, long arg2);
long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3);
long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4);
long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

#define raw_syscall(f) raw_syscall##f


static inline uint64_t *syscall_args(void *hook_fargs)
{
    uint64_t *args;
    if (has_syscall_wrapper) {
        args = ((struct pt_regs *)((hook_fargs0_t *)hook_fargs)->args[0])->regs;
    } else {
        args = ((hook_fargs0_t *)hook_fargs)->args;
    }
    return args;
}

static inline uint64_t syscall_argn(void *fdata_args, int n)
{
    return syscall_args(fdata_args)[n];
}

static inline void set_syscall_argn(void *fdata_args, int n, uint64_t val)
{
    uint64_t *args = syscall_args(fdata_args);
    args[n] = val;
}

static inline void *syscall_argn_p(void *fdata_args, int n)
{
    return syscall_args(fdata_args) + n;
}

__attribute__((no_sanitize("cfi")))  static __always_inline 
uintptr_t syscalln_name_addr(int nr, int is_compat)
{
    const char *name = 0;
    if (!is_compat) {
        if (syscall_name_table[nr].addr) {
            return syscall_name_table[nr].addr;
        }
        name = syscall_name_table[nr].name;
    } else {
        if (compat_syscall_name_table[nr].addr) {
            return compat_syscall_name_table[nr].addr;
        }
        name = compat_syscall_name_table[nr].name;
    }

    if (!name) return 0;

    const char *prefix[2];
    prefix[0] = "__arm64_";
    prefix[1] = "";
    const char *suffix[3];
    suffix[0] = ".cfi_jt";
    suffix[1] = ".cfi";
    suffix[2] = "";

    uintptr_t addr = 0;

    char buffer[256];
    int i;
    for (i = 0; i < 2; i++) {
        int j;
    for (j = 0; j < 3; j++) {
            snprintf(buffer, sizeof(buffer), "%s%s%s", prefix[i], name, suffix[j]);
            addr = kallsyms_lookup_name_ptr(buffer);
            if (addr) break;
        }
        if (addr) break;
    }
    if (!is_compat) {
        syscall_name_table[nr].addr = addr;
    } else {
        compat_syscall_name_table[nr].addr = addr;
    }
    return addr;
}

__attribute__((no_sanitize("cfi")))  static __always_inline 
uintptr_t syscalln_addr(int nr, int is_compat)
{
    if (!is_compat && sys_call_table) return sys_call_table[nr];
    if (is_compat && compat_sys_call_table) return compat_sys_call_table[nr];
    return syscalln_name_addr(nr, is_compat);
}

__attribute__((no_sanitize("cfi")))
long raw_syscall0(long nr)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall0_f)addr)();
}

__attribute__((no_sanitize("cfi")))
long raw_syscall1(long nr, long arg0)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall1_f)addr)(arg0);
}

__attribute__((no_sanitize("cfi")))
long raw_syscall2(long nr, long arg0, long arg1)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall2_f)addr)(arg0, arg1);
}

__attribute__((no_sanitize("cfi")))
long raw_syscall3(long nr, long arg0, long arg1, long arg2)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall3_f)addr)(arg0, arg1, arg2);
}

__attribute__((no_sanitize("cfi")))
long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall4_f)addr)(arg0, arg1, arg2, arg3);
}

__attribute__((no_sanitize("cfi")))
long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall5_f)addr)(arg0, arg1, arg2, arg3, arg4);
}

__attribute__((no_sanitize("cfi")))
long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        regs.regs[5] = arg5;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall6_f)addr)(arg0, arg1, arg2, arg3, arg4, arg5);
}

__attribute__((no_sanitize("cfi"))) static __always_inline 
void syscall_init(void)
{
    sys_call_table = (typeof(sys_call_table))kallsyms_lookup_name_ptr("sys_call_table");
    logk("sys_call_table addr: %llx\n", sys_call_table);

    compat_sys_call_table = (typeof(compat_sys_call_table))kallsyms_lookup_name_ptr("compat_sys_call_table");
    logk("compat_sys_call_table addr: %llx\n", compat_sys_call_table);

    has_config_compat = 0;
    has_syscall_wrapper = 0;

    if (kallsyms_lookup_name_ptr("__arm64_compat_sys_openat")) {
        has_config_compat = 1;
        has_syscall_wrapper = 1;
    } else {
        if (kallsyms_lookup_name_ptr("compat_sys_call_table") || kallsyms_lookup_name_ptr("compat_sys_openat")) {
            has_config_compat = 1;
        }
        if (kallsyms_lookup_name_ptr("__arm64_sys_openat")) {
            has_syscall_wrapper = 1;
        }
    }

    logk("syscall config_compat: %d\n", has_config_compat);
    logk("syscall has_wrapper: %d\n", has_syscall_wrapper);
    syscall_inited=1;
}


__attribute__((no_sanitize("cfi")))  static __always_inline 
hook_err_t inline_syscall(int nr, int is_compat, void *replace, void **backup)
{
    if(syscall_inited==0)
    {
        syscall_init();
    }
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    if (!addr) return -HOOK_BAD_ADDRESS;
    return hook((void *)addr, replace, backup);
}

__attribute__((no_sanitize("cfi")))  static __always_inline 
void inline_unsyscall(int nr, int is_compat)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    unhook((void *)addr);
}

/*
sys_xxx.cfi_jt

hint #0x22  # bti c
b #0xfffffffffeb452f4
*/

__attribute__((no_sanitize("cfi")))  static __always_inline 
hook_err_t inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    if(syscall_inited==0)
    {
        syscall_init();
    }
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    if (!addr) return -HOOK_BAD_ADDRESS;
    if (has_syscall_wrapper) narg = 1;
    return hook_wrap((void *)addr, narg, before, after, udata);
}

__attribute__((no_sanitize("cfi")))  static __always_inline 
void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    hook_unwrap((void *)addr, before, after);
}

__attribute__((no_sanitize("cfi")))  static __always_inline 
hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}

__attribute__((no_sanitize("cfi")))  static __always_inline 
void unhook_syscalln(int nr, void *before, void *after)
{
    return inline_unwrap_syscalln(nr, 0, before, after);
}

__attribute__((no_sanitize("cfi")))  static __always_inline 
hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    return inline_wrap_syscalln(nr, narg, 1, before, after, udata);
}


__attribute__((no_sanitize("cfi")))  static __always_inline 
void unhook_compat_syscalln(int nr, void *before, void *after)
{
    return inline_unwrap_syscalln(nr, 1, before, after);
}

static inline hook_err_t inline_hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}

static inline void inline_unhook_syscalln(int nr, void *before, void *after)
{
    inline_unwrap_syscalln(nr, 0, before, after);
}

static inline hook_err_t inline_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    return inline_wrap_syscalln(nr, narg, 1, before, after, udata);
}

static inline void inline_unhook_compat_syscalln(int nr, void *before, void *after)
{
    inline_unwrap_syscalln(nr, 0, before, after);
}