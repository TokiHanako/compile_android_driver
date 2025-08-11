#include <linux/module.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/hw_breakpoint.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

#ifndef HDBGEN_MAX_BREAKPOINTS
#define HDBGEN_MAX_BREAKPOINTS 4
#endif

#include "inlinehook.h"
#include "utils.h"

struct HwbpInfo {
    struct list_head list_node;
    pid_t pid;
    struct perf_event *sample_hbp;
    struct perf_event_attr original_attr;
    bool is_32bit_task;
    uint64_t jump_pc;
};

static LIST_HEAD(g_hwbp_list);
static DEFINE_SPINLOCK(g_hwbp_lock);
static atomic_t g_hwbp_count = ATOMIC_INIT(0);

static struct perf_event * (*register_user_hw_breakpoint_ptr)(struct perf_event_attr *attr, perf_overflow_handler_t triggered, void *context, struct task_struct *tsk);
static void (*unregister_hw_breakpoint_ptr)(struct perf_event *bp);
static long (*arch_ptrace_ptr)(struct task_struct *child, long request, unsigned long addr, unsigned long data) = NULL;
static long (*backup_arch_ptrace)(struct task_struct *child, long request, unsigned long addr, unsigned long data) = NULL;


static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) 
{
    struct HwbpInfo *info;
    
    spin_lock(&g_hwbp_lock);
    list_for_each_entry(info, &g_hwbp_list, list_node) {
        if (info->sample_hbp == bp) {
            logk("hw_breakpoint HIT! bp_handle:0x%px, addr:0x%llx, current_pc:0x%llx\n", 
                 bp, info->original_attr.bp_addr, regs->pc);
            
            if (info->jump_pc) {
                regs->pc = info->jump_pc;
            }
            break;
        }
    }
    spin_unlock(&g_hwbp_lock);
}

__attribute__((no_sanitize("cfi")))
int install_hwbp_hook(pid_t pid, unsigned long addr, unsigned long jump) 
{
    struct HwbpInfo *new_info;
    struct task_struct *task;
    int ret = 0;

    if (atomic_read(&g_hwbp_count) >= HDBGEN_MAX_BREAKPOINTS) {
        logk("Cannot install HWBP at 0x%lx: Maximum number of hardware breakpoints (%d) reached.\n", addr, HDBGEN_MAX_BREAKPOINTS);
        return -EBUSY;
    }

    logk("Attempting to install HWBP at virt_addr: 0x%lx for pid: %d\n", addr, pid);

    task = my_find_get_task_by_vpid(pid);
    if (!task) {
        logk("get_pid_task failed for pid %d.\n", pid);
        return -ESRCH;
    }

    new_info = kmalloc(sizeof(struct HwbpInfo), GFP_KERNEL);
    if (!new_info) {
        logk("Failed to allocate memory for HwbpInfo.\n");
        put_task_struct(task);
        return -ENOMEM;
    }

    new_info->pid = pid;
    new_info->is_32bit_task = is_compat_thread(task_thread_info(task));
    new_info->jump_pc = jump;

    ptrace_breakpoint_init(&new_info->original_attr);
    new_info->original_attr.bp_addr = addr;
    new_info->original_attr.bp_len = HW_BREAKPOINT_LEN_4; // 适用于32位和64位指令
    new_info->original_attr.bp_type = HW_BREAKPOINT_X;
    new_info->original_attr.disabled = 0;

    new_info->sample_hbp = register_user_hw_breakpoint_ptr(&new_info->original_attr, hwbp_handler, NULL, task);
    put_task_struct(task); 

    if (IS_ERR(new_info->sample_hbp)) {
        ret = PTR_ERR(new_info->sample_hbp);
        logk("register_user_hw_breakpoint failed with error: %d. This might mean no free HWBP slots are available.\n", ret);
        kfree(new_info);
        return ret;
    }
    
    atomic_inc(&g_hwbp_count);

    logk("Successfully registered bp_handle: %px, jump_pc: 0x%llx\n", new_info->sample_hbp, new_info->jump_pc);
    
    spin_lock(&g_hwbp_lock);
    list_add_tail(&new_info->list_node, &g_hwbp_list);
    spin_unlock(&g_hwbp_lock);

    return 0;
}

__attribute__((no_sanitize("cfi")))
int remove_hwbp_hook(unsigned long addr)
{
    struct HwbpInfo *info, *tmp;
    bool found = false;

    spin_lock(&g_hwbp_lock);
    
    list_for_each_entry_safe(info, tmp, &g_hwbp_list, list_node) {
        if (info->original_attr.bp_addr == addr) {
            if (info->sample_hbp && !IS_ERR(info->sample_hbp)) {
                unregister_hw_breakpoint_ptr(info->sample_hbp);
                atomic_dec(&g_hwbp_count);
                logk("Unregistered HWBP at addr: 0x%lx\n", addr);
            }
            list_del(&info->list_node);
            kfree(info);
            found = true;
            break;
        }
    }

    spin_unlock(&g_hwbp_lock);

    if (!found) {
        logk("HWBP at addr: 0x%lx not found for removal.\n", addr);
        return -ENOENT;
    }

    return 0;
}

static long my_arch_ptrace(struct task_struct *child, long request, unsigned long addr, unsigned long data) {
    long ret;
    ret = backup_arch_ptrace(child, request, addr, data);

    if (request == PTRACE_GETREGSET && (addr == NT_ARM_HW_BREAK || addr == NT_ARM_HW_WATCH)) {
        struct iovec iov;
        struct user_hwdebug_state dbg_state;
        size_t copy_size;
        int i, write_idx;

        if (ret || !data) return ret;
        
        struct iovec __user *user_iov = (struct iovec __user *)data;
        if (copy_from_user(&iov, user_iov, sizeof(iov))) return -EFAULT;
        
        if (!iov.iov_base || iov.iov_len == 0) return ret;
        
        copy_size = min(iov.iov_len, sizeof(struct user_hwdebug_state));
        if (copy_from_user(&dbg_state, (void __user *)iov.iov_base, copy_size)) return -EFAULT;
        
        spin_lock(&g_hwbp_lock);

        for (i = 0, write_idx = 0; i < HDBGEN_MAX_BREAKPOINTS; i++) {
            bool should_hide = false;
            struct HwbpInfo *info;

            if (dbg_state.dbg_regs[i].addr == 0) continue;

            list_for_each_entry(info, &g_hwbp_list, list_node) {
                if (dbg_state.dbg_regs[i].addr == info->original_attr.bp_addr) {
                    should_hide = true;
                    break;
                }
            }
            
            if (should_hide) continue;

            if (i != write_idx) {
                memcpy(&dbg_state.dbg_regs[write_idx], &dbg_state.dbg_regs[i], sizeof(dbg_state.dbg_regs[i]));
            }
            write_idx++;
        }

        spin_unlock(&g_hwbp_lock);

        for (; write_idx < HDBGEN_MAX_BREAKPOINTS; write_idx++) {
            memset(&dbg_state.dbg_regs[write_idx], 0, sizeof(dbg_state.dbg_regs[0]));
        }

        if (copy_to_user((void __user *)iov.iov_base, &dbg_state, copy_size)) {
            return -EFAULT;
        }
    }
    return ret;
}

__attribute__((no_sanitize("cfi"))) static __always_inline 
int hwbp_init(void)
{
    hook_err_t err;
    
    atomic_set(&g_hwbp_count, 0);

    unregister_hw_breakpoint_ptr = kallsyms_lookup_name_ptr("unregister_hw_breakpoint");
    register_user_hw_breakpoint_ptr = kallsyms_lookup_name_ptr("register_user_hw_breakpoint");
    
    if (!unregister_hw_breakpoint_ptr || !register_user_hw_breakpoint_ptr) {
        logk("Failed to find HWBP functions.\n");
        return -EINVAL;
    }
    
    arch_ptrace_ptr = kallsyms_lookup_name_ptr("arch_ptrace");
    if (!arch_ptrace_ptr) {
        logk("Failed to find arch_ptrace symbol! This is required for hiding.\n");
        return -EINVAL;
    }
    
    err = hook((void*)arch_ptrace_ptr, my_arch_ptrace, (void**)&backup_arch_ptrace);
    logk("hook arch_ptrace: %d\n", err);
    
    logk("hwbp module initialized.\n");
    return 0;
}

__attribute__((no_sanitize("cfi"))) static __always_inline 
void hwbp_exit(void) {
    struct HwbpInfo *info, *tmp;

    if (arch_ptrace_ptr) {
        unhook((void*)arch_ptrace_ptr);
        logk("Unhooked arch_ptrace.\n");
    }

    spin_lock(&g_hwbp_lock);
    list_for_each_entry_safe(info, tmp, &g_hwbp_list, list_node) {
        if (info->sample_hbp && !IS_ERR(info->sample_hbp)) {
            unregister_hw_breakpoint_ptr(info->sample_hbp);
            logk("Unregistered HWBP at addr: 0x%llx \n", info->original_attr.bp_addr);
        }
        list_del(&info->list_node);
        kfree(info);
    }
    spin_unlock(&g_hwbp_lock);

    logk("hwbp module exited.\n");
}