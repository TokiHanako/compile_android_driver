#ifndef __DEC_HOOK_H_
#define __DEC_HOOK_H_
#include "inlinehook.h"
#include "utils.h"

int (*valid_user_regs_ptr)(struct user_pt_regs *regs, struct task_struct *task) = NULL;

int (*backup_valid_user_regs)(struct user_pt_regs *regs, struct task_struct *task) = NULL;

__attribute__((no_sanitize("cfi")))
static int my_valid_user_regs(struct user_pt_regs *regs, struct task_struct *task)
{
    if (strstr(current->group_leader->comm, "tencent.tmgp")) {
        logk("===== Register Dump for %s (PID: %d) =====", current->comm, task_pid_nr(task));
        
        int i;
        for (i = 0; i < 31; i++) {
            logk("X%-2d: 0x%016llx", i, regs->regs[i]);
        }
        
        logk("SP:  0x%016llx", regs->sp);
        logk("PC:  0x%016llx", regs->pc);
        logk("PSTATE: 0x%016llx", regs->pstate);
        
        logk("=========================================");
    }
    return backup_valid_user_regs(regs, task);
}

__attribute__((no_sanitize("cfi"))) static __always_inline 
int dec_init(void) 
{
    hook_err_t err;
	if(valid_user_regs_ptr == NULL) {
		valid_user_regs_ptr = (typeof(valid_user_regs_ptr))kallsyms_lookup_name_ptr("valid_user_regs");
	}

	if (!valid_user_regs_ptr) {
		logk("failed to find valid_user_regs\n");
		return -1;
	}
	
    err = hook((void *)valid_user_regs_ptr, my_valid_user_regs, (void**)&backup_valid_user_regs);

	logk("hook valid_user_regs: %d\n", err);

	return 1;
}

static __always_inline 
void dec_exit(void) {
	unhook(valid_user_regs_ptr);
}

#endif