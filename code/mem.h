
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#ifndef __MEMORY_H
#define __MEMORY_H
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/memory.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/moduleloader.h>
#include <linux/stop_machine.h>
#include <linux/bpf.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/ioctl.h>
#include <linux/random.h>
#include <linux/kernel.h>

#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/mm.h>

#include <linux/file.h>
#include <linux/uaccess.h>

#include <linux/radix-tree.h>
#include <asm/cpufeature.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>

#include <linux/uaccess.h>
#include <asm/barrier.h>
#include <asm/unaligned.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/mmap_lock.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
#define MM_READ_LOCK(mm)    mmap_read_lock(mm)
#define MM_READ_UNLOCK(mm)  mmap_read_unlock(mm)
#else
#include <linux/rwsem.h>
#define MM_READ_LOCK(mm)    down_read(&(mm)->mmap_sem)
#define MM_READ_UNLOCK(mm)  up_read(&(mm)->mmap_sem)
#endif

#include "utils.h"

#if !defined(ARCH_HAS_VALID_PHYS_ADDR_RANGE) || defined(MODULE)
static void ** high_memory_ptr = NULL;
static inline int memk_valid_phys_addr_range(phys_addr_t addr, size_t size)
{
	return addr + size <= __pa(*high_memory_ptr);
}
#define IS_VALID_PHYS_ADDR_RANGE(x, y) memk_valid_phys_addr_range(x, y)
#else
#define IS_VALID_PHYS_ADDR_RANGE(x, y) valid_phys_addr_range(x, y)
#endif

#if !defined(min)
#define min(x, y) ({        \
typeof(x) _min1 = (x);  \
typeof(y) _min2 = (y);  \
(void) (&_min1 == &_min2); \
_min1 < _min2 ? _min1 : _min2; })
#endif

static size_t dcache_line_size = 0;

static DEFINE_RAW_SPINLOCK(vmap_cache_lock);
static RADIX_TREE(vmap_cache_tree, GFP_ATOMIC);

typedef struct _REQUEST {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} REQUEST, *P_REQUEST;

uintptr_t get_module_base(pid_t pid, char *name) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif
    uintptr_t result;
    char buf[256];
	char *path_nm = NULL;

    result = 0;

    task = my_find_get_task_by_vpid(pid);
    if (!task) {
		logk("failed to get task from %\n",pid);
        return 0;
    }

    mm = get_task_mm(task);
    if (!mm) {
		logk("failed to get mm from task\n");
        return 0;
    }

    MM_READ_LOCK(mm);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
        for (vma = find_vma(mm, 0); vma; vma = find_vma(mm, vma->vm_end))
#endif
    {
        if (vma->vm_file) {
			path_nm = file_path(vma->vm_file, buf, 255);
			//logk("path=%s",path_nm);
			if (IS_ERR(path_nm)){
			path_nm = NULL;
			}else{
			if(strstr(kbasename(path_nm), name)!=NULL)
			{
			    //logk("path=%s",path_nm);
				result = vma->vm_start;
				goto ret;
			}
        }
        }
        }
    ret:
    MM_READ_UNLOCK(mm);

    mmput(mm);
    return result;
}
/*
__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub")))) 
__attribute__((no_sanitize("cfi")))  static __always_inline 
void flush_to_page(void* addr, size_t size)
{
    unsigned long offset;

    offset = (unsigned long)addr & (PAGE_SIZE - 1);
    char *data_ptr = addr;
    size_t remaining = size;

    while (remaining > 0) {
        size_t chunk = min(remaining, (size_t)(PAGE_SIZE - offset));
        unsigned long start, end;
        
        dmb(ish);
        
        start = ALIGN_DOWN((unsigned long)data_ptr, dcache_line_size);
        end = ALIGN((unsigned long)data_ptr + chunk, dcache_line_size);
        
        for (; start < end; start += dcache_line_size) {
            asm volatile("DC CIVAC, %0" : : "r"(start) : "memory");
        }
        
        dsb(ish);
        isb();

        if (chunk > INT_MAX) {
            return;
        }
        
        remaining -= chunk;
        data_ptr += chunk;
        offset = 0;
    }
    
    return;
}
*/

__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub")))) 
__attribute__((no_sanitize("cfi")))  static __always_inline 
void flush_to_page(void* addr, size_t size)
{
    
    unsigned long start = (unsigned long)addr;
    unsigned long end = start + size;
    
    unsigned long aligned_start = ALIGN_DOWN(start, dcache_line_size);
    unsigned long aligned_end = ALIGN(end, dcache_line_size);
    
    dmb(ish);
    unsigned long cur;
    for (cur = aligned_start; cur < aligned_end; cur += dcache_line_size) {
        asm volatile("DC CIVAC, %0" : : "r"(cur) : "memory");
    }
    
    dsb(ish);
    isb();
}

__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub")))) 
__attribute__((no_sanitize("cfi")))  static __always_inline 
void cleanup_cache(void)
{
    struct radix_tree_iter iter;
    void __rcu **slot;
    unsigned long flags;
    
    raw_spin_lock_irqsave(&vmap_cache_lock, flags);
    radix_tree_for_each_slot(slot, &vmap_cache_tree, &iter, 0) {
        void *vaddr = rcu_dereference_protected(*slot, true);
        radix_tree_delete(&vmap_cache_tree, iter.index);
        vunmap(vaddr);
    }
    raw_spin_unlock_irqrestore(&vmap_cache_lock, flags);
}

__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub")))) 
__attribute__((no_sanitize("cfi")))  static __always_inline 
unsigned long phys_to_vaddr(unsigned long phys_addr)
{
    unsigned long flags;
    void *vaddr = NULL;
    pgprot_t prot;
    struct page *page;
    int ret;
    void *existing;
    unsigned long align_phys = phys_addr & PAGE_MASK;
    unsigned long offset = phys_addr & ~PAGE_MASK;

    if (!pfn_valid(__phys_to_pfn(align_phys)))
        return 0;

    if (cpus_have_const_cap(ARM64_HAS_CACHE_DIC)) {
        prot = __pgprot(0x68000000000F0FLL); // pgprot_writecombine(PAGE_KERNEL);
    } else {
        prot = __pgprot(0x6800000000070FLL); // pgprot_noncached(PAGE_KERNEL);
    }

    raw_spin_lock_irqsave(&vmap_cache_lock, flags);
    vaddr = radix_tree_lookup(&vmap_cache_tree, align_phys);
    raw_spin_unlock_irqrestore(&vmap_cache_lock, flags);
    
    if (vaddr)
        return (unsigned long)vaddr + offset;

    page = pfn_to_page(__phys_to_pfn(align_phys));
    vaddr = vmap(&page, 1, VM_MAP, prot);
    if (!vaddr)
        return 0;

    raw_spin_lock_irqsave(&vmap_cache_lock, flags);
    existing = radix_tree_lookup(&vmap_cache_tree, align_phys);
    if (existing) {
        raw_spin_unlock_irqrestore(&vmap_cache_lock, flags);
        vunmap(vaddr);
        return (unsigned long)existing + offset;
    }
    
    ret = radix_tree_insert(&vmap_cache_tree, align_phys, vaddr);
    raw_spin_unlock_irqrestore(&vmap_cache_lock, flags);
    
    if (ret) {
        vunmap(vaddr);
        return 0;
    }
    
    return (unsigned long)vaddr + offset;
}


__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub"))))
static pte_t *page_from_virt_user(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
#if __PAGETABLE_P4D_FOLDED == 1
	p4d_t *p4d;
#endif
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep;
	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return NULL;
	}
#if __PAGETABLE_P4D_FOLDED == 1
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
	{
		return 0;
	}
	pudp = pud_offset(p4d, addr);
#else
	pudp = pud_offset(pgd, addr);
#endif
	pud = READ_ONCE(*pudp);
	if (pud_none(pud) || pud_bad(pud))
	{
		return NULL;
	}
#if defined(pud_leaf) && defined(BIG_PAGE)
	if (pud_leaf(pud))
	{
		ptep = (pte_t *)pudp;
		goto ret;
	}
#endif
	pmdp = pmd_offset(pudp, addr);
	pmd = READ_ONCE(*pmdp);
	if (pmd_none(pmd) || pmd_bad(pmd))
	{
		return NULL;
	}
#if defined(pmd_leaf) && defined(BIG_PAGE)
	if (pmd_leaf(pmd))
	{
		ptep = (pte_t *)pmdp;
		return ptep;
	}
#endif
	ptep = pte_offset_kernel(pmdp, addr);
	if (!ptep)
	{
		return NULL;
	}
	
	return ptep;
}

__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub"))))
static phys_addr_t virt_addr_to_phy_addr(struct mm_struct *mm, uintptr_t va)
{
	pte_t *ptep;
	phys_addr_t page_addr;
	uintptr_t page_offset;
	if (!mm)
		return 0;
	ptep = page_from_virt_user(mm, va);
	if (!ptep)
	{
		return 0;
	}
	if (!pte_present(*ptep))
	{
		return 0;
	}
	page_offset = va & (PAGE_SIZE - 1);
#if defined(__pte_to_phys)
	page_addr = (phys_addr_t)__pte_to_phys(*ptep);
#elif defined(pte_pfn)
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
#else
#error unsupported kernel version：__pte_to_phys or pte_pfn
#endif
	if (page_addr == 0)
	{
		return 0;
	}
	return page_addr + page_offset;
}
__attribute__((__annotate__(("nosub nofco strenc nobcf fla nosub"))))
int pid_vaddr_to_phy(pid_t pid, void *addr, phys_addr_t *pa)
{
	struct task_struct *task;
	struct mm_struct *mm;
	task = my_find_get_task_by_vpid(pid);
    if (!task) {
		logk("failed to get task from %\n",pid);
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
		logk("failed to get mm from task\n");
        return -ESRCH;
    }
	MM_READ_LOCK(mm);
	*pa = virt_addr_to_phy_addr(mm, (uintptr_t)addr);
	MM_READ_UNLOCK(mm);
	mmput(mm);
	
	if (*pa == 0)
	{
		return -EFAULT;
	}
	return 0;
}

/*
__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub"))))
int read_process_memory(pid_t pid, void __user *addr, void __user *dest, size_t size)
{
	phys_addr_t phy_addr;
	int ret = 0;
	size_t processed = 0;
	size_t max;
	void *mapped;
	uintptr_t current_addr = (uintptr_t)addr;
	uintptr_t current_dest = (uintptr_t)dest;

	if (!addr || !dest)
		return -EINVAL;

	if (!__range_ok((void __user *),(void __user *)current_dest, size))
		return -EACCES;

	while (size > 0)
	{
		max = min(PAGE_SIZE - (current_addr & (PAGE_SIZE - 1)), size);

		ret = pid_vaddr_to_phy(pid, (void __user *)current_addr, &phy_addr);
		if (ret)
			break;

		if (!pfn_valid(__phys_to_pfn(phy_addr)))
		{
			ret = -EFAULT;
			break;
		}

		if (!IS_VALID_PHYS_ADDR_RANGE(phy_addr, max))
		{
			ret = -EFAULT;
			break;
		}
		
//        logk("paddr = 0x%llx buffer = 0x%llx size = %d", phy_addr, current_dest, size);
	
        
		//mapped = __va(phy_addr);
		mapped = (void*)phys_to_vaddr(phy_addr);
//		logk("mapped = 0x%llx", mapped);
		if (!mapped)
		{
			ret = -ENOMEM;
			break;
		}
        
        
		if (copy_to_user((void __user *)current_dest, mapped, max))
		{
            
        flush_to_page(mapped, max);
			ret = -EACCES;
			break;
		}
		
        flush_to_page(mapped, max);

		current_addr += max;
		current_dest += max;
		size -= max;
		processed += max;
	}

	return ret ? ret : processed;
}
*/

static inline u32 read_nocache_u32_aligned(const volatile u32 *addr) {
    smp_rmb();
    return *addr;
}

static inline u64 read_nocache_u64_aligned(const volatile u64 *addr) {
    smp_rmb();
    return *addr;
}

typedef volatile u64 __aligned(8) *aligned_u64_ptr;
typedef volatile u32 __aligned(4) *aligned_u32_ptr;

__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub"))))
int read_process_memory(pid_t pid, void __user *addr, void __user *dest, size_t size) {
    phys_addr_t phy_addr;
    int ret = 0;
    size_t processed = 0;
    void *mapped = NULL;
    uintptr_t current_addr = (uintptr_t)addr;
    uintptr_t current_dest = (uintptr_t)dest;
    size_t chunk_size;
    
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    if (!addr || !dest || !access_ok((void __user *)current_dest, size) || size == 0)
    #else
     if (!addr || !dest || !__range_ok((void __user *)current_dest, size) || size == 0)
    #endif
        return -EINVAL;

    while (size > 0) {
        size_t page_offset = current_addr & (PAGE_SIZE - 1);
        chunk_size = min(size, PAGE_SIZE - page_offset);
        const u8 *src_base = NULL;
        u8 __user *dst_base = (u8 __user *)current_dest;

        ret = pid_vaddr_to_phy(pid, (void __user *)current_addr, &phy_addr);
        if (ret)
            goto out;

        phys_addr_t page_phys = phy_addr & PAGE_MASK;
        if (!pfn_valid(__phys_to_pfn(page_phys)) || 
            !IS_VALID_PHYS_ADDR_RANGE(page_phys, PAGE_SIZE)) {
            ret = -EFAULT;
            goto out;
        }

        mapped = (void*)phys_to_vaddr(page_phys);
        if (!mapped) {
            ret = -ENOMEM;
            goto out;
        }
        src_base = (const u8 *)mapped + page_offset;

        size_t remaining = chunk_size;
        const u8 *src = src_base;
        u8 __user *dst = dst_base;

//	    flush_to_page(mapped, size);

        size_t head = (uintptr_t)src % 8;
        size_t handle_head = min(head, remaining);
        if (handle_head > 0) {
            size_t i ;
            for (i = 0; i < handle_head; i++) {
                u8 val = *(volatile u8 *)&src[i];
                if (put_user(val, &dst[i])) {
                    ret = -EACCES;
                    goto out;
                }
            }
            src += handle_head;
            dst += handle_head;
            remaining -= handle_head;
        }

        size_t batch64 = 0;
        if (remaining >= 8) {
            if ((uintptr_t)src % 8 == 0) {
                batch64 = remaining / 8;
            } else {
                batch64 = 0;
            }
        }
        if (batch64 > 0) {
            aligned_u64_ptr src64 = (aligned_u64_ptr)src;
            size_t i ;
            for (i = 0; i < batch64; i++) {
                u64 val = read_nocache_u64_aligned(&src64[i]);
                if (copy_to_user(&dst[i * 8], &val, 8)) {
                    ret = -EACCES;
                    goto out;
                }
            }
            src += batch64 * 8;
            dst += batch64 * 8;
            remaining -= batch64 * 8;
        }

        size_t batch32 = 0;
        if (remaining >= 4) {
            if ((uintptr_t)src % 4 == 0) {
                batch32 = remaining / 4;
            } else {
                batch32 = 0;
            }
        }
        if (batch32 > 0) {
            aligned_u32_ptr src32 = (aligned_u32_ptr)src;
            size_t i ;
            for (i = 0; i < batch32; i++) {
                u32 val = read_nocache_u32_aligned(&src32[i]);
                if (copy_to_user(&dst[i * 4], &val, 4)) {
                    ret = -EACCES;
                    goto out;
                }
            }
            src += batch32 * 4;
            dst += batch32 * 4;
            remaining -= batch32 * 4;
        }

        if (remaining > 0) {
            size_t i ;
            for (i = 0; i < remaining; i++) {
                u8 val = *(volatile u8 *)&src[i];
                if (put_user(val, &dst[i])) {
                    ret = -EACCES;
                    goto out;
                }
            }
        }
        
	    flush_to_page(mapped, size);

        current_addr += chunk_size;
        current_dest += chunk_size;
        size -= chunk_size;
        processed += chunk_size;
    }

out:
    smp_mb();
    return ret ? ret : processed;
}




#endif // __MEMORY_H
