
//code form https://github.com/tiann/KernelSU

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#ifndef __HOOK_H
#define __HOOK_H
#include "utils.h"

static struct security_hook_heads *security_hook_heads_ptr;

static int override_security_head(void *head, const void *new_head, size_t len)
{
    void *addr;
    struct page *page;
	unsigned long base = (unsigned long)head & PAGE_MASK;
	unsigned long offset = offset_in_page(head);

	// this is impossible for our case because the page alignment
	// but be careful for other cases!
	BUG_ON(offset + len > PAGE_SIZE);
	page = phys_to_page(__pa(base));
	if (!page) {
		return -EFAULT;
	}
	
	addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!addr) {
		return -ENOMEM;
	}
	local_irq_disable();
	memcpy(addr + offset, new_head, len);
	local_irq_enable();
	vunmap(addr);
	return 0;
}

static void free_security_hook_list(struct hlist_head *head)
{
	struct hlist_node *temp;
	struct security_hook_list *entry;

	if (!head)
		return;

	hlist_for_each_entry_safe (entry, temp, head, list) {
		hlist_del(&entry->list);
		kfree(entry);
	}

	kfree(head);
}

struct hlist_head *copy_security_hlist(struct hlist_head *orig)
{
	struct security_hook_list *entry;
	struct security_hook_list *new_entry;
	struct hlist_head *new_head = kmalloc(sizeof(*new_head), GFP_KERNEL);
	if (!new_head)
		return NULL;

	INIT_HLIST_HEAD(new_head);

	hlist_for_each_entry (entry, orig, list) {
		new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry) {
			free_security_hook_list(new_head);
			return NULL;
		}

		*new_entry = *entry;

		hlist_add_tail_rcu(&new_entry->list, new_head);
	}

	return new_head;
}

#define LSM_SEARCH_MAX 180 // This should be enough to iterate

__attribute__((no_sanitize("cfi")))
static void *find_head_addr(void *security_ptr, int *index)
{
    struct hlist_head *head_start;
    
    if(security_hook_heads_ptr==NULL)
    {
    security_hook_heads_ptr = (typeof(security_hook_heads_ptr))kallsyms_lookup_name_ptr("security_hook_heads");
    if (!security_hook_heads_ptr) {
        logk("Failed to find security_hook_heads!\n");
        return NULL;
       }
    }
    
	if (!security_ptr) {
		return NULL;
	}
	head_start = (struct hlist_head *)security_hook_heads_ptr;
	
	int i;
	for (i = 0; i < LSM_SEARCH_MAX; i++) {
		struct hlist_head *head = head_start + i;
		struct security_hook_list *pos;
		hlist_for_each_entry (pos, head, list) {
			if (pos->hook.capget == security_ptr) {
				if (index) {
					*index = i;
				}
				return head;
			}
		}
	}

	return NULL;
}


#define LSM_HOOK_HACK_INIT(head_ptr, name, func)                           \
	do {                                                                   \
	    struct hlist_head *new_head;                                    \
		static struct security_hook_list hook = {                      \
			.hook = { .name = func }                               \
		};                                                             \
		hook.head = head_ptr;                                          \
		hook.lsm = "Hack";                                              \
		new_head = copy_security_hlist(hook.head);  \
		if (!new_head) {                                               \
			logk("Failed to copy security list: %s\n", #name);   \
			break;                                                 \
		}                                                              \
		hlist_add_tail_rcu(&hook.list, new_head);                      \
		if (override_security_head(hook.head, new_head,                \
					   sizeof(*new_head))) {               \
			free_security_hook_list(new_head);                     \
			logk("Failed to hack lsm for: %s\n", #name);         \
		}                                                              \
	} while (0)

#endif // __HOOK_H