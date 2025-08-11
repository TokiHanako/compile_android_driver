
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#include "obstr.h"
#include "mem.h"
#include "utils.h"
#include "lsmhook.h"
#include "hide_pid.h"
#include "touch.h"
#include "dec.h"
#include "syscall.h"
#include "hwbp_hook.h"
#include "trick.h"

#define READ_MEM          _IOW('O', 1, REQUEST)
#define GET_PID             _IOW('O', 2, REQUEST)
#define MODULE_BASE      _IOW('O', 3, REQUEST)

#define HIDE_PID_ADD          _IOW('O', 4, int)
#define HIDE_PID_DEL           _IOW('O', 5, int)

#define TOUCH_CLICK_DOWN          _IOW('T', 1, struct touch_event_base)
#define TOUCH_CLICK_UP              _IOW('T', 2, struct touch_event_base)
#define TOUCH_MOVE                 _IOW('T', 3, struct touch_event_base)

#define ADD_MOUNT_KEYWORD       _IOW('G', 1, char[64])
#define DEL_MOUNT_KEYWORD       _IOW('G', 2, char[64])
#define ADD_MAPS_KEYWORD        _IOW('G', 3, char[64])
#define DEL_MAPS_KEYWORD        _IOW('G', 4, char[64])
#define ADD_FILE_KEYWORD         _IOW('G', 5, char[256])
#define DEL_FILE_KEYWORD         _IOW('G', 6, char[256])
#define SET_ACTIVE                  _IOW('G', 7, int)
#define GET_STATUS                 _IOR('G', 8, int[4])

#define INSTALL_HOOK                   _IOW('H', 1, REQUEST)
#define REMOVE_HOOK                   _IOW('H', 2, unsigned long)

/* TwT */
static uint8_t obstr_27e4[] = {0x08,0x0e,0xf9,0x0e,0x3f,0x8f,0x87,0x89,0xfd};
#define O_TwT ObstrDec(obstr_27e4)

/* 栗栗猫QwQ */
static uint8_t obstr_32f6[] = {0x10,0x9c,0xdc,0xf9,0x4d,0x5d,0x08,0x04,0x1e,0xa9,0x19,0x09,0x3a,0xe9,0xca,0x12,0xfb};
#define O_QwQ ObstrDec(obstr_32f6)

/* 0x114514 */
static uint8_t obstr_91dd[] = {0x08,0xc8,0x47,0x53,0x06,0x10,0x49,0xe2,0x6e};
#define O_0x114514 ObstrDec(obstr_91dd)
 

static int (*cap_task_prctl_ptr)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) = NULL;
__attribute__((__annotate__(("nosub nofco strenc nobcf nofla nosub")))) __attribute__((no_sanitize("cfi")))
static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    REQUEST req;
	char name[0x100];
	//memset(name, 0, 0x100);

	switch (cmd)
	{

	case READ_MEM:
	{
		if (copy_from_user((char *)&req, (void __user *)arg, sizeof(req)) != 0)
		{
			return -1;
		}

		if (read_process_memory(req.pid, (void __user *)req.addr, req.buffer, req.size) < 0)
		{
			return -1;
		}
	}
	break;

	case GET_PID:
	{
		if (copy_from_user((char *)&req, (void __user *)arg, sizeof(req)) != 0 || copy_from_user(name, (void __user *)req.buffer, sizeof(name) - 1) != 0)
		{
			return -1;
		}
		//logk("proc_name=%s\n",name);
		req.pid = get_process_pid(name);
		//logk("pid=%d\n",req.pid);
		if (copy_to_user((void __user *)arg, &req, sizeof(req)) != 0)
		{
			return -1;
		}
	}
	break;

	case MODULE_BASE:
	{
		if (copy_from_user((char *)&req, (void __user *)arg, sizeof(req)) != 0 || copy_from_user(name, (void __user *)req.buffer, sizeof(name) - 1) != 0)
		{
			return -1;
		}
		//logk("module_name=%s",name);
		req.addr = get_module_base(req.pid, name);
		if (copy_to_user((void __user *)arg, &req, sizeof(req)) != 0)
		{
			return -1;
		}
	}
	break;

	case HIDE_PID_ADD:
	{
		hide_process((pid_t)arg);
	}
	break;

	case HIDE_PID_DEL:
	{
		restore_process((pid_t)arg);
	}
	break;

	case TOUCH_CLICK_DOWN:
	{
		struct event_pool *pool;
		unsigned long flags;

		pool = get_event_pool();
		if (pool == NULL)
		{
			return -ECOMM;
		}

		struct touch_event_base __user *event_user = (struct touch_event_base __user *)arg;
		struct touch_event_base event;

		if (!event_user)
		{
			return -EBADR;
		}

		if (copy_from_user(&event, event_user, sizeof(struct touch_event_base)))
		{
			return -EACCES;
		}
		spin_lock_irqsave(&pool->event_lock, flags);

		if (pool->size >= MAX_EVENTS)
		{
			logk("event pool is full!\n");
			pool->size = 0;
		}

		input_event_cache(EV_ABS, ABS_MT_SLOT, event.slot, 0);
		int id = input_mt_report_slot_state_with_id_cache(MT_TOOL_FINGER, 1, event.slot, 0);
		input_event_cache(EV_ABS, ABS_MT_POSITION_X, event.x, 0);
		input_event_cache(EV_ABS, ABS_MT_POSITION_Y, event.y, 0);
		input_event_cache(EV_ABS, ABS_MT_PRESSURE, event.pressure, 0);
		input_event_cache(EV_ABS, ABS_MT_TOUCH_MAJOR, event.pressure, 0);
		input_event_cache(EV_ABS, ABS_MT_TOUCH_MINOR, event.pressure, 0);

		event.pressure = id;
		spin_unlock_irqrestore(&pool->event_lock, flags);
		
		if (copy_to_user(event_user, &event, sizeof(struct touch_event_base)))
		{
			logk("copy_to_user failed: %s\n", __func__);
			return -EACCES;
		}
	}
	break;

	case TOUCH_CLICK_UP:
	{
		struct event_pool *pool;
		unsigned long flags;

		pool = get_event_pool();
		if (pool == NULL)
		{
			return -ECOMM;
		}

		struct touch_event_base __user *event_user = (struct touch_event_base __user *)arg;
		struct touch_event_base event;

		if (!event_user)
		{
			return -EBADR;
		}

		if (copy_from_user(&event, event_user, sizeof(struct touch_event_base)))
		{
			return -EACCES;
		}
		spin_lock_irqsave(&pool->event_lock, flags);

		if (pool->size >= MAX_EVENTS)
		{
			logk("event pool is full!\n");
			pool->size = 0;
		}

		input_event_cache(EV_ABS, ABS_MT_SLOT, event.slot, 0);
		input_mt_report_slot_state_cache(MT_TOOL_FINGER, 0, 0);

		spin_unlock_irqrestore(&pool->event_lock, flags);
	}
	break;

	case TOUCH_MOVE:
	{
		struct event_pool *pool;
		unsigned long flags;

		pool = get_event_pool();
		if (pool == NULL)
		{
			return -ECOMM;
		}

		struct touch_event_base __user *event_user = (struct touch_event_base __user *)arg;
		struct touch_event_base event;

		if (!event_user)
		{
			return -EBADR;
		}

		if (copy_from_user(&event, event_user, sizeof(struct touch_event_base)))
		{
			return -EACCES;
		}
		spin_lock_irqsave(&pool->event_lock, flags);

		if (pool->size >= MAX_EVENTS)
		{
			logk("event pool is full!\n");
			pool->size = 0;
		}

		input_event_cache(EV_ABS, ABS_MT_SLOT, event.slot, 0);
		input_event_cache(EV_ABS, ABS_MT_POSITION_X, event.x, 0);
		input_event_cache(EV_ABS, ABS_MT_POSITION_Y, event.y, 0);
		input_event_cache(EV_SYN, SYN_MT_REPORT, 0, 0);

		spin_unlock_irqrestore(&pool->event_lock, flags);
	}
	break;
	
	
    case ADD_MOUNT_KEYWORD:
    case ADD_MAPS_KEYWORD:
    case ADD_FILE_KEYWORD:
    {
        int mode = MODE_HIDE;
        char keyword[MAX_FILE_KEYWORD_LEN] = {0};
        if (copy_from_user(keyword, (void __user *)arg, sizeof(keyword) - 1)) {
            return -EFAULT;
        }
        keyword[sizeof(keyword) - 1] = '\0';
        
        char *mode_ptr = strchr(keyword, ':');
        if (mode_ptr) {
            *mode_ptr = '\0';
            mode = simple_strtoul(mode_ptr + 1, NULL, 10);
            if (mode < MODE_HIDE || mode > MODE_MASK) {
                mode = MODE_HIDE;
            }
        }
        
        mutex_lock(&filter_lock);
        if (cmd == ADD_MOUNT_KEYWORD) {
            add_mount_keyword(keyword, mode);
        } else if (cmd == ADD_MAPS_KEYWORD) {
            add_maps_keyword(keyword, mode);
        } else {
            add_file_keyword(keyword, mode);
        }
        mutex_unlock(&filter_lock);
    }
    break;
        
    case DEL_MOUNT_KEYWORD:
    case DEL_MAPS_KEYWORD:
    case DEL_FILE_KEYWORD:
    {
        char keyword[MAX_FILE_KEYWORD_LEN] = {0};
        if (copy_from_user(keyword, (void __user *)arg, sizeof(keyword) - 1)) {
            return -EFAULT;
            break;
        }
        keyword[sizeof(keyword) - 1] = '\0';
        
        mutex_lock(&filter_lock);
        if (cmd == DEL_MOUNT_KEYWORD) {
            del_mount_keyword(keyword);
        } else if (cmd == DEL_MAPS_KEYWORD) {
            del_maps_keyword(keyword);
        } else {
            del_file_keyword(keyword);
        }
        mutex_unlock(&filter_lock);
    }
    break;
        
    case SET_ACTIVE:
    {
        int mode = MODE_HIDE;
        if (copy_from_user(&mode, (void __user *)arg, sizeof(int))) {
            return -EFAULT;
        } else {
            filter_manager.active = (mode != 0);
            logk("set active state: %d\n", filter_manager.active);
        }
    }
    break;
        
    case GET_STATUS: 
    {
        int status[4] = {
            filter_manager.mount_count,
            filter_manager.maps_count,
            filter_manager.file_count,
            filter_manager.active
        };
        if (copy_to_user((void __user *)arg, status, sizeof(status))) {
            return -EFAULT;
        }
    }
    break;
    
    case INSTALL_HOOK: 
    {
        if (copy_from_user((char *)&req, (void __user *)arg, sizeof(req)) != 0)
		{
			return -1;
		}

		if (install_hwbp_hook(req.pid, req.addr, (unsigned long)req.buffer) < 0)
		{
			return -1;
		}
    }
    break;
        
    case REMOVE_HOOK: 
    {
        unsigned long addr;
        if (copy_from_user((char *)&addr, (void __user *)arg, sizeof(addr)) != 0)
		{
			return -1;
		}
       return remove_hwbp_hook(addr);
    }
    break;
    
	default:
	{
		logk("No Found about cmd %lx", cmd);
		break;
	}
	}

	return 0;
}

static struct file_operations my_fops = {
	.owner = THIS_MODULE,
	// .open = my_open,
	// .read = my_read,
	// .write = my_write,
	.unlocked_ioctl = my_ioctl,
	.compat_ioctl = my_ioctl,
	// .release = my_close,
	// .mmap = my_mmap,
};

__attribute__((__annotate__(("nosub nofco strenc nobcf fla nosub"))))
__attribute__((no_sanitize("cfi"))) static int my_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	char name[0x100];
	//logk("option=%d",option);
	if ((uint32_t)option == (uint32_t)hexStringToInt(O_0x114514))
	{
		if (copy_from_user(name, (void __user *)arg2, sizeof(name) - 1) != 0)
		{
			return cap_task_prctl_ptr(option, arg2, arg3, arg4, arg5);
		}
//		logk("name=%s",name);
	
		if (strncmp(O_TwT, name, 3) == 0)//TwT
        {
            anon_inode_getfd(O_QwQ, &my_fops, 0, O_RDWR | O_CLOEXEC);//栗栗猫QwQ
            //logk("创建成功!\n");
        }
	}
	return cap_task_prctl_ptr(option, arg2, arg3, arg4, arg5);
}

__attribute__((no_sanitize("cfi"))) static int hook_prctl(void)
{
	void *prctl_head;
	size_t task_prctl_offset;

	task_prctl_offset = offsetof(struct security_hook_heads, task_prctl);

	cap_task_prctl_ptr = (typeof(cap_task_prctl_ptr))kallsyms_lookup_name_ptr("cap_task_prctl.cfi_jt");
	prctl_head = find_head_addr(cap_task_prctl_ptr, NULL);
	if (!prctl_head)
	{
		cap_task_prctl_ptr = (typeof(cap_task_prctl_ptr))kallsyms_lookup_name_ptr("cap_task_prctl");
		prctl_head = find_head_addr(cap_task_prctl_ptr, NULL);
	}
	//logk("kallsyms_lookup_name cap_task_prctl=0x%llx find_head_addr prctl_head=0x%lx \n",cap_task_prctl_ptr,prctl_head);
	if (prctl_head)
	{
		if (prctl_head != (void *)(security_hook_heads_ptr + task_prctl_offset))
			logk("task_prctl's address has shifted!\n");
		LSM_HOOK_HACK_INIT(prctl_head, task_prctl, my_task_prctl);
	}
	else
	{
		logk("Failed to find task_prctl!\n");
		return -1;
	}
	smp_mb();
	return 1;
}

__attribute__((no_sanitize("cfi")))
static int __init hook_init(void)
{
    
    dcache_line_size = cache_line_size();
    if (!dcache_line_size) {
        u64 ctr_el0;
        asm volatile("mrs %0, ctr_el0" : "=r"(ctr_el0));
        unsigned int dminline = (ctr_el0 >> 16) & 0xF;
        dcache_line_size = 4 << dminline;
    }
    
    INIT_RADIX_TREE(&vmap_cache_tree, GFP_ATOMIC);
        
	if (kallsyms_lookup_name_ptr == NULL)
	{
		kallsyms_lookup_name_ptr = (typeof(kallsyms_lookup_name_ptr))my_kallsyms_lookup_name("kallsyms_lookup_name");
	}
    
#if !defined(ARCH_HAS_VALID_PHYS_ADDR_RANGE) || defined(MODULE)
	high_memory_ptr = (typeof(high_memory_ptr))kallsyms_lookup_name_ptr("high_memory");
#endif
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)&&LINUX_VERSION_CODE <KERNEL_VERSION(6, 0, 0)
    BypassCFI();
#endif

	hook_prctl();

	input_init();
	
//	dec_exit();
	
	trick_init();
	
	hide_module();
    
    hwbp_init();
    
	logk("module load successful");
	return 0;
}

static void __exit hook_exit(void)
{
	hide_exit();
	
	cleanup_cache();
	
	input_exit();
	
//	dec_exit();
    
    trick_exit();
    
    hwbp_exit();
    
	logk("module exit successful\n");
}

module_init(hook_init);
module_exit(hook_exit);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TG@TwT_driver");
MODULE_DESCRIPTION("栗栗猫TnT");
