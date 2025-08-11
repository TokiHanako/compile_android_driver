
//code form https://github.com/fuqiuluo/ovo

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#ifndef __TOUCH_H_
#define __TOUCH_H_

#include <linux/input.h>

#include <linux/mutex.h>
#include <linux/input/mt.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/input-event-codes.h>

#include "inlinehook.h"
#include "utils.h"

/* input_event */
static uint8_t obstr_ee16[] = {0x10,0xb6,0x08,0xf1,0x79,0xbc,0xaa,0x0e,0x59,0xe8,0x20,0xd2,0xfa,0x3f,0x7c,0x20,0x41};
#define O_input_event ObstrDec(obstr_ee16)

/* input_handle_event */
static uint8_t obstr_e401[] = {0x18,0xeb,0x6e,0xe0,0xcf,0x45,0xd2,0x9a,0x84,0xea,0x2a,0xc7,0xc9,0xb1,0x59,0x4a,0x9e,0xd5,0x0b,0xf9,0xf0,0xd8,0x84,0xea,0xc3};
#define O_input_handle_event ObstrDec(obstr_e401)

/* input_inject_event */
static uint8_t obstr_b592[] = {0x18,0x26,0xf6,0x77,0x3d,0x15,0xdb,0xf6,0x56,0xaf,0x71,0xa7,0x5b,0x76,0x36,0x9b,0x1d,0xd5,0x0b,0xf9,0xf0,0xd8,0x84,0xea,0xc3};
#define O_input_inject_event ObstrDec(obstr_b592)

struct touch_event_base {
	int slot;
	int x;
	int y;
	int pressure;
};

struct touch_event {
	unsigned int type;
	unsigned int code;
	int value;
};

#define MAX_EVENTS 1024
#define RING_MASK (MAX_EVENTS - 1)

struct event_pool {
	struct touch_event events[MAX_EVENTS];
	unsigned long size;
	spinlock_t event_lock;
};

void (*input_event_ptr)(struct input_dev *dev, unsigned int type, unsigned int code, int value) = NULL;
void (*input_update_event_ptr)(struct input_handle *handle, unsigned int type, unsigned int code, int value) = NULL;

void (*backup_input_event)(struct input_dev *dev, unsigned int type, unsigned int code, int value) = NULL;
void (*backup_input_update_event)(struct input_handle *handle, unsigned int type, unsigned int code, int value) = NULL;

static inline int is_event_supported(unsigned int code, unsigned long *bm, unsigned int max)
{
	return code <= max && test_bit(code, bm);
}
// "input_event"
#define OBF_STR_INPUT_EVENT OBF_STR(0x2724c968846c2057ULL, 0x1a, 0x2e, 0x47, 0x5a, 0x55, 0x93, 0x82, 0xe4, 0x27, 0x3e, 0x0c)

// "input_inject_event"
#define OBF_STR_INPUT_INJECT_EVENT OBF_STR(0xd5ba52424b94f09aULL, 0x1a, 0x2e, 0x47, 0x5a, 0x55, 0x97, 0x8a, 0xe0, 0x3d, 0x2a, 0x5d, 0x2a, 0x2b, 0x18, 0x43, 0x05, 0x6e, 0x22, 0x0c)
int get_last_driver_slot(struct input_dev* dev) {
	int slot;
	int new_slot;
	struct input_mt *mt;
	int is_new_slot;

	if(!dev) {
		logk("wtf? dev is null\n");
		return -114;
	}

	is_new_slot = 0;
	mt = dev->mt;
	if (mt)
		new_slot = mt->slot;
	else
		new_slot = -999;

	if (dev->absinfo != NULL)
		slot = dev->absinfo[ABS_MT_SLOT].value;
	else
		slot = -999;

	if(new_slot == -999 && slot == -999) {
		return -114;
	}

	if(slot == -999) {
		return new_slot;
	}

	if(new_slot == -999) {
		return slot;
	}

	is_new_slot = new_slot != slot;
	return is_new_slot ? new_slot : slot;
}

static void (*input_handle_event_ptr)(struct input_dev *dev, unsigned int type, unsigned int code, int value) = NULL;

__attribute__((no_sanitize("cfi")))
int input_event_no_lock(struct input_dev *dev, unsigned int type, unsigned int code, int value)
{
	if (is_event_supported(type, dev->evbit, EV_MAX)) {
		input_handle_event_ptr(dev, type, code, value);
	}
	return 0;
}

__attribute__((no_sanitize("cfi")))
struct input_dev* find_touch_device(void) {
	static struct input_dev* CACHE = NULL;

	if (CACHE != NULL) {
		return CACHE;
	}

	struct input_dev *dev;
	struct list_head *input_dev_list;
	struct mutex *input_mutex;

	input_dev_list = (struct list_head *)kallsyms_lookup_name_ptr("input_dev_list");
	input_mutex = (struct mutex *)kallsyms_lookup_name_ptr("input_mutex");
	if (!input_dev_list || !input_mutex) {
		printk(KERN_ERR "Failed to find symbols!\n");
		return NULL;
	}
	// /*
	// * input_mutex protects access to both input_dev_list and input_handler_list.
	// * This also causes input_[un]register_device and input_[un]register_handler
	// * be mutually exclusive which simplifies locking in drivers implementing
	// * input handlers.
	// */
	//static DEFINE_MUTEX(input_mutex);
	mutex_lock(input_mutex);

	list_for_each_entry(dev, input_dev_list, node) {
		if (test_bit(EV_ABS, dev->evbit) &&
			(test_bit(ABS_MT_POSITION_X, dev->absbit) || test_bit(ABS_X, dev->absbit))) {\
            logk("Name: %s, Bus: %d Vendor: %d Product: %d Version: %d\n", dev->name, dev->id.bustype, dev->id.vendor, dev->id.product, dev->id.version);
			mutex_unlock(input_mutex);
			CACHE = dev;
			return dev;
		}
	}

	mutex_unlock(input_mutex);
	return NULL;
}

static struct event_pool *pool = NULL;

static __always_inline struct event_pool * get_event_pool(void) {
	return pool;
}

int input_event_cache(unsigned int type, unsigned int code, int value, int lock) {
	unsigned long flags;
	if (lock)
		spin_lock_irqsave(&pool->event_lock, flags);
	if (pool->size >= MAX_EVENTS) {
		if (lock)
			spin_unlock_irqrestore(&pool->event_lock, flags);
		return -EFAULT;
	}
	struct touch_event* event = &pool->events[pool->size++];
	event->type = type;
	event->code = code;
	event->value = value;
	if (lock)
		spin_unlock_irqrestore(&pool->event_lock, flags);

	return 0;
}

int input_mt_report_slot_state_cache(unsigned int tool_type, bool active, int lock)
{
	if (!active) {
		input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
		return 0;
	}

	struct input_dev* dev = find_touch_device();
	struct input_mt *mt = dev->mt;
	struct input_mt_slot *slot;
	int id;

	if (!mt)
		return -1;

	if (mt->slot < 0 || mt->slot > mt->num_slots) {
		return -1;
	}
	slot = &mt->slots[mt->slot];

	id = input_mt_get_value(slot, ABS_MT_TRACKING_ID);
	if (id < 0)
		id = input_mt_new_trkid(mt);

	input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
	input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);

	return id;
}

bool input_mt_report_slot_state_with_id_cache(unsigned int tool_type, bool active, int id, int lock)
{
	if (!active) {
		input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
		return false;
	}

	input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
	input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);

	return true;
}

static void handle_cache_events(struct input_dev* dev) {
	struct input_mt *mt = dev->mt;
	struct input_mt_slot *slot;
	unsigned long flags, flags2;
	int id;
    int i;
	if (!mt)
		return;

	if (mt->slot < 0 || mt->slot > mt->num_slots) {
		return;
	}
	slot = &mt->slots[mt->slot];

	spin_lock_irqsave(&pool->event_lock, flags2);
	if (pool->size == 0) {
		spin_unlock_irqrestore(&pool->event_lock, flags2);
		return;
	}
	spin_lock_irqsave(&dev->event_lock, flags);

	for (i = 0; i < pool->size; ++i) {
		struct touch_event event = pool->events[i];

		if (event.type == EV_ABS &&
			event.code == ABS_MT_TRACKING_ID &&
			event.value == -114514) {
			id = input_mt_get_value(slot, ABS_MT_TRACKING_ID);
			if (id < 0)
				id = input_mt_new_trkid(mt);
			event.value = id;
		}

		input_event_no_lock(dev, event.type, event.code, event.value);
	}
	spin_unlock_irqrestore(&dev->event_lock, flags);
	pool->size = 0;
	spin_unlock_irqrestore(&pool->event_lock, flags2);
}

__attribute__((no_sanitize("cfi"))) __attribute__((__annotate__(("nosub nofco strenc nobcf fla nosub"))))
static void custom_input_handle_event_handler(struct input_dev * dev,unsigned int type, unsigned int code, int value)
{
	//logk("input_event(%u, %u, %d)", type, code, value);
	if(!dev) {
		backup_input_event(dev, type, code, value);
		return ;
	}

/*
	if (type == EV_ABS) {
		logk("input_event(%u, %u, %d)", type, code, value);
	}
*/

	if (type != EV_SYN) {
		backup_input_event(dev, type, code, value);
		return ;
	}

	handle_cache_events(dev);
	backup_input_event(dev, type, code, value);
		return ;
}

__attribute__((no_sanitize("cfi"))) __attribute__((__annotate__(("nosub nofco strenc nobcf fla nosub"))))
static void my_input_handle_event_handler(struct input_handle * handle,unsigned int type, unsigned int code, int value)
{
	if(!handle) {
		backup_input_update_event(handle, type, code, value);
		return ;
	}

/*
	if (type == EV_ABS) {
		logk("input_event(%u, %u, %d)", type, code, value);
	}

*/
	if (type != EV_SYN) {
		backup_input_update_event(handle, type, code, value);
		return ;
	}

	handle_cache_events(handle->dev);
	backup_input_update_event(handle, type, code, value);
		return ;
}



__attribute__((no_sanitize("cfi"))) static __always_inline 
int input_init(void) 
{
    hook_err_t err1;
    hook_err_t err2;
	if(input_event_ptr == NULL || input_update_event_ptr == NULL) {
    input_event_ptr = (typeof(input_event_ptr))kallsyms_lookup_name_ptr(O_input_event);//input_event
    input_update_event_ptr = (typeof(input_update_event_ptr))kallsyms_lookup_name_ptr(O_input_inject_event);//input_inject_event
	}

	if (!input_event_ptr && !input_update_event_ptr) {
		logk("failed to find input_event\n");
		return -1;
	}
	
    err1 = hook((void *)input_event_ptr, custom_input_handle_event_handler, (void**)&backup_input_event);
	logk("hook input_event: %d\n", err1);
	
	err2 = hook((void *)input_update_event_ptr, my_input_handle_event_handler, (void**)&backup_input_update_event);
	logk("hook input_update_event: %d\n", err2);
	
	if(input_handle_event_ptr == NULL) {
		input_handle_event_ptr = (typeof(input_handle_event_ptr))kallsyms_lookup_name_ptr(O_input_handle_event);
	}

	if (!input_handle_event_ptr) {
		logk("failed to find input_handle_event\n");
		return -1;
	}

	pool = kvmalloc(sizeof(struct event_pool), GFP_KERNEL);
	if (!pool) {
        unhook(input_event_ptr);
	    unhook(input_update_event_ptr);
		return -ENOMEM;
	}
	pool->size = 0;
	spin_lock_init(&pool->event_lock);

	return 1;
}

static __always_inline 
void input_exit(void) 
{
    unhook(input_event_ptr);
	unhook(input_update_event_ptr);
	if (pool)
		kfree(pool);
}
#endif //__TOUCH_H_
