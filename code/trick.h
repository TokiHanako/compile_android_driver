
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#ifndef __TRICK_H
#define __TRICK_H
#include <linux/printk.h>
//#include <syscall.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/random.h>
#include <asm/current.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/dirent.h>
#include <linux/fdtable.h>

#include "inlinehook.h"
#include "utils.h"

#define MAX_KEYWORD_LEN 64
#define MAX_FILE_KEYWORD_LEN 256
#define MAX_FILTERS 128

enum filter_mode {
    MODE_HIDE = 0,
    MODE_MASK = 1
};

struct hook_funcs {
    void *original;
    void *replacement;
    void **backup;
};

struct filter_keyword {
    char keyword[MAX_KEYWORD_LEN];
    size_t len;
    enum filter_mode mode;
};

struct file_path {
    char path[MAX_FILE_KEYWORD_LEN];
    size_t len;
    enum filter_mode mode;
};

struct {
    struct filter_keyword *mount_keywords;
    size_t mount_count;
    size_t mount_capacity;
    
    struct filter_keyword *maps_keywords;
    size_t maps_count;
    size_t maps_capacity;
    
    struct file_path *file_keywords;
    size_t file_count;
    size_t file_capacity;
    
    bool active;
} filter_manager = {
    .active = true
};

static DEFINE_MUTEX(filter_lock);

typedef int (*vfs_show_func_t)(struct seq_file *, struct vfsmount *);
typedef void (*map_show_func_t)(struct seq_file *, struct vm_area_struct *);
typedef int (*smap_show_func_t)(struct seq_file *, void *);
typedef int (*_filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned);

static vfs_show_func_t ori_show_vfsmnt, backup_show_vfsmnt;
static vfs_show_func_t ori_show_mountinfo, backup_show_mountinfo;
static vfs_show_func_t ori_show_vfsstat, backup_show_vfsstat;
static map_show_func_t ori_show_map_vma, backup_show_map_vma;
static smap_show_func_t ori_show_smap, backup_show_smap;
static _filldir_t ori_filldir, backup_filldir;
static _filldir_t ori_filldir64, backup_filldir64;


static hook_err_t hook_err = 0;

static const char RANDOM_CHARS[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static const size_t RANDOM_CHARS_LEN = sizeof(RANDOM_CHARS) - 1;

static char get_random_char(void) {
    return RANDOM_CHARS[get_random_u64() % RANDOM_CHARS_LEN];
}


__attribute__((no_sanitize("cfi")))  __always_inline 
static void replace_keyword(char *str, size_t len, const char *keyword, size_t kw_len, enum filter_mode mode) {
    char *pos;
    while ((pos = strnstr(str, keyword, len)) != NULL) {
        size_t offset = pos - str;
        
        if (mode == MODE_MASK) {
            size_t i;
            for (i = 0; i < kw_len && (offset + i < len); i++) {
                str[offset + i] = get_random_char();
            }
        }
        
        str += offset + kw_len;
        len -= offset + kw_len;
    }
}
/*
static bool contains_keyword(char *str, size_t len, struct filter_keyword *keywords, size_t count) {    
    size_t i;
    for (i = 0; i < count; i++) {
        if (strnstr(str, keywords[i].keyword, len)) {
            return true;
        }
    }
    return false;
}

static bool matches_file_path(const char *filename, struct file_path *files, size_t count) {    
    size_t i;
    for (i = 0; i < count; i++) {
        if (strstr(filename, files[i].path)) {
            return true;
        }
    }
    return false;
}
*/

__attribute__((no_sanitize("cfi")))  __always_inline 
static bool filter_output(struct seq_file *m, size_t old_count, struct filter_keyword *keywords, size_t count, bool do_replace) {
    if (m->count <= old_count) return false;
    if (!filter_manager.active) return false;

    char *buf_start = m->buf + old_count;
    size_t len = m->count - old_count;
    size_t i;
    for (i = 0; i < count; i++) {
        if (strnstr(buf_start, keywords[i].keyword, len)) {
            if (do_replace) {
                replace_keyword(buf_start, len, keywords[i].keyword, keywords[i].len, keywords[i].mode);
            } else {
                m->count = old_count;
            }
            return true;
        }
    }
    return false;
}

__attribute__((no_sanitize("cfi")))
static int rep_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt) {
    size_t old_count = m->count;
    int ret = backup_show_vfsmnt(m, mnt);
    if (ret == 0) {
        mutex_lock(&filter_lock);
        filter_output(m, old_count, filter_manager.mount_keywords, filter_manager.mount_count, false);
        mutex_unlock(&filter_lock);
    }
    return ret;
}

__attribute__((no_sanitize("cfi")))
static int rep_show_mountinfo(struct seq_file *m, struct vfsmount *mnt) {
    size_t old_count = m->count;
    int ret = backup_show_mountinfo(m, mnt);
    if (ret == 0) {
        mutex_lock(&filter_lock);
        filter_output(m, old_count, filter_manager.mount_keywords, filter_manager.mount_count, true);
        mutex_unlock(&filter_lock);
    }
    return ret;
}

__attribute__((no_sanitize("cfi")))
static int rep_show_vfsstat(struct seq_file *m, struct vfsmount *mnt) {
    size_t old_count = m->count;
    int ret = backup_show_vfsstat(m, mnt);
    if (ret == 0) {
        mutex_lock(&filter_lock);
        filter_output(m, old_count, filter_manager.mount_keywords, filter_manager.mount_count, false);
        mutex_unlock(&filter_lock);
    }
    return ret;
}

__attribute__((no_sanitize("cfi")))
static void rep_show_map_vma(struct seq_file *m, struct vm_area_struct *vma) {
    size_t old_count = m->count;
    backup_show_map_vma(m, vma);
    mutex_lock(&filter_lock);
    filter_output(m, old_count, filter_manager.maps_keywords, filter_manager.maps_count, false);
    mutex_unlock(&filter_lock);
}

__attribute__((no_sanitize("cfi")))
static int rep_show_smap(struct seq_file *m, void *v) {
    size_t old_count = m->count;
    int ret = backup_show_smap(m, v);
    if (ret == 0) {
        mutex_lock(&filter_lock);
        filter_output(m, old_count, filter_manager.maps_keywords, filter_manager.maps_count, false);
        mutex_unlock(&filter_lock);
    }
    return ret;
}

__attribute__((no_sanitize("cfi")))
static int rep_filldir(struct dir_context *ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type) {
    mutex_lock(&filter_lock);
    
    bool should_filter = false;
    enum filter_mode mode = MODE_HIDE;
        size_t i;
    for (i = 0; i < filter_manager.file_count; i++) {
        if (strstr(name, filter_manager.file_keywords[i].path)) {
            should_filter = true;
            mode = filter_manager.file_keywords[i].mode;
            break;
        }
    }
    
    mutex_unlock(&filter_lock);
    
    if (!should_filter || !filter_manager.active) {
        return backup_filldir(ctx, name, namelen, offset, ino, d_type);
    }
    
    switch (mode) {
    case MODE_HIDE:
        return 0;
        
    case MODE_MASK: {
        char masked_name[MAX_FILE_KEYWORD_LEN];
        strncpy(masked_name, name, namelen);
        masked_name[namelen] = '\0';
        
        int i;
        for (i = 0; i < namelen; i++) {
            masked_name[i] = get_random_char();
        }
        
        return backup_filldir(ctx, masked_name, namelen, offset, ino, d_type);
    }
    
    default:
        return backup_filldir(ctx, name, namelen, offset, ino, d_type);
    }
}

__attribute__((no_sanitize("cfi")))
static int rep_filldir64(struct dir_context *ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type) {
    mutex_lock(&filter_lock);
    
    bool should_filter = false;
    enum filter_mode mode = MODE_HIDE;
        size_t i;
    for (i = 0; i < filter_manager.file_count; i++) {
        if (strstr(name, filter_manager.file_keywords[i].path)) {
            should_filter = true;
            mode = filter_manager.file_keywords[i].mode;
            break;
        }
    }
    
    mutex_unlock(&filter_lock);
    
    if (!should_filter || !filter_manager.active) {
        return backup_filldir64(ctx, name, namelen, offset, ino, d_type);
    }
    
    switch (mode) {
    case MODE_HIDE:
        return 0;
        
    case MODE_MASK: {
        char masked_name[MAX_FILE_KEYWORD_LEN];
        strncpy(masked_name, name, namelen);
        masked_name[namelen] = '\0';
        
        int i;
        for (i = 0; i < namelen; i++) {
            masked_name[i] = get_random_char();
        }
        
        return backup_filldir64(ctx, masked_name, namelen, offset, ino, d_type);
    }
    
    default:
        return backup_filldir64(ctx, name, namelen, offset, ino, d_type);
    }
}
__attribute__((no_sanitize("cfi")))   __always_inline 
static bool hook_all(void) {
    struct hook_funcs hooks[] = {
        { ori_show_vfsmnt, rep_show_vfsmnt, (void **)&backup_show_vfsmnt },
        { ori_show_mountinfo, rep_show_mountinfo, (void **)&backup_show_mountinfo },
        { ori_show_vfsstat, rep_show_vfsstat, (void **)&backup_show_vfsstat },
        { ori_show_map_vma, rep_show_map_vma, (void **)&backup_show_map_vma },
        { ori_show_smap, rep_show_smap, (void **)&backup_show_smap },
        { ori_filldir, rep_filldir, (void **)&backup_filldir },
        { ori_filldir64, rep_filldir64, (void **)&backup_filldir64 }
    };
    size_t i;
    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        if (!hooks[i].original) {
            logk("missing symbol for hook %zu\n", i);
            continue;
        }
        hook_err = hook(hooks[i].original, hooks[i].replacement, hooks[i].backup);
//        logk("hook item %d: %d\n", i, hook_err);
    }
    
    return hook_err == HOOK_NO_ERR;
}

static inline bool install_hook(void) {
    if (hook_all()) {
        logk("hook installed...\n");
        return true;
    }
    logk("hook installation failed...\n");
    return false;
}

__attribute__((no_sanitize("cfi")))
static inline bool uninstall_hook(void) {
    unhook(ori_show_vfsmnt);
    unhook(ori_show_mountinfo);
    unhook(ori_show_vfsstat);
    unhook(ori_show_map_vma);
    unhook(ori_show_smap);
    unhook(ori_filldir);
    unhook(ori_filldir64);
    logk("hook uninstalled...\n");
    return true;
}


__attribute__((no_sanitize("cfi")))   __always_inline 
static int add_mount_keyword(const char *kw, enum filter_mode mode) {
    size_t len = strlen(kw);
    if (len == 0 || len >= MAX_KEYWORD_LEN) return -EINVAL;
        size_t i;
    for (i = 0; i < filter_manager.mount_count; i++) {
        if (strcmp(filter_manager.mount_keywords[i].keyword, kw) == 0) {
            return -EEXIST;
        }
    }
    
    if (filter_manager.mount_count >= filter_manager.mount_capacity) {
        size_t new_capacity = (filter_manager.mount_capacity == 0) ? 8 : filter_manager.mount_capacity * 2;
        
        struct filter_keyword *new_keywords = krealloc(filter_manager.mount_keywords, new_capacity * sizeof(struct filter_keyword), GFP_KERNEL);
        if (!new_keywords) return -ENOMEM;
        
        filter_manager.mount_keywords = new_keywords;
        filter_manager.mount_capacity = new_capacity;
    }
    
    strncpy(filter_manager.mount_keywords[filter_manager.mount_count].keyword, kw, MAX_KEYWORD_LEN);
    filter_manager.mount_keywords[filter_manager.mount_count].keyword[MAX_KEYWORD_LEN-1] = '\0';
    filter_manager.mount_keywords[filter_manager.mount_count].len = len;
    filter_manager.mount_keywords[filter_manager.mount_count].mode = mode;
    filter_manager.mount_count++;
    
    return 0;
}

__attribute__((no_sanitize("cfi")))  __always_inline 
static int del_mount_keyword(const char *kw) {    
    size_t i;
    for (i = 0; i < filter_manager.mount_count; i++) {
        if (strcmp(filter_manager.mount_keywords[i].keyword, kw) == 0) {
            if (i < filter_manager.mount_count - 1) {
                memmove(&filter_manager.mount_keywords[i], &filter_manager.mount_keywords[i+1], (filter_manager.mount_count - i - 1) * sizeof(struct filter_keyword));
            }
            filter_manager.mount_count--;
            return 0;
        }
    }
    return -ENOENT;
}

__attribute__((no_sanitize("cfi"))) __always_inline 
static int add_maps_keyword(const char *kw, enum filter_mode mode) {
    size_t len = strlen(kw);
    if (len == 0 || len >= MAX_KEYWORD_LEN) return -EINVAL;
        size_t i;
    for (i = 0; i < filter_manager.maps_count; i++) {
        if (strcmp(filter_manager.maps_keywords[i].keyword, kw) == 0) {
            return -EEXIST;
        }
    }
    
    if (filter_manager.maps_count >= filter_manager.maps_capacity) {
        size_t new_capacity = (filter_manager.maps_capacity == 0) ? 8 : filter_manager.maps_capacity * 2;
        
        struct filter_keyword *new_keywords = krealloc(filter_manager.maps_keywords, new_capacity * sizeof(struct filter_keyword), GFP_KERNEL);
        if (!new_keywords) return -ENOMEM;
        
        filter_manager.maps_keywords = new_keywords;
        filter_manager.maps_capacity = new_capacity;
    }
    
    strncpy(filter_manager.maps_keywords[filter_manager.maps_count].keyword, kw, MAX_KEYWORD_LEN);
    filter_manager.maps_keywords[filter_manager.maps_count].keyword[MAX_KEYWORD_LEN-1] = '\0';
    filter_manager.maps_keywords[filter_manager.maps_count].len = len;
    filter_manager.maps_keywords[filter_manager.maps_count].mode = mode;
    filter_manager.maps_count++;
    
    return 0;
}

__attribute__((no_sanitize("cfi")))  __always_inline 
static int del_maps_keyword(const char *kw) {    
    size_t i;
    for (i = 0; i < filter_manager.maps_count; i++) {
        if (strcmp(filter_manager.maps_keywords[i].keyword, kw) == 0) {
            if (i < filter_manager.maps_count - 1) {
                memmove(&filter_manager.maps_keywords[i], &filter_manager.maps_keywords[i+1], (filter_manager.maps_count - i - 1) * sizeof(struct filter_keyword));
            }
            filter_manager.maps_count--;
            return 0;
        }
    }
    return -ENOENT;
}


__attribute__((no_sanitize("cfi")))  __always_inline 
static int add_file_keyword(const char *path, enum filter_mode mode) {
    size_t len = strlen(path);
    if (len == 0 || len >= MAX_FILE_KEYWORD_LEN) return -EINVAL;
        size_t i;
    for (i = 0; i < filter_manager.file_count; i++) {
        if (strcmp(filter_manager.file_keywords[i].path, path) == 0) {
            return -EEXIST;
        }
    }
    
    if (filter_manager.file_count >= filter_manager.file_capacity) {
        size_t new_capacity = (filter_manager.file_capacity == 0) ? 8 : filter_manager.file_capacity * 2;
        
        struct file_path *new_keywords = krealloc(filter_manager.file_keywords, new_capacity * sizeof(struct file_path), GFP_KERNEL);
        if (!new_keywords) return -ENOMEM;
        
        filter_manager.file_keywords = new_keywords;
        filter_manager.file_capacity = new_capacity;
    }
    
    strncpy(filter_manager.file_keywords[filter_manager.file_count].path, path, MAX_FILE_KEYWORD_LEN);
    filter_manager.file_keywords[filter_manager.file_count].path[MAX_FILE_KEYWORD_LEN-1] = '\0';
    filter_manager.file_keywords[filter_manager.file_count].len = len;
    filter_manager.file_keywords[filter_manager.file_count].mode = mode;
    filter_manager.file_count++;
    
    return 0;
}

__attribute__((no_sanitize("cfi"))) __always_inline 
static int del_file_keyword(const char *path) {    
    size_t i;
    for (i = 0; i < filter_manager.file_count; i++) {
        if (strcmp(filter_manager.file_keywords[i].path, path) == 0) {
            if (i < filter_manager.file_count - 1) {
                memmove(&filter_manager.file_keywords[i], &filter_manager.file_keywords[i+1], (filter_manager.file_count - i - 1) * sizeof(struct file_path));
            }
            filter_manager.file_count--;
            return 0;
        }
    }
    return -ENOENT;
}
    
__attribute__((no_sanitize("cfi"))) static __always_inline 
void trick_init(void) {
    mutex_init(&filter_lock);
    
    static const char *syms[] = {
        "show_vfsmnt", "show_mountinfo", "show_vfsstat", 
        "show_map_vma", "show_smap", "filldir", "filldir64"
    };
    void *funcs[] = {
        (void *)&ori_show_vfsmnt, (void *)&ori_show_mountinfo, 
        (void *)&ori_show_vfsstat, (void *)&ori_show_map_vma, 
        (void *)&ori_show_smap, (void *)&ori_filldir, (void *)&ori_filldir64
    };
    size_t i;
    for (i = 0; i < ARRAY_SIZE(syms); i++) {
        *(void **)funcs[i] = (void *)kallsyms_lookup_name_ptr(syms[i]);
    }

    mutex_lock(&filter_lock);
    
 //   add_mount_keyword("adb", MODE_HIDE);
 //  add_mount_keyword("module", MODE_HIDE);
    add_mount_keyword("APatch", MODE_MASK);
    
//    add_maps_keyword("jit", MODE_HIDE);
//    add_maps_keyword("memfd", MODE_MASK);
    
    //add_file_keyword("adb", MODE_HIDE);
    //add_file_keyword("", MODE_MASK);
    
    mutex_unlock(&filter_lock);
    
    logk("Default filters loaded: %d mount, %d maps, %d file\n", filter_manager.mount_count, filter_manager.maps_count, filter_manager.file_count);
    
    install_hook();
    
    return ;
}

static __always_inline 
void trick_exit(void) {
    
    uninstall_hook();
    
    mutex_lock(&filter_lock);
    
    kfree(filter_manager.mount_keywords);
    kfree(filter_manager.maps_keywords);
    kfree(filter_manager.file_keywords);
    
    filter_manager.mount_keywords = NULL;
    filter_manager.maps_keywords = NULL;
    filter_manager.file_keywords = NULL;
    
    filter_manager.mount_count = 0;
    filter_manager.maps_count = 0;
    filter_manager.file_count = 0;
    
    filter_manager.mount_capacity = 0;
    filter_manager.maps_capacity = 0;
    filter_manager.file_capacity = 0;
    
    mutex_unlock(&filter_lock);
    
    return ;
}

#endif //__TRICK_H