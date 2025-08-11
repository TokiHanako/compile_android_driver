#pragma once
#ifndef OBFUSCATE_LKM_H
#define OBFUSCATE_LKM_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/sched.h> 

#define RND_SEED(i) ((__COUNTER__ + __LINE__ + (i)) * 2654435761u)
#define OBF_INLINE inline __attribute__((always_inline))

#define read_arm64_sysreg(reg_name) ({ \
    u64 _val; \
    asm volatile("mrs %0, " #reg_name : "=r" (_val)); \
    _val; \
})

OBF_INLINE u64 get_cpu_ticks(void) { return read_arm64_sysreg(cntvct_el0); }

OBF_INLINE u64 generate_dynamic_key(void) {
    u64 ticks = get_cpu_ticks();
    u64 pid_stack_entropy = (u64)current->pid ^ ((u64)&ticks >> 4);
    return ticks ^ pid_stack_entropy;
}

#define OBF_NUM(num)                                                        \
({                                                                          \
    const unsigned long long key1 = RND_SEED(1);                            \
    const unsigned long long key2 = RND_SEED(2);                            \
    const unsigned long long encrypted_val = ((unsigned long long)(num) ^ key1) ^ key2; \
    volatile unsigned long long val_to_decrypt = encrypted_val;             \
    volatile unsigned long long decryption_key1 = key1;                     \
    volatile unsigned long long decryption_key2 = key2;                     \
    volatile u64 dynamic_key = generate_dynamic_key();                      \
    unsigned long long decrypted_val = (val_to_decrypt ^ decryption_key1 ^ decryption_key2) ^ (dynamic_key ^ dynamic_key); \
    (typeof(num))(decrypted_val);                                           \
})

#endif
