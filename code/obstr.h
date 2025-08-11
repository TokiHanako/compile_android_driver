#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wgcc-compat"

#include <linux/ctype.h>  // 用于 isdigit 和 tolower
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/sched.h> 

static inline int hexCharToInt(char c) {
    if (isdigit(c)) {
        return c - '0';
    } else {
        c = tolower(c);
        if (c >= 'a' && c <= 'f') {
            return 10 + (c - 'a');
        }
    }
    return -1;  // 非法字符
}

// 自定义函数：将十六进制字符串转换为整数
static inline unsigned int hexStringToInt(const char* str) {
    unsigned int result = 0;
    
    // 检查是否以 "0x" 或 "0X" 开头
    if (str[0] == '0' && tolower(str[1]) == 'x') {
        str += 2;  // 跳过 "0x" 前缀
    }
    
    // 逐个字符处理
    while (*str != '\0') {
        int value = hexCharToInt(*str);
        if (value == -1) {
           // printf("Invalid hex character: %c\n", *str);
            return 0;  // 遇到非法字符，返回 0 或处理错误
        }
        result = result * 16 + value;
        str++;
    }
    
    return result;
}

// https://en.wikipedia.org/wiki/XTEA
#define DELTA 0x9E3779B9 

/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */
static void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=DELTA;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

static void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=DELTA, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

static uint32_t s_obstrkey[] = {0x6C, 0x5D, 0x18, 0x3C};

static inline void ObstrEnc(const char *v, uint8_t *out, int *outsize)
{
    int vs = (strlen(v) + 7) & 0xfffffff8;
    int leb = vs;
    int osize = 0;
    // LEB128 codec.
    while (leb > 127) {
        *out++ = leb | 0x80;
        leb >>= 7;
        osize++;
    }
    osize++;
    *out++ = leb;

    memcpy(out, v, strlen(v)+1);
    for (int i = 0; i < vs/8; ++i) {
        encipher(16, (uint32_t *)out + 2 * i, s_obstrkey);
    }
    *outsize = osize + vs;
}

static inline char *ObstrDec(uint8_t *v)
{
    if (*v) {
        int vs = 0;
        uint8_t *bv = v;
        uint8_t byte = *v++;
        if (byte < 128) {
            vs = byte;
        } else {
            vs = byte & 0x7f;
            unsigned shift = 7;
            do
            {
                byte = *v++;
                vs |= (byte & 0x7f) << shift;
                shift += 7;
            } while (byte >= 128);
        }
        while (bv != v) {
            *bv++ = 0;
        }

        for (int i = 0; i < vs / 8; ++i)
        {
            decipher(16, (uint32_t*)v+2*i, s_obstrkey);
        }
    } else {
        while (!*(++v)) {}
    }
    return (char *)v;
}
