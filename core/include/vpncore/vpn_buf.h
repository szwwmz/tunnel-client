/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_buf.h - 动态写缓冲 + 只读游标
 *
 * 网络字节序（大端）与大端字写入都提供，PPP/L2TP/SSTP 报文构造统一走这里，
 * 避免各模块各自写指针运算导致越界。
 */
#ifndef VPN_BUF_H
#define VPN_BUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} vpn_buf;

void vpn_buf_init(vpn_buf *b);
void vpn_buf_free(vpn_buf *b);
void vpn_buf_reset(vpn_buf *b);

int vpn_buf_reserve(vpn_buf *b, size_t need);
int vpn_buf_append(vpn_buf *b, const void *data, size_t len);
int vpn_buf_append_u8(vpn_buf *b, uint8_t v);
int vpn_buf_append_be16(vpn_buf *b, uint16_t v);
int vpn_buf_append_be32(vpn_buf *b, uint32_t v);
int vpn_buf_append_le16(vpn_buf *b, uint16_t v);
int vpn_buf_append_le32(vpn_buf *b, uint32_t v);
int vpn_buf_append_zeros(vpn_buf *b, size_t n);

/* 回填：把 value 写到之前预留的位置 */
int vpn_buf_patch_be16(vpn_buf *b, size_t off, uint16_t v);
int vpn_buf_patch_be32(vpn_buf *b, size_t off, uint32_t v);

/* 只读游标 */
typedef struct {
    const uint8_t *data;
    size_t         len;
    size_t         pos;
} vpn_rd;

void     vpn_rd_init(vpn_rd *r, const void *data, size_t len);
size_t   vpn_rd_remaining(const vpn_rd *r);
bool     vpn_rd_ok(const vpn_rd *r);
int      vpn_rd_u8(vpn_rd *r, uint8_t *out);
int      vpn_rd_be16(vpn_rd *r, uint16_t *out);
int      vpn_rd_be32(vpn_rd *r, uint32_t *out);
int      vpn_rd_le16(vpn_rd *r, uint16_t *out);
int      vpn_rd_bytes(vpn_rd *r, void *out, size_t n);
int      vpn_rd_skip(vpn_rd *r, size_t n);
const uint8_t *vpn_rd_ptr(const vpn_rd *r);

uint16_t vpn_be16(const void *p);
uint32_t vpn_be32(const void *p);
uint16_t vpn_le16(const void *p);
uint32_t vpn_le32(const void *p);
void     vpn_put_be16(void *p, uint16_t v);
void     vpn_put_be32(void *p, uint32_t v);

/* 十六进制 dump（日志用），返回静态轮转缓冲，最多 4 个并存 */
const char *vpn_hexdump(const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VPN_BUF_H */
