#include "vpncore/vpn_buf.h"
#include "vpncore/vpn_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vpn_buf_init(vpn_buf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void vpn_buf_free(vpn_buf *b)
{
    free(b->data);
    vpn_buf_init(b);
}

void vpn_buf_reset(vpn_buf *b) { b->len = 0; }

int vpn_buf_reserve(vpn_buf *b, size_t need)
{
    if (b->len + need <= b->cap)
        return VPN_OK;

    size_t want = b->cap ? b->cap : 128;
    while (want < b->len + need)
        want *= 2;

    uint8_t *nd = (uint8_t *)realloc(b->data, want);
    if (!nd)
        return VPN_ERR_NOMEM;
    b->data = nd;
    b->cap = want;
    return VPN_OK;
}

int vpn_buf_append(vpn_buf *b, const void *data, size_t len)
{
    int rc = vpn_buf_reserve(b, len);
    if (rc != VPN_OK)
        return rc;
    if (len)
        memcpy(b->data + b->len, data, len);
    b->len += len;
    return VPN_OK;
}

int vpn_buf_append_u8(vpn_buf *b, uint8_t v) { return vpn_buf_append(b, &v, 1); }

int vpn_buf_append_be16(vpn_buf *b, uint16_t v)
{
    uint8_t t[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    return vpn_buf_append(b, t, 2);
}

int vpn_buf_append_be32(vpn_buf *b, uint32_t v)
{
    uint8_t t[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    return vpn_buf_append(b, t, 4);
}

int vpn_buf_append_le16(vpn_buf *b, uint16_t v)
{
    uint8_t t[2] = { (uint8_t)v, (uint8_t)(v >> 8) };
    return vpn_buf_append(b, t, 2);
}

int vpn_buf_append_le32(vpn_buf *b, uint32_t v)
{
    uint8_t t[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    return vpn_buf_append(b, t, 4);
}

int vpn_buf_append_zeros(vpn_buf *b, size_t n)
{
    int rc = vpn_buf_reserve(b, n);
    if (rc != VPN_OK)
        return rc;
    memset(b->data + b->len, 0, n);
    b->len += n;
    return VPN_OK;
}

int vpn_buf_patch_be16(vpn_buf *b, size_t off, uint16_t v)
{
    if (off + 2 > b->len)
        return VPN_ERR_INVALID;
    b->data[off] = (uint8_t)(v >> 8);
    b->data[off + 1] = (uint8_t)v;
    return VPN_OK;
}

int vpn_buf_patch_be32(vpn_buf *b, size_t off, uint32_t v)
{
    if (off + 4 > b->len)
        return VPN_ERR_INVALID;
    b->data[off] = (uint8_t)(v >> 24);
    b->data[off + 1] = (uint8_t)(v >> 16);
    b->data[off + 2] = (uint8_t)(v >> 8);
    b->data[off + 3] = (uint8_t)v;
    return VPN_OK;
}

void vpn_rd_init(vpn_rd *r, const void *data, size_t len)
{
    r->data = (const uint8_t *)data;
    r->len = len;
    r->pos = 0;
}

size_t vpn_rd_remaining(const vpn_rd *r) { return r->len > r->pos ? r->len - r->pos : 0; }
bool vpn_rd_ok(const vpn_rd *r) { return r->pos <= r->len; }

int vpn_rd_u8(vpn_rd *r, uint8_t *out)
{
    if (vpn_rd_remaining(r) < 1)
        return VPN_ERR_PROTO;
    *out = r->data[r->pos++];
    return VPN_OK;
}

int vpn_rd_be16(vpn_rd *r, uint16_t *out)
{
    if (vpn_rd_remaining(r) < 2)
        return VPN_ERR_PROTO;
    *out = (uint16_t)((r->data[r->pos] << 8) | r->data[r->pos + 1]);
    r->pos += 2;
    return VPN_OK;
}

int vpn_rd_be32(vpn_rd *r, uint32_t *out)
{
    if (vpn_rd_remaining(r) < 4)
        return VPN_ERR_PROTO;
    *out = ((uint32_t)r->data[r->pos] << 24) | ((uint32_t)r->data[r->pos + 1] << 16) |
           ((uint32_t)r->data[r->pos + 2] << 8) | r->data[r->pos + 3];
    r->pos += 4;
    return VPN_OK;
}

int vpn_rd_le16(vpn_rd *r, uint16_t *out)
{
    if (vpn_rd_remaining(r) < 2)
        return VPN_ERR_PROTO;
    *out = (uint16_t)(r->data[r->pos] | (r->data[r->pos + 1] << 8));
    r->pos += 2;
    return VPN_OK;
}

int vpn_rd_bytes(vpn_rd *r, void *out, size_t n)
{
    if (vpn_rd_remaining(r) < n)
        return VPN_ERR_PROTO;
    if (n && out)
        memcpy(out, r->data + r->pos, n);
    r->pos += n;
    return VPN_OK;
}

int vpn_rd_skip(vpn_rd *r, size_t n)
{
    if (vpn_rd_remaining(r) < n)
        return VPN_ERR_PROTO;
    r->pos += n;
    return VPN_OK;
}

const uint8_t *vpn_rd_ptr(const vpn_rd *r) { return r->data + r->pos; }

uint16_t vpn_be16(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)((b[0] << 8) | b[1]);
}

uint32_t vpn_be32(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

uint16_t vpn_le16(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | (b[1] << 8));
}

uint32_t vpn_le32(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

void vpn_put_be16(void *p, uint16_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
}

void vpn_put_be32(void *p, uint32_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

const char *vpn_hexdump(const void *data, size_t len)
{
    static char slots[4][512];
    static int  idx = 0;
    char *out = slots[idx];
    const uint8_t *p = (const uint8_t *)data;
    size_t max = len > 160 ? 160 : len;
    size_t pos = 0;

    idx = (idx + 1) & 3;
    out[0] = '\0';
    for (size_t i = 0; i < max && pos + 4 < sizeof(slots[0]); i++)
        pos += (size_t)snprintf(out + pos, sizeof(slots[0]) - pos, "%02x", p[i]);
    if (max < len)
        snprintf(out + pos, sizeof(slots[0]) - pos, "...(%zu bytes)", len);
    return out;
}
