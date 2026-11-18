/* vpn_ppp_frame.h - PPP over HDLC-like 成帧（RFC 1662）
 *
 * SSTP 用它在 TLS 之上承载 PPP：0x7E 定界 + 0xFF 0x03 地址控制 + 协议 +
 * 载荷 + 16bit FCS，转义 0x7D。ACFC/PFC 默认关闭发送（保证与 MikroTik 兼容），
 * 但接收侧同时支持被压缩的地址/控制/协议字段。
 */
#ifndef VPN_PPP_FRAME_H
#define VPN_PPP_FRAME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PPP_FLAG      0x7e
#define PPP_ESCAPE    0x7d
#define PPP_ACCM      0xffffffffu

uint16_t vpn_ppp_fcs16(const void *data, size_t len);

/* 把 PPP 帧（协议+载荷）封装为 HDLC 帧，写入 out（容量 cap），返回帧长，<0 失败 */
int vpn_ppp_hdlc_encode(const uint8_t *frame, size_t len, uint8_t *out, size_t cap);

/* 解码器：逐字节喂入，遇到 0x7E 完成一帧后回调 */
typedef void (*vpn_hdlc_frame_cb)(void *ctx, const uint8_t *frame, size_t len);

typedef struct {
    uint8_t  buf[4096];
    size_t   len;
    uint16_t fcs;
    int      escaped;
    int      in_frame;
    int64_t  frames_ok;
    int64_t  frames_bad_fcs;
    int64_t  frames_overflow;
    vpn_hdlc_frame_cb cb;
    void    *ctx;
} vpn_hdlc_decoder;

void vpn_hdlc_decoder_init(vpn_hdlc_decoder *d, vpn_hdlc_frame_cb cb, void *ctx);
void vpn_hdlc_decoder_feed(vpn_hdlc_decoder *d, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VPN_PPP_FRAME_H */
