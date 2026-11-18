/* vpn_ike.h - IKEv1 (PSK) + ESP transport，用户态实现
 *
 * 目的：让客户端自带 L2TP/IPsec 能力，不依赖系统 strongSwan，也不要求
 * root 权限（全部流量走 UDP/500 与 UDP/4500 的 NAT-T 封装，不使用 IP 协议 50）。
 *
 * 只实现 MikroTik RouterOS l2tp-server use-ipsec=yes 所需的最小集合：
 *   - IKEv1 主模式（Main Mode），PSK 认证
 *   - 加密 3DES-CBC / AES-128-CBC / AES-256-CBC，哈希 SHA1，DH group 2
 *   - Quick Mode 建立 ESP transport SA，保护 UDP/1701
 *   - ESP：AES-CBC + HMAC-SHA1-96，NAT-T UDP/4500 封装
 */
#ifndef VPN_IKE_H
#define VPN_IKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VPN_IKE_MAX_PKT 2048

typedef struct vpn_ipsec vpn_ipsec;

typedef struct {
    char     host[64];      /* 服务器 IPv4 点分串（上层负责解析域名） */
    uint16_t port;          /* IKE 端口，0 = 500 */
    char     psk[128];      /* 预共享密钥 */
    char     local_id[64];  /* 本地 ID（空 = 按出口地址自动取） */
    int      timeout_ms;    /* 单次 IKE 交互超时，0 = 8000 */
    /* 用户态收不到 IP 协议 50，必须走 NAT-T 封装。置 true 时在 NAT-D 中
     * 通告"存在 NAT"，对端判定 NAT 后会把 IKE 浮动到 4500 并用 UDP 封装 ESP。
     * 手机/PC 客户端默认应开启；仅当服务器已强制 encaps（forceencaps）时可关。 */
    bool     force_natt;
} vpn_ike_params;

/* 创建/释放。失败返回 NULL。 */
vpn_ipsec *vpn_ipsec_new(const vpn_ike_params *p, char *err, size_t errlen);
void       vpn_ipsec_free(vpn_ipsec *ip);

/* 完成 IKEv1 主模式 + Quick Mode。
 * 成功返回 VPN_OK(0)，失败返回负错误码并在 err 中给出原因。
 * 需要数秒（含 DH 运算）。 */
int vpn_ipsec_connect(vpn_ipsec *ip, char *err, size_t errlen);

bool vpn_ipsec_up(const vpn_ipsec *ip);

/* 收/发一条 L2TP 报文（内部完成 ESP 加解密 + NAT-T 封装）。
 * recv 的 timeout_ms < 0 表示阻塞；返回到明文长度，超时返回 0，错误 < 0。 */
int vpn_ipsec_send(vpn_ipsec *ip, const uint8_t *data, size_t len);
int vpn_ipsec_recv(vpn_ipsec *ip, uint8_t *buf, size_t cap, int timeout_ms);

/* 底层 UDP fd（用于 poll），没有则返回 -1 */
int vpn_ipsec_fd(const vpn_ipsec *ip);

/* 供日志/UI 展示 */
const char *vpn_ipsec_cipher(const vpn_ipsec *ip);

#ifdef __cplusplus
}
#endif

#endif /* VPN_IKE_H */
