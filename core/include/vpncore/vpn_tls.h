/* vpn_tls.h - TLS 传输抽象
 *
 * 默认实现基于 OpenSSL。抽象的目的：Android 上可替换为 mbedTLS 以减小体积，
 * 而证书验证策略（严格 / 忽略 + 主机名）在两种实现中保持一致语义。
 */
#ifndef VPN_TLS_H
#define VPN_TLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vpn_config.h"
#include "vpn_net.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vpn_tls vpn_tls;

typedef struct {
    vpn_sock_t    sock;          /* 已连接的 TCP socket，TLS 不负责关闭它 */
    vpn_cert_mode cert_mode;     /* VERIFY / IGNORE */
    const char   *ca_file;       /* 追加信任的 CA（PEM），可 NULL */
    const char   *ca_dir;
    const char   *server_name;   /* SNI + 证书主机名校验，可 NULL */
    bool          verify_hostname;
    int           handshake_timeout_ms;
    char          error[320];
} vpn_tls_params;

vpn_tls *vpn_tls_new(const vpn_tls_params *p);
void     vpn_tls_free(vpn_tls *t);

int  vpn_tls_handshake(vpn_tls *t);
/* 读：返回 >0 字节数；0 = 对端优雅关闭；<0 = VPN_ERR_* */
int  vpn_tls_read(vpn_tls *t, void *buf, size_t cap, int timeout_ms);
int  vpn_tls_write(vpn_tls *t, const void *buf, size_t len, int timeout_ms);
/* 是否有已解密但未取走的数据（用于非阻塞轮询） */
bool vpn_tls_has_pending(const vpn_tls *t);
/* 最近一次失败原因 */
const char *vpn_tls_last_error(const vpn_tls *t);
/* 协商结果（日志诊断用） */
const char *vpn_tls_cipher_name(const vpn_tls *t);
const char *vpn_tls_version_str(const vpn_tls *t);
/* 对端证书摘要（SHA-256 指纹），用于证书固定/诊断输出 */
int vpn_tls_peer_fingerprint(const vpn_tls *t, char *out, size_t outlen);

/* 对端证书 DER 的 SHA-1（MS-SSTP 2.2.11 的 Cert Hash 字段） */
int vpn_tls_peer_cert_sha1(const vpn_tls *t, uint8_t out[20]);

/* 对端证书 DER 的 SHA-256（Crypto Binding 选择 SHA-256 时使用） */
int vpn_tls_peer_cert_sha256(const vpn_tls *t, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* VPN_TLS_H */
