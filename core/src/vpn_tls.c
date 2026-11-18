/* vpn_tls.c - OpenSSL 实现的 TLS 传输层（SSTP 使用） */
#include "vpncore/vpn_tls.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_platform.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct vpn_tls {
    SSL_CTX   *ctx;
    SSL       *ssl;
    vpn_sock_t sock;
    bool       handshake_done;
    char       error[320];
    char       cipher[128];
    char       version[32];
    char       fingerprint[96];
};

static void tls_set_error(vpn_tls *t, const char *what)
{
    unsigned long e = ERR_get_error();
    char buf[320];

    if (e)
        ERR_error_string_n(e, buf, sizeof(buf));
    else
        snprintf(buf, sizeof(buf), "%s", what);

    /* 显式限定长度，避免长参数触发 -Wformat-truncation（截断是预期行为） */
    snprintf(t->error, sizeof(t->error), "%.64s (%.200s)", what, buf);
    VPN_ERROR("TLS: %s", t->error);
    ERR_clear_error();
}

vpn_tls *vpn_tls_new(const vpn_tls_params *p)
{
    vpn_tls *t;
    char errbuf[256];

    if (!p || p->sock == VPN_INVALID_SOCK)
        return NULL;

    t = (vpn_tls *)calloc(1, sizeof(*t));
    if (!t)
        return NULL;

    t->sock = p->sock;
    t->ctx = SSL_CTX_new(TLS_client_method());
    if (!t->ctx) {
        tls_set_error(t, "SSL_CTX_new 失败");
        free(t);
        return NULL;
    }

    /* RouterOS 等老服务器可能只支持 TLS1.0~1.2 且使用较弱套件，
     * 这里放宽到 TLS1.0 + SECLEVEL=1，同时仍禁用 SSLv3/RC4。 */
    SSL_CTX_set_min_proto_version(t->ctx, TLS1_VERSION);
    SSL_CTX_set_options(t->ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_cipher_list(t->ctx, "DEFAULT@SECLEVEL=1");

    if (p->cert_mode == VPN_CERT_VERIFY) {
        SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_set_default_verify_paths(t->ctx))
            VPN_WARN("TLS: 加载系统默认 CA 失败");
        if (p->ca_file && p->ca_file[0]) {
            if (SSL_CTX_load_verify_locations(t->ctx, p->ca_file,
                                              (p->ca_dir && p->ca_dir[0]) ? p->ca_dir : NULL) != 1) {
                snprintf(t->error, sizeof(t->error), "加载自定义 CA 失败: %s", p->ca_file);
                VPN_ERROR("%s", t->error);
                SSL_CTX_free(t->ctx);
                free(t);
                return NULL;
            }
            VPN_INFO("TLS: 已加载自定义 CA %s", p->ca_file);
        }
    } else {
        SSL_CTX_set_verify(t->ctx, SSL_VERIFY_NONE, NULL);
        VPN_WARN("TLS: 已关闭证书校验（不安全，仅用于自签名服务器调试）");
    }

    t->ssl = SSL_new(t->ctx);
    if (!t->ssl) {
        tls_set_error(t, "SSL_new 失败");
        SSL_CTX_free(t->ctx);
        free(t);
        return NULL;
    }

    SSL_set_fd(t->ssl, (int)p->sock);

    if (p->server_name && p->server_name[0]) {
        SSL_set_tlsext_host_name(t->ssl, p->server_name);
        if (p->cert_mode == VPN_CERT_VERIFY && p->verify_hostname) {
            SSL_set_hostflags(t->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (SSL_set1_host(t->ssl, p->server_name) != 1) {
                snprintf(errbuf, sizeof(errbuf), "设置证书主机名校验失败: %s", p->server_name);
                tls_set_error(t, errbuf);
                SSL_free(t->ssl);
                SSL_CTX_free(t->ctx);
                free(t);
                return NULL;
            }
        }
    }

    return t;
}

void vpn_tls_free(vpn_tls *t)
{
    if (!t)
        return;
    if (t->ssl) {
        SSL_shutdown(t->ssl);
        SSL_free(t->ssl);
    }
    if (t->ctx)
        SSL_CTX_free(t->ctx);
    free(t);
}

static int tls_wait(vpn_tls *t, int timeout_ms, bool want_read)
{
    /* 用 select 等待 socket 可用 */
    fd_set fds;
    struct timeval tv;
    int rc;

    FD_ZERO(&fds);
    FD_SET((unsigned)t->sock, &fds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = select((int)t->sock + 1, want_read ? &fds : NULL, want_read ? NULL : &fds, NULL, &tv);
    if (rc == 0)
        return VPN_ERR_TIMEOUT;
    if (rc < 0)
        return VPN_ERR_IO;
    return VPN_OK;
}

int vpn_tls_handshake(vpn_tls *t)
{
    int64_t deadline;
    int timeout = 15000;

    if (!t)
        return VPN_ERR_INVALID;

    deadline = vpn_now_ms() + timeout;
    SSL_set_connect_state(t->ssl);

    for (;;) {
        int rc = SSL_connect(t->ssl);
        if (rc == 1)
            break;

        int err = SSL_get_error(t->ssl, rc);
        int remain = (int)(deadline - vpn_now_ms());

        if (remain <= 0) {
            snprintf(t->error, sizeof(t->error), "TLS 握手超时");
            VPN_ERROR("%s", t->error);
            return VPN_ERR_TIMEOUT;
        }

        if (err == SSL_ERROR_WANT_READ) {
            if (tls_wait(t, remain, true) != VPN_OK)
                continue;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (tls_wait(t, remain, false) != VPN_OK)
                continue;
        } else {
            long vr = SSL_get_verify_result(t->ssl);
            if (vr != X509_V_OK) {
                snprintf(t->error, sizeof(t->error), "证书校验失败: %s",
                         X509_verify_cert_error_string(vr));
                VPN_ERROR("%s", t->error);
                return VPN_ERR_TLS;
            }
            tls_set_error(t, "TLS 握手失败");
            return VPN_ERR_TLS;
        }
    }

    t->handshake_done = true;
    snprintf(t->version, sizeof(t->version), "%s", SSL_get_version(t->ssl));
    snprintf(t->cipher, sizeof(t->cipher), "%s", SSL_get_cipher_name(t->ssl));
    VPN_INFO("TLS 握手完成: %s / %s", t->version, t->cipher);

    vpn_tls_peer_fingerprint(t, t->fingerprint, sizeof(t->fingerprint));
    VPN_INFO("服务器证书 SHA-256: %s", t->fingerprint);
    return VPN_OK;
}

int vpn_tls_read(vpn_tls *t, void *buf, size_t cap, int timeout_ms)
{
    int64_t deadline;

    if (!t || !t->ssl)
        return VPN_ERR_INVALID;

    deadline = vpn_now_ms() + (timeout_ms > 0 ? timeout_ms : 30000);

    for (;;) {
        int n;

        /* socket 是阻塞模式：无数据时 SSL_read 会一直挂住，让单线程事件循环无法
         * 处理 TUN 方向的流量。超时语义（timeout_ms >= 0）下先 select 探测一次，
         * 避免把整个循环拖到一个 TLS 记录到达为止。 */
        if (timeout_ms >= 0 && SSL_pending(t->ssl) == 0) {
            int remain = (int)(deadline - vpn_now_ms());

            if (remain < 0)
                remain = 0;
            if (tls_wait(t, remain, true) != VPN_OK)
                return VPN_ERR_TIMEOUT;
        }

        n = SSL_read(t->ssl, buf, (int)cap);
        if (n > 0)
            return n;

        int err = SSL_get_error(t->ssl, n);
        int remain = (int)(deadline - vpn_now_ms());

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (remain <= 0)
                return VPN_ERR_TIMEOUT;
            if (tls_wait(t, remain, err == SSL_ERROR_WANT_READ) != VPN_OK)
                return VPN_ERR_TIMEOUT;
            continue;
        }
        if (err == SSL_ERROR_ZERO_RETURN)
            return 0;
        tls_set_error(t, "TLS 读取失败");
        return VPN_ERR_IO;
    }
}

int vpn_tls_write(vpn_tls *t, const void *buf, size_t len, int timeout_ms)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    int64_t deadline;

    if (!t || !t->ssl)
        return VPN_ERR_INVALID;

    deadline = vpn_now_ms() + (timeout_ms > 0 ? timeout_ms : 30000);

    while (off < len) {
        int n = SSL_write(t->ssl, p + off, (int)(len - off));
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        int err = SSL_get_error(t->ssl, n);
        int remain = (int)(deadline - vpn_now_ms());
        if (remain <= 0)
            return VPN_ERR_TIMEOUT;
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (tls_wait(t, remain, err == SSL_ERROR_WANT_READ) != VPN_OK)
                return VPN_ERR_TIMEOUT;
            continue;
        }
        tls_set_error(t, "TLS 写入失败");
        return VPN_ERR_IO;
    }
    return (int)off;
}

bool vpn_tls_has_pending(const vpn_tls *t)
{
    return t && t->ssl && SSL_pending(t->ssl) > 0;
}

const char *vpn_tls_last_error(const vpn_tls *t) { return t ? t->error : "no tls"; }
const char *vpn_tls_cipher_name(const vpn_tls *t) { return t ? t->cipher : ""; }
const char *vpn_tls_version_str(const vpn_tls *t) { return t ? t->version : ""; }

int vpn_tls_peer_cert_sha1(const vpn_tls *t, uint8_t out[20])
{
    X509 *cert;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    int rc;

    if (!t || !t->ssl || !out)
        return VPN_ERR_INVALID;

    cert = SSL_get1_peer_certificate(t->ssl);
    if (!cert)
        return VPN_ERR_TLS;

    rc = X509_digest(cert, EVP_sha1(), md, &mdlen);
    X509_free(cert);

    if (rc != 1 || mdlen != 20)
        return VPN_ERR_TLS;

    memcpy(out, md, 20);
    return VPN_OK;
}

int vpn_tls_peer_cert_sha256(const vpn_tls *t, uint8_t out[32])
{
    X509 *cert;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    int rc;

    if (!t || !t->ssl || !out)
        return VPN_ERR_INVALID;

    cert = SSL_get1_peer_certificate(t->ssl);
    if (!cert)
        return VPN_ERR_TLS;

    rc = X509_digest(cert, EVP_sha256(), md, &mdlen);
    X509_free(cert);

    if (rc != 1 || mdlen != 32)
        return VPN_ERR_TLS;

    memcpy(out, md, 32);
    return VPN_OK;
}

int vpn_tls_peer_fingerprint(const vpn_tls *t, char *out, size_t outlen)
{
    X509 *cert;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    size_t pos = 0;

    if (!t || !t->ssl || !out)
        return VPN_ERR_INVALID;

    cert = SSL_get1_peer_certificate(t->ssl);
    if (!cert) {
        snprintf(out, outlen, "no-certificate");
        return VPN_ERR_TLS;
    }

    if (X509_digest(cert, EVP_sha256(), md, &mdlen) != 1) {
        X509_free(cert);
        return VPN_ERR_TLS;
    }
    X509_free(cert);

    for (unsigned int i = 0; i < mdlen && pos + 3 < outlen; i++)
        pos += (size_t)snprintf(out + pos, outlen - pos, i ? ":%02X" : "%02X", md[i]);

    return VPN_OK;
}
