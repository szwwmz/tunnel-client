/* vpn_error.h - 统一错误码 */
#ifndef VPN_ERROR_H
#define VPN_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

enum vpn_errno {
    VPN_OK             = 0,
    VPN_ERR_INVALID    = -1,
    VPN_ERR_NOMEM      = -2,
    VPN_ERR_IO         = -3,
    VPN_ERR_TIMEOUT    = -4,
    VPN_ERR_AUTH       = -5,
    VPN_ERR_TLS        = -6,
    VPN_ERR_PROTO      = -7,
    VPN_ERR_CANCELLED  = -8,
    VPN_ERR_UNSUPPORTED = -9,
    VPN_ERR_CONFIG     = -10,
    VPN_ERR_CLOSED     = -11,
    VPN_ERR_BUSY       = -12  /* 资源已被占用（如 TUN 已挂接） */
};

/* 返回静态字符串，不要释放 */
const char *vpn_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* VPN_ERROR_H */
