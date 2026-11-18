/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* test_capi.c - C ABI（JNI / C# 入口）冒烟测试 */
#include "test.h"

#include "vpncore/vpn_capi.h"
#include "vpncore/vpn_error.h"

#include <string.h>

static void capi_state(int state, const char *detail, void *user)
{
    int *last = user;
    (void)detail;
    *last = state;
}

static vpn_capi_config make_cfg(void)
{
    vpn_capi_config cc;
    memset(&cc, 0, sizeof(cc));
    cc.proto = 0;
    cc.host = "127.0.0.1";
    cc.port = 1;
    cc.username = "user";
    cc.password = "pass";
    cc.auth = 0;
    cc.cert_mode = 1;
    cc.verify_hostname = 0;
    cc.mtu = 1400;
    cc.keepalive_s = 0;
    cc.reconnect_delay_s = 1;
    cc.max_retries = 0;
    cc.connect_timeout_s = 1;
    cc.io_timeout_s = 1;
    cc.log_level = 0;
    cc.tun_fd = -1;
    return cc;
}

TEST(capi_invalid_config_rejected)
{
    vpn_capi_config cc = make_cfg();
    char err[192];
    vpn_handle h;

    cc.host = "";
    memset(err, 0, sizeof(err));
    h = vpn_capi_create(&cc, NULL, NULL, NULL, err, sizeof(err));
    CHECK(h == NULL);
    CHECK(err[0] != '\0');
}

TEST(capi_lifecycle)
{
    vpn_capi_config cc = make_cfg();
    vpn_capi_stats st;
    char err[192];
    vpn_handle h;
    int last_state = -1;
    int rc;

    h = vpn_capi_create(&cc, capi_state, NULL, &last_state, err, sizeof(err));
    CHECK(h != NULL);
    CHECK_EQ_INT(vpn_capi_state(h), VPN_CAPI_STATE_IDLE);

    rc = vpn_capi_start(h);
    CHECK_EQ_INT(rc, VPN_OK);

    rc = vpn_capi_wait(h, 8000);
    CHECK(rc != VPN_OK); /* 127.0.0.1:1 必然连不上 */
    CHECK(last_state == VPN_CAPI_STATE_FAILED ||
          last_state == VPN_CAPI_STATE_DISCONNECTED);

    vpn_capi_get_stats(h, &st);
    CHECK_EQ_INT(st.rx_bytes, 0);
    CHECK_EQ_INT(st.tx_bytes, 0);

    vpn_capi_stop(h);
    vpn_capi_destroy(h);
}

TEST(capi_helpers)
{
    CHECK(strcmp(vpn_capi_state_name(VPN_CAPI_STATE_CONNECTED), "connected") == 0);
    CHECK(vpn_capi_strerror(VPN_OK) != NULL);
    CHECK(vpn_capi_strerror(VPN_ERR_AUTH) != NULL);
}
