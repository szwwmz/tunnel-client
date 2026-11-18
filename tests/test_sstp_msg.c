/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* test_sstp_msg.c - SSTP 控制报文/属性编解码（MS-SSTP 2.2.2） */
#include "test.h"

#include "vpncore/vpn_sstp.h"

#include <stdint.h>
#include <string.h>

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

TEST(sstp_attr_basic)
{
    uint8_t buf[16];
    const uint8_t encap[2] = { 0x00, 0x01 };
    int n;

    n = vpn_sstp_build_attr(buf, sizeof(buf), SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID,
                            encap, sizeof(encap));
    CHECK_EQ_INT(n, 6);
    CHECK_EQ_INT(buf[0], 0);   /* Reserved */
    CHECK_EQ_INT(buf[1], SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID); /* 规范里 Encap = 0 */
    CHECK_EQ_INT(be16(buf + 2), 6);  /* Length 含 4 字节头 */
    CHECK_EQ_INT(be16(buf + 4), SSTP_ENCAP_PPP);

    /* 容量不足必须拒绝 */
    CHECK_EQ_INT(vpn_sstp_build_attr(buf, 5, SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID, encap, 2), -1);
}

/* CALL_CONNECTED 是原地构造：value 直接指向输出区里的 attrs+4。
 * 以前这里走 memcpy，源目标完全重叠属未定义行为（gcc -Wrestrict 报错），
 * 现改为 memmove；本用例锁定该用法必须继续得到正确结果。 */
TEST(sstp_attr_in_place_overlap)
{
    uint8_t attrs[8];
    int n;

    memset(attrs, 0xAA, sizeof(attrs));
    attrs[4] = 0x00;
    attrs[5] = 0x01;                       /* Encap = PPP */
    n = vpn_sstp_build_attr(attrs, sizeof(attrs),
                            SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID, attrs + 4, 2);
    CHECK_EQ_INT(n, 6);
    CHECK_EQ_INT(attrs[1], SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID);
    CHECK_EQ_INT(be16(attrs + 2), 6);
    CHECK_EQ_INT(be16(attrs + 4), SSTP_ENCAP_PPP);
}

TEST(sstp_control_call_connect_request)
{
    uint8_t attrs[32];
    uint8_t pkt[64];
    const uint8_t encap[2] = { 0x00, 0x01 };
    int alen = 0, n;

    n = vpn_sstp_build_attr(attrs, sizeof(attrs), SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID,
                            encap, sizeof(encap));
    CHECK(n > 0);
    alen += n;

    n = vpn_sstp_build_control(pkt, sizeof(pkt), SSTP_MSG_CALL_CONNECT_REQUEST,
                               attrs, (size_t)alen);
    CHECK_EQ_INT(n, 8 + alen);
    CHECK_EQ_INT(pkt[0], SSTP_VERSION);      /* 0x10 */
    CHECK_EQ_INT(pkt[1] & 0x01, 0x01);       /* C = 1（控制报文） */
    CHECK_EQ_INT(be16(pkt + 2), n);          /* Length */
    CHECK_EQ_INT(be16(pkt + 4), SSTP_MSG_CALL_CONNECT_REQUEST);
    CHECK_EQ_INT(be16(pkt + 6), 1);          /* Num-Attributes */
    CHECK_BYTES(pkt + 8, attrs, (size_t)alen);

    /* 整包逐字节：10 01 00 0C 00 01 00 01 | 00 00 00 06 00 01 */
    {
        static const uint8_t expect[] = {
            0x10, 0x01, 0x00, 0x0E, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x06, 0x00, 0x01
        };
        CHECK_EQ_INT(n, (int)sizeof(expect));
        CHECK_BYTES(pkt, expect, sizeof(expect));
    }
}

TEST(sstp_control_multi_attrs)
{
    uint8_t attrs[64];
    uint8_t pkt[96];
    const uint8_t encap[2] = { 0x00, 0x01 };
    const uint8_t status[4] = { 0x00, 0x00, 0x00, 0x00 };
    int alen = 0, n;

    n = vpn_sstp_build_attr(attrs + alen, sizeof(attrs) - (size_t)alen,
                            SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID, encap, 2);
    CHECK(n > 0);
    alen += n;
    n = vpn_sstp_build_attr(attrs + alen, sizeof(attrs) - (size_t)alen,
                            SSTP_ATTR_STATUS_INFO, status, 4);
    CHECK(n > 0);
    alen += n;

    n = vpn_sstp_build_control(pkt, sizeof(pkt), SSTP_MSG_CALL_CONNECT_NAK, attrs,
                               (size_t)alen);
    CHECK_EQ_INT(n, 8 + alen);
    CHECK_EQ_INT(be16(pkt + 6), 2);
    CHECK_EQ_INT(be16(pkt + 4), SSTP_MSG_CALL_CONNECT_NAK);

    /* 逐个属性走一遍，确认 TLV 边界清楚 */
    {
        size_t pos = 8;
        int seen = 0;
        while (pos + 4 <= (size_t)n) {
            uint16_t alen2 = be16(pkt + pos + 2);
            CHECK(alen2 >= 4);
            CHECK(pos + alen2 <= (size_t)n);
            pos += alen2;
            seen++;
        }
        CHECK_EQ_INT(seen, 2);
        CHECK_EQ_INT(pos, (size_t)n);
    }
}

TEST(sstp_control_capacity_guard)
{
    uint8_t pkt[16];
    uint8_t attrs[8];
    const uint8_t encap[2] = { 0x00, 0x01 };
    int alen, n;

    alen = vpn_sstp_build_attr(attrs, sizeof(attrs), SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID, encap, 2);
    CHECK(alen > 0);
    /* 需要 8 + alen 字节，故意只给 10 字节 */
    n = vpn_sstp_build_control(pkt, 10, SSTP_MSG_CALL_CONNECT_REQUEST, attrs,
                               (size_t)alen);
    if (8 + alen > 10)
        CHECK_EQ_INT(n, -1);
    else
        CHECK(n > 0);
}
