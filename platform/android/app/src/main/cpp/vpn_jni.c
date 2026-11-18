/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_jni.c - Android JNI 桥：把 core 的 C ABI 暴露给 Kotlin
 *
 * 线程说明：on_state / on_stats 由核心 worker 线程回调，这里负责
 * AttachCurrentThread（若需要），保证 JNIEnv 合法。
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vpncore/vpn_capi.h"

typedef struct {
    jobject cb; /* NativeCallback 的全局引用 */
    jmethodID m_on_state;
    jmethodID m_on_stats;
    jmethodID m_on_log;
} jni_bridge;

static JavaVM *g_vm;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    g_vm = vm;
    return JNI_VERSION_1_6;
}

static JNIEnv *get_env(int *attached)
{
    JNIEnv *env = NULL;
    *attached = 0;
    if (!g_vm)
        return NULL;
    if ((*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK)
        return env;
    {
        /* C 与 C++ 的 AttachCurrentThread 原型不同，统一用 void* 中转 */
        void *penv = NULL;
        if ((*g_vm)->AttachCurrentThread(g_vm, &penv, NULL) == JNI_OK) {
            *attached = 1;
            return (JNIEnv *)penv;
        }
    }
    return NULL;
}

static void release_env(int attached)
{
    if (attached && g_vm)
        (*g_vm)->DetachCurrentThread(g_vm);
}

/* --- VpnService.protect 桥接：隧道建立后服务器连接必须走物理网卡 --- */
static jclass g_cls_vpncore;
static jmethodID g_mid_protect;

static int jni_protect(void *ctx, int fd)
{
    int attached = 0;
    JNIEnv *env;
    jboolean ok;

    (void)ctx;
    if (!g_cls_vpncore || !g_mid_protect)
        return -1;
    env = get_env(&attached);
    if (!env)
        return -1;
    ok = (*env)->CallStaticBooleanMethod(env, g_cls_vpncore, g_mid_protect, (jint)fd);
    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);
    release_env(attached);
    return ok ? 0 : -1;
}

/* 第一次 nativeCreate 时缓存 VpnCore 类引用并注册钩子 */
static void ensure_protect_hook(JNIEnv *env)
{
    jclass cls;

    if (g_cls_vpncore)
        return;
    cls = (*env)->FindClass(env, "com/example/vpnclient/VpnCore");
    if (!cls) {
        (*env)->ExceptionClear(env);
        return;
    }
    g_cls_vpncore = (jclass)(*env)->NewGlobalRef(env, cls);
    g_mid_protect = (*env)->GetStaticMethodID(env, cls, "protectSocket", "(I)Z");
    (*env)->DeleteLocalRef(env, cls);
    if (g_mid_protect)
        vpn_capi_set_socket_protect(jni_protect, NULL);
}

static void jni_on_state(int state, const char *detail, void *user)
{
    jni_bridge *b = user;
    int attached;
    JNIEnv *env = get_env(&attached);
    if (!env)
        return;
    jstring jd = (*env)->NewStringUTF(env, detail ? detail : "");
    (*env)->CallVoidMethod(env, b->cb, b->m_on_state, (jint)state, jd);
    (*env)->DeleteLocalRef(env, jd);
    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);
    release_env(attached);
}

static void jni_on_stats(const vpn_capi_stats *st, void *user)
{
    jni_bridge *b = user;
    int attached;
    JNIEnv *env = get_env(&attached);
    jlong vals[8];
    jlongArray arr;

    if (!env)
        return;
    vals[0] = (jlong)st->rx_bytes;
    vals[1] = (jlong)st->tx_bytes;
    vals[2] = (jlong)st->rx_packets;
    vals[3] = (jlong)st->tx_packets;
    vals[4] = (jlong)st->dropped;
    vals[5] = (jlong)st->reconnects;
    vals[6] = (jlong)st->rtt_ms;
    vals[7] = (jlong)st->connected_since_ms;

    arr = (*env)->NewLongArray(env, 8);
    (*env)->SetLongArrayRegion(env, arr, 0, 8, vals);
    (*env)->CallVoidMethod(env, b->cb, b->m_on_stats, arr);
    (*env)->DeleteLocalRef(env, arr);
    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);
    release_env(attached);
}

static void jni_on_log(int level, const char *msg, void *user)
{
    jni_bridge *b = user;
    int attached;
    JNIEnv *env = get_env(&attached);

    if (!env || !b || !b->m_on_log) {
        release_env(attached);
        return;
    }
    jstring jm = (*env)->NewStringUTF(env, msg ? msg : "");
    (*env)->CallVoidMethod(env, b->cb, b->m_on_log, (jint)level, jm);
    (*env)->DeleteLocalRef(env, jm);
    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);
    release_env(attached);
}

/* 取数组里的字符串（越界或 null 返回空串） */
static void get_elem(JNIEnv *env, jobjectArray arr, jsize idx, char *dst, size_t cap)
{
    jstring s;
    const char *utf;

    dst[0] = '\0';
    if (!arr || idx >= (*env)->GetArrayLength(env, arr))
        return;
    s = (jstring)(*env)->GetObjectArrayElement(env, arr, idx);
    if (!s)
        return;
    utf = (*env)->GetStringUTFChars(env, s, NULL);
    if (utf) {
        snprintf(dst, cap, "%s", utf);
        (*env)->ReleaseStringUTFChars(env, s, utf);
    }
    (*env)->DeleteLocalRef(env, s);
}

static int get_int(JNIEnv *env, jobjectArray arr, jsize idx, int def)
{
    char buf[32];
    get_elem(env, arr, idx, buf, sizeof(buf));
    return buf[0] ? atoi(buf) : def;
}

/* 配置数组下标（与 Kotlin 侧 VpnCore.buildConfig 一一对应） */
#define CFG_PROTO        0
#define CFG_HOST         1
#define CFG_PORT         2
#define CFG_USER         3
#define CFG_PASS         4
#define CFG_PSK          5
#define CFG_AUTH         6
#define CFG_CERT_MODE    7
#define CFG_CA_FILE      8
#define CFG_SERVER_NAME  9
#define CFG_VERIFY_NAME 10
#define CFG_MTU         11
#define CFG_KEEPALIVE   12
#define CFG_RECONNECT   13
#define CFG_MAX_RETRY   14
#define CFG_CONN_TIMEOUT 15
#define CFG_IO_TIMEOUT  16
#define CFG_LOCAL_IP    17
#define CFG_DNS1        18
#define CFG_DNS2        19
#define CFG_LOG_LEVEL   20

JNIEXPORT jlong JNICALL
Java_com_example_vpnclient_VpnCore_nativeCreate(JNIEnv *env, jclass cls,
                                                jobjectArray cfg, jobject callback)
{
    static char host[256], user[128], pass[256], psk[128], cafile[512], sname[256];
    static char lip[64], dns1[64], dns2[64];
    jni_bridge *bridge;
    vpn_capi_config cc;
    jclass cbcls;
    vpn_handle h;
    char err[192];

    (void)cls;
    ensure_protect_hook(env);
    get_elem(env, cfg, CFG_HOST, host, sizeof(host));
    get_elem(env, cfg, CFG_USER, user, sizeof(user));
    get_elem(env, cfg, CFG_PASS, pass, sizeof(pass));
    get_elem(env, cfg, CFG_PSK, psk, sizeof(psk));
    get_elem(env, cfg, CFG_CA_FILE, cafile, sizeof(cafile));
    get_elem(env, cfg, CFG_SERVER_NAME, sname, sizeof(sname));
    get_elem(env, cfg, CFG_LOCAL_IP, lip, sizeof(lip));
    get_elem(env, cfg, CFG_DNS1, dns1, sizeof(dns1));
    get_elem(env, cfg, CFG_DNS2, dns2, sizeof(dns2));

    bridge = calloc(1, sizeof(*bridge));
    if (!bridge)
        return 0;

    if (callback) {
        cbcls = (*env)->GetObjectClass(env, callback);
        bridge->cb = (*env)->NewGlobalRef(env, callback);
        bridge->m_on_state = (*env)->GetMethodID(env, cbcls, "onState", "(ILjava/lang/String;)V");
        bridge->m_on_stats = (*env)->GetMethodID(env, cbcls, "onStats", "([J)V");
        bridge->m_on_log = (*env)->GetMethodID(env, cbcls, "onLog", "(ILjava/lang/String;)V");
        (*env)->DeleteLocalRef(env, cbcls);
    }

    memset(&cc, 0, sizeof(cc));
    cc.proto = get_int(env, cfg, CFG_PROTO, 0);
    cc.host = host;
    cc.port = get_int(env, cfg, CFG_PORT, 0);
    cc.username = user;
    cc.password = pass;
    cc.psk = psk;
    cc.auth = get_int(env, cfg, CFG_AUTH, 0);
    cc.cert_mode = get_int(env, cfg, CFG_CERT_MODE, 0);
    cc.ca_file = cafile;
    cc.ca_dir = NULL;
    cc.server_name = sname;
    cc.verify_hostname = get_int(env, cfg, CFG_VERIFY_NAME, 1);
    cc.mtu = get_int(env, cfg, CFG_MTU, 1400);
    cc.keepalive_s = get_int(env, cfg, CFG_KEEPALIVE, 30);
    cc.reconnect_delay_s = get_int(env, cfg, CFG_RECONNECT, 5);
    cc.max_retries = get_int(env, cfg, CFG_MAX_RETRY, 3);
    cc.connect_timeout_s = get_int(env, cfg, CFG_CONN_TIMEOUT, 20);
    cc.io_timeout_s = get_int(env, cfg, CFG_IO_TIMEOUT, 20);
    cc.local_ip = lip;
    cc.dns1 = dns1;
    cc.dns2 = dns2;
    cc.log_level = get_int(env, cfg, CFG_LOG_LEVEL, 2);
    cc.tun_fd = -1; /* Android：等 PPP 拿到地址后再 attach */

    err[0] = '\0';
    h = vpn_capi_create_ex(&cc, NULL, jni_on_state, jni_on_stats, bridge, err, sizeof(err));
    if (!h) {
        if (bridge->cb)
            (*env)->DeleteGlobalRef(env, bridge->cb);
        free(bridge);
        return 0;
    }
    vpn_capi_set_log_callback(jni_on_log, bridge);
    return (jlong)(intptr_t)h;
}

JNIEXPORT jint JNICALL
Java_com_example_vpnclient_VpnCore_nativeStart(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return vpn_capi_start((vpn_handle)(intptr_t)handle);
}

JNIEXPORT jint JNICALL
Java_com_example_vpnclient_VpnCore_nativeWait(JNIEnv *env, jclass cls, jlong handle,
                                              jint timeout_ms)
{
    (void)env; (void)cls;
    return vpn_capi_wait((vpn_handle)(intptr_t)handle, timeout_ms);
}

JNIEXPORT jint JNICALL
Java_com_example_vpnclient_VpnCore_nativeAttachTunFd(JNIEnv *env, jclass cls, jlong handle,
                                                     jint fd)
{
    (void)env; (void)cls;
    return vpn_capi_attach_tun_fd((vpn_handle)(intptr_t)handle, fd);
}

JNIEXPORT jint JNICALL
Java_com_example_vpnclient_VpnCore_nativeState(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return vpn_capi_state((vpn_handle)(intptr_t)handle);
}

JNIEXPORT jobjectArray JNICALL
Java_com_example_vpnclient_VpnCore_nativeStatsText(JNIEnv *env, jclass cls, jlong handle)
{
    vpn_capi_stats st;
    jclass strcls;
    jobjectArray arr;
    int i;
    const char *vals[6];

    (void)cls;
    memset(&st, 0, sizeof(st));
    vpn_capi_get_stats((vpn_handle)(intptr_t)handle, &st);
    vals[0] = st.local_ip;
    vals[1] = st.peer_ip;
    vals[2] = st.dns1;
    vals[3] = st.dns2;
    vals[4] = st.cipher;
    vals[5] = st.cert_fingerprint;

    strcls = (*env)->FindClass(env, "java/lang/String");
    arr = (*env)->NewObjectArray(env, 6, strcls, NULL);
    for (i = 0; i < 6; i++) {
        jstring s = (*env)->NewStringUTF(env, vals[i]);
        (*env)->SetObjectArrayElement(env, arr, i, s);
        (*env)->DeleteLocalRef(env, s);
    }
    return arr;
}

/* 拆掉已挂接的 TUN（关闭 fd，系统随即撤销这条 VPN）。
 * 自动重连成功后地址会变，必须拆掉旧的重新 establish，否则
 * TUN 接口上还是上一个会话的地址，发出去的包源地址不对，服务器直接丢。 */
JNIEXPORT jboolean JNICALL
Java_com_example_vpnclient_VpnCore_nativeDetachTun(JNIEnv *env, jclass cls, jlong handle)
{
    vpn_handle h = (vpn_handle)(intptr_t)handle;
    (void)env; (void)cls;
    if (!h)
        return JNI_FALSE;
    vpn_capi_detach_tun(h);
    return JNI_TRUE;
}

JNIEXPORT void JNICALL
Java_com_example_vpnclient_VpnCore_nativeStop(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    vpn_capi_stop((vpn_handle)(intptr_t)handle);
}

JNIEXPORT void JNICALL
Java_com_example_vpnclient_VpnCore_nativeDestroy(JNIEnv *env, jclass cls, jlong handle)
{
    vpn_handle h = (vpn_handle)(intptr_t)handle;
    jni_bridge *b;
    (void)cls;
    if (!h)
        return;
    b = vpn_capi_user(h);
    vpn_capi_set_log_callback(NULL, NULL);
    vpn_capi_detach_tun(h);
    vpn_capi_destroy(h);
    if (b) {
        if (b->cb)
            (*env)->DeleteGlobalRef(env, b->cb);
        free(b);
    }
}

JNIEXPORT void JNICALL
Java_com_example_vpnclient_VpnCore_nativeSetLogLevel(JNIEnv *env, jclass cls, jint level)
{
    (void)env; (void)cls;
    vpn_capi_set_log_level(level);
}
