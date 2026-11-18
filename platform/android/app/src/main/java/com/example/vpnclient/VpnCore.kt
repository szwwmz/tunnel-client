// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 wwm-spec. All rights reserved.

package com.example.vpnclient

import android.util.Log

/**
 * 核心库（libvpncore + JNI 桥）的 Kotlin 门面。
 *
 * 协议逻辑全部在 C 层，这里只做：
 *  1. 把 UI 配置打包成字符串数组传给 JNI；
 *  2. 暴露 start/stop/state/attachTun 给 VpnService；
 *  3. 把 C 层回调转成 Kotlin 回调。
 */
object VpnCore {

    init {
        System.loadLibrary("vpncore_jni")
    }

    /**
     * VpnService.protect 的注入点：由 [VpnClientService] 在 onCreate 里设置。
     * 核心在创建 TCP/UDP socket 后回调这里，把连接绑定到物理网卡，
     * 否则隧道建立后通往服务器的流量会被自己的路由捕获，连接立刻中断。
     */
    @Volatile
    private var protectHook: ((Int) -> Boolean)? = null

    fun setProtectHook(hook: ((Int) -> Boolean)?) {
        protectHook = hook
    }

    /** 供 JNI 调用（signature (I)Z），不要改名 */
    @JvmStatic
    fun protectSocket(fd: Int): Boolean = protectHook?.invoke(fd) ?: false

    const val STATE_IDLE = 0
    const val STATE_CONNECTING = 1
    const val STATE_AUTHENTICATING = 2
    const val STATE_CONNECTED = 3
    const val STATE_RECONNECTING = 4
    const val STATE_DISCONNECTED = 5
    const val STATE_FAILED = 6

    const val PROTO_SSTP = 0
    const val PROTO_L2TP = 1
    const val PROTO_PPTP = 2

    const val CERT_VERIFY = 0
    const val CERT_IGNORE = 1

    const val AUTH_MSCHAPV2 = 0
    const val AUTH_CHAP = 1
    const val AUTH_PAP = 2
    const val AUTH_AUTO = 3

    /** 与 vpn_jni.c 的 CFG_* 下标严格对应 */
    fun buildConfig(
        proto: Int,
        host: String,
        port: Int,
        user: String,
        pass: String,
        psk: String = "",
        auth: Int = AUTH_AUTO,
        certMode: Int = CERT_IGNORE,
        caFile: String = "",
        serverName: String = "",
        verifyHostname: Boolean = true,
        mtu: Int = 1400,
        keepalive: Int = 30,
        reconnectDelay: Int = 5,
        maxRetries: Int = 3,
        connectTimeout: Int = 20,
        ioTimeout: Int = 20,
        localIp: String = "",
        dns1: String = "",
        dns2: String = "",
        logLevel: Int = 2
    ): Array<String> = arrayOf(
        proto.toString(), host, port.toString(), user, pass, psk,
        auth.toString(), certMode.toString(), caFile, serverName,
        if (verifyHostname) "1" else "0",
        mtu.toString(), keepalive.toString(), reconnectDelay.toString(),
        maxRetries.toString(), connectTimeout.toString(), ioTimeout.toString(),
        localIp, dns1, dns2, logLevel.toString()
    )

    /** JNI 回调载体：方法名/签名必须与 vpn_jni.c 一致 */
    class NativeCallback(
        private val onStateChanged: (Int, String) -> Unit,
        private val onStatsChanged: (LongArray) -> Unit,
        private val onLogLine: (Int, String) -> Unit
    ) {
        @Suppress("unused")
        fun onState(state: Int, detail: String) = onStateChanged(state, detail)

        @Suppress("unused")
        fun onStats(values: LongArray) = onStatsChanged(values)

        @Suppress("unused")
        fun onLog(level: Int, message: String) = onLogLine(level, message)
    }

    external fun nativeCreate(cfg: Array<String>, callback: NativeCallback): Long
    external fun nativeStart(handle: Long): Int
    external fun nativeWait(handle: Long, timeoutMs: Int): Int
    external fun nativeAttachTunFd(handle: Long, fd: Int): Int
    external fun nativeDetachTun(handle: Long): Boolean
    external fun nativeState(handle: Long): Int
    external fun nativeStatsText(handle: Long): Array<String>
    external fun nativeStop(handle: Long)
    external fun nativeDestroy(handle: Long)
    external fun nativeSetLogLevel(level: Int)

    @Volatile
    private var handle: Long = 0

    /* stop/destroy 会 join 工作线程（最长十几秒），绝不能放在主线程做：
     * 放主线程轻则 ANR，重则 join 超时后对象被释放、线程还在用 —— 直接崩。
     * 这里串行排队执行。 */
    private val stopper = java.util.concurrent.Executors
        .newSingleThreadExecutor { r -> Thread(r, "vpncore-stop").apply { isDaemon = true } }

    /** 连接期信息：地址/对端/DNS/加密套件/证书指纹 */
    data class TunnelInfo(
        val localIp: String,
        val peerIp: String,
        val dns1: String,
        val dns2: String,
        val cipher: String,
        val certFingerprint: String
    )

    fun tunnelInfo(): TunnelInfo {
        if (handle == 0L) return TunnelInfo("", "", "", "", "", "")
        val a = nativeStatsText(handle)
        return TunnelInfo(
            a.getOrElse(0) { "" }, a.getOrElse(1) { "" }, a.getOrElse(2) { "" },
            a.getOrElse(3) { "" }, a.getOrElse(4) { "" }, a.getOrElse(5) { "" }
        )
    }

    val isRunning: Boolean get() = handle != 0L

    fun currentState(): Int = if (handle == 0L) STATE_IDLE else nativeState(handle)

    /**
     * 连接。回调 [onConnected] 时 PPP 已拿到地址，此时才能
     * VpnService.Builder.addAddress(...).establish()。
     */
    fun connect(
        cfg: Array<String>,
        onState: (Int, String) -> Unit,
        onStats: (LongArray) -> Unit = {},
        onLog: (Int, String) -> Unit = { l, m -> Log.println(l + 2, "vpncore", m) },
        onConnected: () -> Unit
    ): Boolean {
        disconnect()
        val cb = NativeCallback(onStateChanged = { state, detail ->
            onState(state, detail)
            if (state == STATE_CONNECTED) onConnected()
        }, onStatsChanged = onStats, onLogLine = onLog)

        handle = nativeCreate(cfg, cb)
        if (handle == 0L) {
            Log.e("vpncore", "nativeCreate failed (check server address / user name)")
            return false
        }
        nativeSetLogLevel(cfg.last().toIntOrNull() ?: 2)
        return nativeStart(handle) == 0
    }

    /** PPP 协商完成后把 VpnService 的 fd 交给核心（所有权转移，勿再 close） */
    fun attachTun(fd: Int): Boolean {
        if (handle == 0L) return false
        val rc = nativeAttachTunFd(handle, fd)
        if (rc != 0) Log.e("vpncore", "attachTun failed rc=$rc")
        return rc == 0
    }

    /** 拆掉当前 TUN（关闭 fd）；重连后要重新 establish 才能拿到新地址 */
    fun detachTun(): Boolean {
        val h = handle
        if (h == 0L) return false
        return nativeDetachTun(h)
    }

    fun disconnect() {
        val h = handle
        if (h == 0L) return
        /* 先摘掉 handle：之后再进来的调用（UI 刷新、二次 disconnect）
         * 立刻看到 0，不会去碰正在销毁的实例 */
        handle = 0L
        stopper.execute {
            nativeStop(h)
            nativeDestroy(h)
        }
    }
}
