// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 wwm-spec. All rights reserved.

@file:Suppress("DEPRECATION")

package com.example.vpnclient

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log

/**
 * Android 外壳（VpnService）。
 *
 * SSS/L2TP/PPTP 的地址都是服务器在 IPCP 阶段分配的，而 VpnService.Builder
 * 必须先有地址才能 establish()。因此分两步：
 *   1. 核心以 "无 TUN" 模式跑协议栈，STATE_CONNECTED 时我们才拿到本机地址；
 *   2. 用该地址 build + establish，把 fd 交给核心（vpn_client_attach_tun）。
 */
class VpnClientService : VpnService() {

    companion object {
        private const val TAG = "VpnClientService"
        private const val CHANNEL_ID = "vpn_status"
        private const val NOTIFY_ID = 1001

        const val ACTION_START = "com.example.vpnclient.START"
        const val ACTION_STOP = "com.example.vpnclient.STOP"

        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_USER = "user"
        const val EXTRA_PASS = "pass"
        const val EXTRA_PROTO = "proto"
        const val EXTRA_CERT_MODE = "cert_mode"
        const val EXTRA_PSK = "psk"
        const val EXTRA_ROUTE_ALL = "route_all"
        const val EXTRA_VPNDNS = "vpndns"
        const val EXTRA_DEBUG = "debug"

        fun start(ctx: Context, host: String, port: Int, user: String, pass: String,
                  proto: Int = VpnCore.PROTO_SSTP, certMode: Int = VpnCore.CERT_IGNORE,
                  psk: String = "", routeAll: Boolean = true, vpnDns: Boolean = true,
                  debug: Boolean = false) {
            val i = Intent(ctx, VpnClientService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_HOST, host)
                putExtra(EXTRA_PORT, port)
                putExtra(EXTRA_USER, user)
                putExtra(EXTRA_PASS, pass)
                putExtra(EXTRA_PROTO, proto)
                putExtra(EXTRA_CERT_MODE, certMode)
                putExtra(EXTRA_PSK, psk)
                putExtra(EXTRA_ROUTE_ALL, routeAll)
                putExtra(EXTRA_VPNDNS, vpnDns)
                putExtra(EXTRA_DEBUG, debug)
            }
            ctx.startService(i)
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, VpnClientService::class.java).apply {
                action = ACTION_STOP
            })
        }
    }

    private val main = Handler(Looper.getMainLooper())

    /** 上次的连接参数：断网恢复后用它自动重连 */
    private data class ConnArgs(
        val host: String, val port: Int, val user: String, val pass: String,
        val proto: Int, val certMode: Int, val psk: String,
        val routeAll: Boolean, val vpnDns: Boolean, val debug: Boolean
    )

    @Volatile private var lastArgs: ConnArgs? = null
    /** 正在等网络恢复（此时不重试，等 onAvailable 再连） */
    @Volatile private var waitingNet = false
    private var netCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile private var stopping = false
    @Volatile private var tunnelEstablished = false
    @Volatile private var routeAll = true
    @Volatile private var vpnDns = true

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                shutdown()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                startFg(L.t("正在连接…", "Connecting…"))
                connect(
                    host = intent.getStringExtra(EXTRA_HOST) ?: "",
                    port = intent.getIntExtra(EXTRA_PORT, 0),
                    user = intent.getStringExtra(EXTRA_USER) ?: "",
                    pass = intent.getStringExtra(EXTRA_PASS) ?: "",
                    proto = intent.getIntExtra(EXTRA_PROTO, VpnCore.PROTO_PPTP),
                    certMode = intent.getIntExtra(EXTRA_CERT_MODE, VpnCore.CERT_VERIFY),
                    psk = intent.getStringExtra(EXTRA_PSK) ?: "",
                    routeAll = intent.getBooleanExtra(EXTRA_ROUTE_ALL, true),
                    vpnDns = intent.getBooleanExtra(EXTRA_VPNDNS, true),
                    debug = intent.getBooleanExtra(EXTRA_DEBUG, false)
                )
            }
        }
        return START_STICKY
    }

    private fun connect(host: String, port: Int, user: String, pass: String,
                        proto: Int, certMode: Int, psk: String,
                        routeAll: Boolean, vpnDns: Boolean, debug: Boolean) {
        if (host.isBlank() || user.isBlank()) {
            notify(L.t("服务器/用户名不能为空", "Server/username must not be empty"))
            stopSelf()
            return
        }
        stopping = false
        tunnelEstablished = false
        waitingNet = false
        this.routeAll = routeAll
        this.vpnDns = vpnDns
        lastArgs = ConnArgs(host, port, user, pass, proto, certMode, psk,
                            routeAll, vpnDns, debug)

        /* 只有用户真放了 ca.pem 且选了严格校验才传给核心；
         * 以前无条件塞路径，文件不存在时核心直接报
         * "加载自定义 CA 失败" 并放弃握手，白建一次连接 */
        val caPath = filesDir.resolve("ca.pem").let {
            if (certMode == VpnCore.CERT_VERIFY && it.exists()) it.absolutePath else ""
        }
        val cfg = VpnCore.buildConfig(
            proto = proto,
            host = host,
            port = port,
            user = user,
            pass = pass,
            psk = psk,
            certMode = certMode,
            caFile = caPath,
            /* 与 Windows 端一致：默认 INFO(2)，ini/开关打开才给 DEBUG(1) */
            logLevel = if (debug) 1 else 2
        )

        val ok = VpnCore.connect(
            cfg = cfg,
            onState = { state, detail -> onStateChanged(state, detail) },
            onStats = { v ->
                UiBus.pushStats(v[0], v[1], v[2], v[3])
            },
            onLog = { level, msg -> UiBus.appendLog(level, msg) },
            onConnected = { establishTunnel() }
        )
        if (!ok) {
            notify(L.t("连接失败", "Connection failed"))
            stopSelf()
        }
    }

    /**
     * 拆掉系统隧道。
     *
     * 自动重连时核心会重新协商 PPP，服务器重新分配的地址也变了
     * （日志里 10.10.5.72 → 10.10.5.68）。原来那个 TUN 接口上是旧地址，
     * 什么都不做的话：应用发出的包源地址仍是旧地址，服务器按会话直接丢弃，
     * 表现就是"自动重连成功、界面显示已连接，但数据完全不通；
     * 手动断开再连又一切正常"（手动那次走的是 nativeDestroy，顺带把
     * 旧 TUN 拆了）。
     */
    private fun closeTunnel() {
        if (!tunnelEstablished) return
        tunnelEstablished = false
        VpnCore.detachTun()
    }

    /** PPP 已 up：此刻用真实分配到的地址建立系统隧道 */
    private fun establishTunnel() {
        if (stopping) return
        /* 每次 PPP up 都重建：地址可能是新的，旧接口必须拆掉 */
        closeTunnel()
        tunnelEstablished = true

        val info = VpnCore.tunnelInfo()
        val addr = if (info.localIp.isNotBlank()) info.localIp else "10.111.222.2"

        if (VpnService.prepare(this) != null) {
            notify(L.t("需要 VPN 授权", "VPN permission required"))
            stopSelf()
            return
        }

        try {
            val builder = Builder()
                .setSession(L.t("VPN 客户端", "VPN Client"))
                .setMtu(1400)
                .addAddress(addr, 32)
                .setBlocking(false)

            /* 路由范围与 Windows 端同语义：
             *   routeAll=1 → 0.0.0.0/0（全部流量进隧道）
             *   routeAll=0 → 只接管三个私有网段，公网直连 */
            if (routeAll) {
                builder.addRoute("0.0.0.0", 0)
            } else {
                builder.addRoute("10.0.0.0", 8)
                builder.addRoute("172.16.0.0", 12)
                builder.addRoute("192.168.0.0", 16)
            }

            /* 把自己这个应用的流量整体排除在 VPN 之外。
             * protect() 已经保护了隧道 socket，但那是逐 fd 的、依赖 JNI 回调
             * 真的生效；一旦漏掉，0.0.0.0/0 会把我们发往服务器的 UDP 也吸进
             * TUN，表现就是连上之后一路 "PPP: 发送帧失败（i/o error）"。
             * 这里按包名整体排除，作为兜底（本应用没有其它需要走隧道的流量） */
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "addDisallowedApplication failed", e)
            }
            /* DNS 只在服务器下发了地址时才接管，否则会把自己配的
             * 1.1.1.1 塞进隧道，断网后解析全部失败 */
            if (vpnDns) {
                if (info.dns1.isNotBlank()) builder.addDnsServer(info.dns1)
                if (info.dns2.isNotBlank()) builder.addDnsServer(info.dns2)
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            val pfd = builder.establish() ?: throw IllegalStateException("establish() returned null")
            val fd = pfd.detachFd() // 所有权转移给核心，核心负责 close
            pfd.close()

            if (!VpnCore.attachTun(fd)) {
                notify(L.t("挂接 TUN 失败", "Failed to attach TUN"))
                stopSelf()
                return
            }
            notify(L.t("已连接 · $addr", "Connected · $addr"))
            Log.i(TAG, "tunnel established addr=$addr")
        } catch (e: Exception) {
            Log.e(TAG, "failed to establish the tunnel", e)
            notify(L.t("建立隧道失败：${e.message}", "Tunnel setup failed: ${e.message}"))
            stopSelf()
        }
    }

    private fun onStateChanged(state: Int, detail: String) {
        Log.i(TAG, "state=$state $detail")
        UiBus.pushState(state, detail)
        /* 进入重连态就立刻拆隧道：旧 TUN 里已经没有任何人读写，
         * 留着只会把全系统的流量吸进黑洞（界面看着"已连接"，实际全断） */
        if (state == VpnCore.STATE_RECONNECTING ||
            state == VpnCore.STATE_FAILED ||
            state == VpnCore.STATE_DISCONNECTED
        ) {
            if (!stopping) closeTunnel()
        }
        main.post {
            when (state) {
                VpnCore.STATE_CONNECTING -> notify(L.t("正在连接…", "Connecting…"))
                VpnCore.STATE_AUTHENTICATING -> notify(L.t("认证中…", "Authenticating…"))
                VpnCore.STATE_RECONNECTING -> notify(L.t("重连中…", "Reconnecting…"))
                VpnCore.STATE_FAILED -> {
                    notify(L.t("连接失败：$detail", "Connection failed: $detail"))
                    stopSelf()
                }
                VpnCore.STATE_DISCONNECTED -> if (!stopping) notify(
                    L.t("已断开", "Disconnected"))
            }
        }
    }

    /**
     * 监听系统默认网络。
     *
     * 核心的 L2TP 走 UDP：WiFi 掉了以后 socket 不会报"连接关闭"，
     * 只会在 send 上反复失败，界面就一直停在"已连接"。
     * 这里用系统回调第一时间感知，断网即拆会话、恢复即自动重连。
     */
    private fun watchNetwork() {
        if (netCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) {
                if (stopping || lastArgs == null) return
                main.post { onNetworkLost() }
            }

            override fun onAvailable(network: Network) {
                if (stopping || lastArgs == null) return
                /* 留一点时间等接口真正可用（切网时 onAvailable 常早于路由就绪） */
                main.postDelayed({ onNetworkBack() }, 800)
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            netCallback = cb
        } catch (e: Exception) {
            Log.w(TAG, "failed to register the network callback", e)
        }
    }

    private fun onNetworkLost() {
        if (stopping || waitingNet) return
        waitingNet = true
        /* 先同步拆掉系统隧道：关闭 fd 系统就撤销这条 VPN，
         * 800ms 后重连时 establish 才不会和旧接口撞上。
         * 以前只把标志位清零而不关 fd，旧接口会一直挂到后台的
         * destroy 线程跑完，切网后偶发"连上了但不通" */
        closeTunnel()
        VpnCore.disconnect()
        UiBus.appendLog(Log.WARN,
            L.t("系统网络已断开，等待恢复…", "Network lost, waiting…"))
        UiBus.pushState(VpnCore.STATE_RECONNECTING,
            L.t("网络已断开，恢复后自动重连", "Network lost; will reconnect when it is back"))
        UiBus.pushStats(0, 0, 0, 0)
        notify(L.t("网络已断开，等待恢复…", "Network lost, waiting…"))
    }

    private fun onNetworkBack() {
        if (stopping || !waitingNet) return
        val a = lastArgs ?: return
        waitingNet = false
        UiBus.appendLog(Log.INFO,
            L.t("网络已恢复，重新连接…", "Network is back, reconnecting…"))
        connect(a.host, a.port, a.user, a.pass, a.proto, a.certMode, a.psk,
                a.routeAll, a.vpnDns, a.debug)
    }

    /** Android 14 起前台服务必须给出类型，且要与清单里的
     *  foregroundServiceType 一致，否则进程会被直接杀掉 */
    private fun startFg(text: String) {
        val n = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFY_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFY_ID, n)
        }
    }

    private fun shutdown() {
        stopping = true
        closeTunnel()
        VpnCore.disconnect()
        UiBus.pushState(VpnCore.STATE_DISCONNECTED, L.t("已断开", "Disconnected"))
        stopForeground(true)
        stopSelf()
    }

    override fun onCreate() {
        super.onCreate()
        // 核心创建 socket 后回调这里，把服务器连接钉在物理网卡上
        VpnCore.setProtectHook { fd -> protect(fd) }
        // WiFi / 移动网络断开与恢复
        watchNetwork()
    }

    override fun onDestroy() {
        netCallback?.let { cb ->
            runCatching {
                getSystemService(ConnectivityManager::class.java)
                    ?.unregisterNetworkCallback(cb)
            }
        }
        netCallback = null
        VpnCore.setProtectHook(null)
        VpnCore.disconnect()
        super.onDestroy()
    }

    override fun onRevoke() {
        shutdown()
        super.onRevoke()
    }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, L.t("VPN 状态", "VPN status"),
                    NotificationManager.IMPORTANCE_LOW)
            )
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle(L.t("VPN 客户端", "VPN Client"))
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(pi)
                .setOngoing(true)
                .build()
        } else {
            Notification.Builder(this)
                .setContentTitle(L.t("VPN 客户端", "VPN Client"))
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(pi)
                .setOngoing(true)
                .build()
        }
    }

    private fun notify(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFY_ID, buildNotification(text))
    }
}
