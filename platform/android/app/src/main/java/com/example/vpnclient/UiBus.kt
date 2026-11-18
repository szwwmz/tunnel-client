// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 wwm-spec. All rights reserved.

package com.example.vpnclient

import android.os.Handler
import android.os.Looper

/**
 * 界面与 VpnClientService 之间的进程内总线。
 *
 * 为何不用 BroadcastReceiver：客户端与 Service 同进程，广播要走系统调度、
 * 还要处理 Android 14 的导出标志；这里直接回调更简单，也避免日志在
 * 广播里被截断。所有回调统一切到主线程，UI 可直接更新控件。
 */
object UiBus {

    interface Listener {
        fun onState(state: Int, detail: String)
        fun onStats(rxBytes: Long, txBytes: Long, rxPkts: Long, txPkts: Long)
        fun onLogAppended()
    }

    private const val MAX_LINES = 1500

    private val main = Handler(Looper.getMainLooper())
    private val lines = ArrayDeque<String>()
    private val listeners = mutableListOf<Listener>()

    /** 已有一次待执行的重绘；高频日志只排队一次，避免把主线程消息队列淹没 */
    private var logPending = false

    @Volatile
    var state: Int = VpnCore.STATE_IDLE
        private set

    @Volatile
    var detail: String = ""
        private set

    @Volatile
    var rxBytes: Long = 0
    @Volatile
    var txBytes: Long = 0
    @Volatile
    var rxPkts: Long = 0
    @Volatile
    var txPkts: Long = 0

    fun register(l: Listener) {
        synchronized(listeners) { if (!listeners.contains(l)) listeners.add(l) }
    }

    fun unregister(l: Listener) {
        synchronized(listeners) { listeners.remove(l) }
    }

    fun logText(): String = synchronized(lines) { lines.joinToString("\n") }

    fun clearLogs() {
        LogFile.clear()
        synchronized(lines) { lines.clear() }
        main.post { snapshot().forEach { it.onLogAppended() } }
    }

    /** 与 Windows 端的级别标签保持一致（0=跟踪 1=调试 2=信息 3=警告 4=错误） */
    private fun tag(level: Int): String = when (level) {
        0 -> L.t("跟踪", "Trace")
        1 -> L.t("调试", "Debug")
        3 -> L.t("警告", "Warn")
        4 -> L.t("错误", "Error")
        else -> L.t("信息", "Info")
    }

    fun appendLog(level: Int, message: String) {
        if (message.isBlank()) return
        /* 带时间戳：崩溃后回看最后几条能对上"什么时候" */
        val ts = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
            .format(java.util.Date())
        val line = "[$ts][${tag(level)}] $message"
        LogFile.append(line)
        val schedule = synchronized(lines) {
            lines.addLast(line)
            while (lines.size > MAX_LINES) lines.removeFirst()
            if (logPending) false else { logPending = true; true }
        }
        if (schedule) {
            main.post {
                synchronized(lines) { logPending = false }
                snapshot().forEach { it.onLogAppended() }
            }
        }
    }

    /** 直接追加一段原文（用于回填上次会话日志），不重复落盘 */
    fun appendRaw(text: String) {
        if (text.isBlank()) return
        synchronized(lines) {
            text.split("\n").forEach {
                lines.addLast(it)
                while (lines.size > MAX_LINES) lines.removeFirst()
            }
        }
        main.post { snapshot().forEach { it.onLogAppended() } }
    }

    fun pushState(s: Int, d: String) {
        state = s
        detail = d
        main.post { snapshot().forEach { it.onState(s, d) } }
    }

    fun pushStats(rx: Long, tx: Long, rxp: Long, txp: Long) {
        rxBytes = rx; txBytes = tx; rxPkts = rxp; txPkts = txp
        main.post { snapshot().forEach { it.onStats(rx, tx, rxp, txp) } }
    }

    fun resetStats() {
        rxBytes = 0; txBytes = 0; rxPkts = 0; txPkts = 0
    }

    private fun snapshot(): List<Listener> = synchronized(listeners) { listeners.toList() }
}

/** 字节数的可读形式，与 Windows 端同一套单位 */
fun humanBytes(v: Long): String = when {
    v >= 1024L * 1024 * 1024 -> String.format("%.2f GB", v / 1024.0 / 1024 / 1024)
    v >= 1024L * 1024 -> String.format("%.2f MB", v / 1024.0 / 1024)
    v >= 1024L -> String.format("%.1f KB", v / 1024.0)
    else -> "$v B"
}
