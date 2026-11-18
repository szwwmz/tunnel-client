// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 wwm-spec. All rights reserved.

package com.example.vpnclient

import android.app.Application
import android.content.Context
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

/**
 * 进程入口。
 *
 * 手机上没有 logcat 时，崩溃只能靠"装一次闪一次"来猜。这里装一个未捕获
 * 异常处理器，把堆栈写到 filesDir/crash.log，下次启动由界面的日志区读出来
 * 展示（读一次即删），用户复制日志就能定位。
 */
class VpnApp : Application() {
    override fun onCreate() {
        super.onCreate()
        LogFile.init(filesDir)
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                val sw = StringWriter()
                e.printStackTrace(PrintWriter(sw))
                /* 崩溃现场 = 堆栈 + 崩溃前最后 200 行日志，
                 * 否则光有堆栈看不出当时在做什么 */
                File(filesDir, CRASH_FILE).writeText(
                    "thread=${t.name}\n${sw}\n--- 最后日志 ---\n${LogFile.tail(200)}"
                )
            } catch (_: Throwable) {
                /* 崩溃处理本身绝不能再抛 */
            }
            prev?.uncaughtException(t, e)
        }
    }
}

private const val CRASH_FILE = "crash.log"

object CrashLog {
    /** 取出上次的崩溃堆栈并删除文件；没有则返回空串 */
    fun take(ctx: Context): String = try {
        val f = File(ctx.filesDir, CRASH_FILE)
        if (!f.exists()) {
            ""
        } else {
            val text = f.readText()
            f.delete()
            text
        }
    } catch (_: Throwable) {
        ""
    }
}
