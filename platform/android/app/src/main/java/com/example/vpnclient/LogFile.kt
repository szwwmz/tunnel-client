package com.example.vpnclient

import java.io.File

/**
 * 日志落盘副本。
 *
 * UiBus 的日志只存在内存里，进程一死（native 层崩溃、被系统杀）就全没了 ——
 * 下次打开界面一片空白，用户没法把现场发出来。这里把每行同时追加到
 * filesDir/session.log（超过 256KB 只保留后一半），启动时回填最后若干行。
 */
object LogFile {

    private const val NAME = "session.log"
    private const val LIMIT = 256 * 1024

    @Volatile
    private var file: File? = null

    fun init(dir: File) {
        file = File(dir, NAME)
    }

    @Synchronized
    fun append(line: String) {
        val f = file ?: return
        try {
            f.appendText(line + "\n")
            if (f.length() > LIMIT) {
                /* 只留后一半：崩溃现场几乎总在最近几百行里 */
                f.writeText(f.readText().takeLast(LIMIT / 2))
            }
        } catch (_: Throwable) {
            /* 落盘失败绝不能影响日志和界面 */
        }
    }

    /** 取最后 maxLines 行；没有文件返回空串 */
    fun tail(maxLines: Int = 200): String = try {
        val f = file
        if (f == null || !f.exists()) "" else
            f.readLines().takeLast(maxLines).joinToString("\n")
    } catch (_: Throwable) {
        ""
    }

    fun clear() {
        try {
            file?.delete()
        } catch (_: Throwable) {
        }
    }
}
