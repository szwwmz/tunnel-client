// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 wwm-spec. All rights reserved.

package com.example.vpnclient

import java.util.Locale

/**
 * 极简双语（简体中文 / 英文）。
 *
 * 不引入 androidx（本工程刻意只用系统 API），所以不用
 * AppCompatDelegate 那套 per-app language，直接跟随系统语言：
 * 系统是中文就给中文，其余一律英文。
 *
 * [zh] 用 getter 而不是 val，系统语言变更导致 Activity 重建后
 * 能立刻拿到新值（val 只在类初始化时求值一次）。
 */
object L {

    /** 作者，界面上"关于"和底部都会显示 */
    const val AUTHOR = "wwm <wwme@163.com>"

    val zh: Boolean
        get() = Locale.getDefault().language.startsWith("zh")

    fun t(zhText: String, enText: String): String = if (zh) zhText else enText
}
