// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 wwm-spec. All rights reserved.

@file:Suppress("DEPRECATION")

package com.example.vpnclient

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Bundle
import android.text.InputType
import android.view.inputmethod.InputMethodManager
import android.text.method.ScrollingMovementMethod
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.ArrayAdapter
import android.widget.TextView
import android.widget.Toast

/**
 * 连接界面。
 *
 * 与 Windows 版保持同一套交互：协议/地址/端口/账号/预共享密钥、路由与 DNS 接管
 * 开关、调试日志开关、状态与实时收发统计、日志区（清空/复制）、版本说明。
 * 配置保存在 SharedPreferences 里（对应 Windows 的 vpn-gui.ini）。
 */
class MainActivity : Activity(), UiBus.Listener {

    companion object {
        const val VERSION = "1.4.0"

        private const val PREFS = "vpn-gui"
        private const val REQ_VPN = 100
        private const val REQ_NOTIFY = 101

        /* PPTP 的数据面要 GRE(IP 协议 47) 原始套接字，未 root 的 Android
         * 建不出来，所以不显示。
         * L2TP 则要看是否套 IPsec：
         *   · 不带 IPsec（RFC 2661）只走普通 UDP 1701 —— 可用
         *   · 带 IPsec 时 ESP 需要原始套接字 —— 不可用
         * 所以保留 L2TP，但界面明确标注"无 IPsec"，服务端必须关掉 IPsec。 */
        /* 用 getter 而不是常量：系统语言切换后 Activity 重建即可刷新文案 */
        private val PROTO_NAMES get() =
            arrayOf("SSTP", L.t("L2TP（无 IPsec）", "L2TP (no IPsec)"))
        private val PROTO_IDS = intArrayOf(VpnCore.PROTO_SSTP, VpnCore.PROTO_L2TP)
        private val DEFAULT_PORTS = intArrayOf(443, 1701)

        /* 证书策略：RouterOS 等服务器多用自签证书，而 Android 上没有 OpenSSL
         * 的默认 CA 路径，严格校验必然 tls error，所以默认跳过校验。 */
        private val CERT_NAMES get() = arrayOf(
            L.t("跳过校验（自签证书，推荐）", "Skip verification (self-signed, recommended)"),
            L.t("严格校验（需 ca.pem）", "Strict verification (needs ca.pem)"))
        private val CERT_MODES = intArrayOf(VpnCore.CERT_IGNORE, VpnCore.CERT_VERIFY)
    }

    private lateinit var protoSpinner: Spinner
    private lateinit var certSpinner: Spinner
    private lateinit var certRow: LinearLayout
    private lateinit var hostInput: EditText
    private lateinit var portInput: EditText
    private lateinit var userInput: EditText
    private lateinit var passInput: EditText
    private lateinit var routeAllBox: CheckBox
    private lateinit var vpnDnsBox: CheckBox
    private lateinit var debugBox: CheckBox
    private lateinit var warnText: TextView
    private lateinit var statusText: TextView
    private lateinit var statsText: TextView
    private lateinit var logText: TextView
    private lateinit var btnConnect: Button
    private lateinit var btnDisconnect: Button
    private lateinit var scroll: ScrollView

    private val prefs by lazy { getSharedPreferences(PREFS, Context.MODE_PRIVATE) }

    @Deprecated("仅为了不引入 androidx 依赖")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) doConnect() else toast(L.t("未授权 VPN，无法建立隧道","VPN permission denied, cannot create the tunnel"))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildUi())
        loadPrefs()

        /* 上次若闪退过，把堆栈贴到日志区（读一次即删），
         * 用户点"复制日志"就能把现场发出来 */
        val crash = CrashLog.take(this)
        if (crash.isNotBlank()) {
            UiBus.appendLog(4, L.t(
                "上次运行崩溃，堆栈如下（可点“复制日志”反馈）：\n$crash",
                "Previous run crashed, stack trace below (tap \"Copy log\" to report):\n$crash"))
        } else {
            /* 没有 Java 堆栈说明是 native 层直接死掉（或进程被系统杀掉），
             * 这时只能靠落盘的最后几行判断死在哪一步 */
            val prev = LogFile.tail(200)
            if (prev.isNotBlank()) {
                UiBus.appendRaw(L.t(
                    "—— 上次会话的最后日志（进程异常退出前的记录）——",
                    "—— tail of the last session (before the process died) ——"))
                UiBus.appendRaw(prev)
            }
        }

        /* Android 13+ 需要运行时授予通知权限，否则前台服务的通知不显示
         *（服务照常运行，只是状态栏看不到） */
        if (android.os.Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFY)
        }

        renderState(UiBus.state, UiBus.detail)
        refreshLog(scrollToEnd = true)
    }

    override fun onResume() {
        super.onResume()
        UiBus.register(this)
        renderState(UiBus.state, UiBus.detail)
        refreshLog(scrollToEnd = true)
    }

    override fun onPause() {
        UiBus.unregister(this)
        super.onPause()
    }

    // ---------------- 界面构建 ----------------

    private fun buildUi(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(16))
        }

        root.addView(TextView(this).apply {
            text = L.t("VPN 客户端", "VPN Client")
            textSize = 20f
            setTypeface(typeface, Typeface.BOLD)
        })
        root.addView(TextView(this).apply {
            text = L.t("v$VERSION · 协议 SSTP / L2TP",
                       "v$VERSION · SSTP / L2TP protocols")
            textSize = 12f
            setTextColor(Color.GRAY)
            setPadding(0, dp(2), 0, dp(10))
        })

        // 协议
        protoSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity,
                android.R.layout.simple_spinner_dropdown_item, PROTO_NAMES)
            onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, v: View?, pos: Int, id: Long) {
                    applyProtoDefaults(pos)
                }
                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
            }
        }
        root.addView(label(L.t("协议", "Protocol")))
        root.addView(protoSpinner)

        certSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity,
                android.R.layout.simple_spinner_dropdown_item, CERT_NAMES)
            onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, v: View?, pos: Int, id: Long) {
                    updateCertHint()
                }
                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
            }
        }
        certRow = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(label(L.t("证书校验（仅 SSTP）", "Certificate check (SSTP only)")))
            addView(certSpinner)
        }
        root.addView(certRow)
        warnText = TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(4), 0, 0)
        }
        root.addView(warnText)

        hostInput = EditText(this).apply {
            hint = L.t("服务器地址 / 域名", "Server address / hostname")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        }
        portInput = EditText(this).apply {
            hint = L.t("端口（留空 = 默认 443）", "Port (blank = 443)")
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        userInput = EditText(this).apply { hint = L.t("用户名", "Username") }
        passInput = EditText(this).apply {
            hint = L.t("密码", "Password")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        root.addView(label(L.t("服务器", "Server")))
        root.addView(hostInput)
        root.addView(portInput)
        root.addView(userInput)
        root.addView(passInput)

        // 选项
        routeAllBox = CheckBox(this).apply {
            text = L.t("接管全部流量（不勾则只接管私有网段）",
                       "Route all traffic (off: private ranges only)")
        }
        vpnDnsBox = CheckBox(this).apply { text = L.t("接管 DNS", "Use VPN DNS") }
        debugBox = CheckBox(this).apply {
            text = L.t("输出调试日志（排障用，默认关闭）",
                       "Debug logs (troubleshooting, off by default)")
        }
        root.addView(optionGroup())

        // 连接按钮
        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(8), 0, dp(4))
        }
        btnConnect = Button(this).apply {
            text = L.t("连接", "Connect")
            setOnClickListener { savePrefs(); startConnect() }
        }
        btnDisconnect = Button(this).apply {
            text = L.t("断开", "Disconnect")
            setOnClickListener {
                VpnClientService.stop(this@MainActivity)
                renderState(VpnCore.STATE_DISCONNECTED, L.t("已断开", "Disconnected"))
            }
        }
        btnRow.addView(btnConnect, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        btnRow.addView(btnDisconnect, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(btnRow)

        val about = Button(this).apply {
            text = L.t("版本说明", "Release notes")
            setOnClickListener { showAbout() }
        }
        root.addView(about)

        // 状态
        statusText = TextView(this).apply {
            text = L.t("未连接", "Not connected")
            textSize = 14f
            setPadding(0, dp(8), 0, 0)
        }
        statsText = TextView(this).apply {
            text = L.t("收发 0 B / 0 B", "Traffic 0 B / 0 B")
            textSize = 12f
            setTextColor(Color.GRAY)
        }
        root.addView(statusText)
        root.addView(statsText)

        // 日志
        val logBtnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(10), 0, dp(4))
        }
        logBtnRow.addView(Button(this).apply {
            text = L.t("清空日志", "Clear log")
            setOnClickListener {
                UiBus.clearLogs()
                toast(L.t("日志已清空", "Log cleared"))
            }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        logBtnRow.addView(Button(this).apply {
            text = L.t("复制日志", "Copy log")
            setOnClickListener { copyLog() }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(logBtnRow)

        logText = TextView(this).apply {
            textSize = 11f
            typeface = Typeface.MONOSPACE
            movementMethod = ScrollingMovementMethod()
            setBackgroundColor(Color.parseColor("#F5F5F5"))
            setPadding(dp(8), dp(8), dp(8), dp(8))
        }
        scroll = ScrollView(this).apply {
            addView(logText)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(220))
        }
        root.addView(scroll)

        root.addView(TextView(this).apply {
            text = L.t("作者：", "Author: ") + L.AUTHOR
            textSize = 11f
            setTextColor(Color.GRAY)
            setPadding(0, dp(14), 0, 0)
        })

        val wrapper = ScrollView(this).apply { addView(root) }
        return wrapper
    }

    private fun optionGroup(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, dp(8), 0, 0)
        addView(routeAllBox)
        addView(vpnDnsBox)
        addView(debugBox)
    }

    private fun label(t: String): TextView = TextView(this).apply {
        text = t
        textSize = 12f
        setTextColor(Color.GRAY)
        setPadding(0, dp(8), 0, 0)
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    // ---------------- 配置持久化 ----------------

    private fun loadPrefs() {
        hostInput.setText(prefs.getString("host", ""))
        portInput.setText(prefs.getString("port", ""))
        userInput.setText(prefs.getString("user", ""))
        passInput.setText(prefs.getString("pass", ""))
        routeAllBox.isChecked = prefs.getBoolean("routeall", true)
        vpnDnsBox.isChecked = prefs.getBoolean("vpndns", true)
        debugBox.isChecked = prefs.getBoolean("debug", false)

        val proto = prefs.getInt("proto", VpnCore.PROTO_SSTP)
        val idx = PROTO_IDS.indexOf(proto).takeIf { it >= 0 } ?: 0
        protoSpinner.setSelection(idx, false)
        applyProtoDefaults(idx)

        /* 旧配置可能存着已下线的 PPTP(0)/L2TP(1)，indexOf 兜住后回落默认 */
        val cert = prefs.getInt("certmode", VpnCore.CERT_IGNORE)
        certSpinner.setSelection(CERT_MODES.indexOf(cert).takeIf { it >= 0 } ?: 0, false)
        updateCertHint()
    }

    private fun savePrefs() {
        prefs.edit()
            .putString("host", hostInput.text.toString().trim())
            .putString("port", portInput.text.toString().trim())
            .putString("user", userInput.text.toString().trim())
            .putString("pass", passInput.text.toString())
            .putInt("proto", PROTO_IDS[protoSpinner.selectedItemPosition])
            .putInt("certmode", CERT_MODES[certSpinner.selectedItemPosition])
            .putBoolean("routeall", routeAllBox.isChecked)
            .putBoolean("vpndns", vpnDnsBox.isChecked)
            .putBoolean("debug", debugBox.isChecked)
            .apply()
    }

    private fun applyProtoDefaults(pos: Int) {
        if (!::portInput.isInitialized) return

        val sstp = PROTO_IDS[pos] == VpnCore.PROTO_SSTP

        /* 纯 L2TP 的端口由核心固定成 UDP/1701（不接受自定义），
         * 留一个填了也不生效的输入框只会误导，直接隐藏；
         * SSTP 才需要用户填端口（留空 = 443） */
        portInput.visibility = if (sstp) View.VISIBLE else View.GONE
        if (sstp) {
            portInput.hint = L.t("端口（留空 = 默认 443）", "Port (blank = 443)")
        }

        if (!::certRow.isInitialized || !::warnText.isInitialized) return

        certRow.visibility = if (sstp) View.VISIBLE else View.GONE

        if (sstp) {
            updateCertHint()
        } else {
            warnText.text = L.t(
                "L2TP 不带 IPsec 时只走 UDP 1701，不涉及证书。" +
                    "服务器必须关闭 IPsec（RouterOS：/interface l2tp-server server " +
                    "set use-ipsec=no），并放行 UDP 1701；此模式不加密。",
                "Plain L2TP uses UDP 1701 only and no certificates. The server must " +
                    "disable IPsec (RouterOS: /interface l2tp-server server set " +
                    "use-ipsec=no) and allow UDP 1701. This mode is not encrypted.")
            warnText.setTextColor(Color.parseColor("#B45309"))
        }
    }

    /** 证书策略提示：严格校验时只有 ca.pem 真存在才会用上，
     *  否则连接必然 tls error，必须提前说清楚 */
    private fun updateCertHint() {
        if (!::warnText.isInitialized || !::certSpinner.isInitialized) return
        /* L2TP 下证书策略不适用，别把提示文案覆盖掉 */
        if (::certRow.isInitialized && certRow.visibility != View.VISIBLE) return
        val strict = CERT_MODES[certSpinner.selectedItemPosition] == VpnCore.CERT_VERIFY
        val caFile = java.io.File(filesDir, "ca.pem")
        when {
            !strict -> {
                warnText.text = L.t(
                    "不校验证书：适合自签证书服务器（通道仍加密，但不验证服务器身份）",
                    "No certificate check: for self-signed servers " +
                        "(traffic is still encrypted, but the server is not authenticated)")
                warnText.setTextColor(Color.parseColor("#4B5563"))
            }
            caFile.exists() -> {
                warnText.text = L.t("严格校验：使用 ${caFile.absolutePath}",
                                    "Strict verification: using ${caFile.absolutePath}")
                warnText.setTextColor(Color.parseColor("#4B5563"))
            }
            else -> {
                warnText.text = L.t(
                    "严格校验需要 ${caFile.absolutePath}，当前不存在，连接会失败",
                    "Strict verification needs ${caFile.absolutePath}, " +
                        "which does not exist; the connection will fail")
                warnText.setTextColor(Color.parseColor("#C62828"))
            }
        }
    }

    // ---------------- 动作 ----------------

    private fun startConnect() {
        val host = hostInput.text.toString().trim()
        val user = userInput.text.toString().trim()
        if (host.isEmpty() || user.isEmpty()) {
            toast(L.t("请填写服务器与用户名", "Please fill in server and username"))
            return
        }
        val it = VpnService.prepare(this)
        if (it != null) startActivityForResult(it, REQ_VPN) else doConnect()
    }

    private fun doConnect() {
        val proto = PROTO_IDS[protoSpinner.selectedItemPosition]
        /* L2TP 传 0：核心按协议固定用 UDP/1701，不看这个值；
         * SSTP 才取输入框（空 = 443） */
        val port = if (proto == VpnCore.PROTO_L2TP) {
            0
        } else {
            portInput.text.toString().trim().toIntOrNull() ?: 0
        }
        UiBus.clearLogs()
        UiBus.pushState(VpnCore.STATE_CONNECTING, L.t("正在连接…", "Connecting…"))
        VpnClientService.start(
            ctx = this,
            host = hostInput.text.toString().trim(),
            port = port,
            user = userInput.text.toString().trim(),
            pass = passInput.text.toString(),
            proto = proto,
            certMode = CERT_MODES[certSpinner.selectedItemPosition],
            routeAll = routeAllBox.isChecked,
            vpnDns = vpnDnsBox.isChecked,
            debug = debugBox.isChecked
        )
    }

    private fun copyLog() {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(
            L.t("VPN 日志", "VPN log"), UiBus.logText()))
        toast(L.t("日志已复制", "Log copied"))
    }

    private fun showAbout() {
        val zhNotes =
            "v$VERSION\n" +
            "  · 三端版本号统一为 1.4.0（Windows 端本版新增界面中英双语切换）\n" +
            "  · 作者信息更新为 wwm &lt;wwme@163.com&gt;\n" +
            "  · 连接日志、CLI 帮助与错误提示统一改为英文（界面文案仍中英双语）\n" +
            "  · 修复 CALL_CONNECTED 原地构造时 memcpy 源目标重叠（未定义行为，\n" +
            "    gcc -Wrestrict 报警）；改为 memmove 并补回归用例\n" +
            "  · 修复 L2TP/IPsec 域名拷贝被静默截断（IKE host 64 → 256 字节）\n" +
            "  · 合规：随包提供第三方组件声明（Wintun / OpenSSL / NDK / Kotlin），\n" +
            "    许可全文见「第三方组件」按钮，与 Windows 包内的 NOTICES 一致\n" +
            "  · 合规：源文件补充 SPDX 许可标识与版权头；应用图标确认自绘原创\n" +
            "  · 新增中英文双语：跟随系统语言，界面、通知、状态全部切换\n" +
            "  · 界面与“关于”显示作者：${L.AUTHOR}\n" +
            "  · 恢复 L2TP（无 IPsec）：只走 UDP 1701，用普通 UDP socket，\n" +
            "    不需要原始套接字，Android 可用。服务器需关闭 IPsec\n" +
            "    （RouterOS：/interface l2tp-server server set use-ipsec=no）\n" +
            "    并放行 UDP 1701；该模式不加密。PPTP 仍不显示（GRE 47 需 root）\n" +
            "  · 选 L2TP 时自动隐藏证书校验，它只对 SSTP 有意义\n" +
            "  · 选 L2TP 时同时隐藏端口输入框：纯 L2TP 固定走 UDP 1701\n" +
            "  · SCCRQ 增加 2 秒 RTO 重传（最多 5 次），超时提示里带重传次数，\n" +
            "    便于区分\"服务端根本没回\"和\"链路丢包\"\n" +
            "  · 修复自动重连后数据不通：重连成功时服务器会重新分配地址，\n" +
            "    现在每次都拆掉旧 TUN 并按新地址重建（以前只有第一次会建，\n" +
            "    TUN 接口上一直是旧地址，发出去的包源地址不对，服务器直接丢弃；\n" +
            "    手动断开重连能好，是因为那条路径顺带把旧 TUN 拆了）\n" +
            "  · 进入重连态立即拆除旧隧道，重连期间不再把流量吸进没人读的 TUN\n" +
            "  · 日志落盘：每行同步写 filesDir/session.log（>256KB 只留后一半），\n" +
            "    进程异常退出后重开能看到上次会话的最后 200 行\n" +
            "  · 修复退出/断开时的崩溃：工作线程没在超时内退出时不再释放客户端对象\n" +
            "    （以前会 free 掉线程仍在使用的内存，native 段错误，Java 崩溃处理器\n" +
            "    也抓不到，表现是：用着用着直接退出、重开没有日志）\n" +
            "  · stop/destroy 移到后台线程，避免主线程被 join 卡住\n" +
            "  · 连接中/已连接时锁定服务器、账号、协议等所有配置项\n" +
            "  · 流量统计修复：核心改为每秒上抛一次收发统计（以前只在连上那一刻\n" +
            "    发一次，界面数字永远停在 0，看起来像应用卡死）\n" +
            "  · 日志重绘合并，刷屏时不再把主线程消息队列淹没\n" +
            "  · 断网检测：监听系统默认网络，WiFi/移动网络断开时立即提示\"网络已断开\"\n" +
            "    并拆掉会话，恢复后自动重连；同时核心按发送连续性兜底判定链路中断\n" +
            "\n" +
            "v1.3.4\n" +
            "  · 修复连接成功但数据不通：核心事件循环在连接前只快照了一次 TUN，\n" +
            "    而 Android 必须先完成 PPP 拿到地址才能 establish()，TUN 是连接\n" +
            "    成功后才挂上的，于是整个会话 tun.read 恒为空，上行一个包都不读。\n" +
            "    现在每轮循环重新取快照\n" +
            "\n" +
            "v1.3.3\n" +
            "  · SSTP 支持跳过证书校验（自签证书服务器）\n" +
            "  · 只有 ca.pem 真存在才传给核心\n" +
            "\n" +
            "v1.3.2\n" +
            "  · 修复点连接即闪退（Android 14 前台服务类型）\n"

        val enNotes =
            "v$VERSION\n" +
            "  · Version aligned across all three platforms (1.4.0); the Windows\n" +
            "    build adds a Chinese/English UI switch in this release\n" +
            "  · Author updated to wwm <wwme@163.com>\n" +
            "  · Connection logs, CLI help and error messages are now English-only" +
            "    (the UI stays bilingual)\n" +
            "  · Fixed UB: in-place memcpy overlap when building CALL_CONNECTED" +
            "    (gcc -Wrestrict); switched to memmove plus a regression test\n" +
            "  · Fixed silent truncation of long L2TP/IPsec host names" +
            "    (IKE host 64 -> 256 bytes)\n" +
            "  · Compliance: third-party notices (Wintun / OpenSSL / NDK /" +
            "    Kotlin) now ship with the package, viewable via the" +
            "    \"Third-party\" button and identical to the Windows NOTICES\n" +
            "  · Compliance: SPDX identifiers and copyright headers added to" +
            "    all sources; the app icon is confirmed to be original work\n" +
            "  · Chinese/English UI, follows the system language" +
            "    (screens, notifications, states)\n" +
            "  · Author shown on screen and in this dialog: ${L.AUTHOR}\n" +
            "  · Restored L2TP without IPsec: plain UDP 1701 over a normal UDP" +
            "    socket, no raw socket needed, so it works on Android. The server" +
            "    must disable IPsec (RouterOS: /interface l2tp-server server set" +
            "    use-ipsec=no) and allow UDP 1701. This mode is not encrypted." +
            "    PPTP is still hidden (GRE 47 needs root).\n" +
            "  · Certificate check is hidden for L2TP, it only applies to SSTP\n" +
            "  · Port field is hidden for L2TP too: plain L2TP always uses UDP 1701\n" +
            "  · SCCRQ now retransmits every 2s (up to 5 times); the timeout " +
            "message reports the retry count\n" +
            "  · Fixed 'no data after auto-reconnect': the server assigns a new\n" +
            "    address on every re-negotiation, so the TUN is now re-established\n" +
            "    each time (previously only on the first connect, leaving stale\n" +
            "    addresses on the interface and packets dropped by the server)\n" +
            "  · Old tunnel is torn down as soon as reconnecting starts\n" +
            "  · Logs are mirrored to filesDir/session.log; after an abnormal exit\n" +
            "    the next launch shows the last 200 lines of the previous session\n" +
            "  · Fixed a native crash on disconnect: the client object is no longer\n" +
            "    freed while its worker thread is still alive\n" +
            "  · stop/destroy moved off the main thread\n" +
            "  · All configuration inputs are locked while connecting/connected\n" +
            "  · Traffic stats fixed: the core now publishes counters once per " +
            "second (it used to publish only at connect time, so the numbers " +
            "stayed at 0 and the app looked frozen)\n" +
            "  · Log repaint coalescing\n" +
            "  · Network loss detection: watches the default network, reports " +
            "\"Network lost\" and drops the session, reconnects automatically\n" +
            "\n" +
            "v1.3.4\n" +
            "  · Fixed \"connected but no traffic\": the core snapshotted the TUN" +
            "    once before its loop, while Android attaches the TUN only after" +
            "    PPP assigns an address, so nothing was ever read. It is" +
            "    re-snapshotted every iteration now.\n" +
            "\n" +
            "v1.3.3\n" +
            "  · SSTP can skip certificate verification (self-signed servers)\n" +
            "  · ca.pem is passed to the core only when it really exists\n" +
            "\n" +
            "v1.3.2\n" +
            "  · Fixed crash on connect (Android 14 foreground service type)\n"

        AlertDialog.Builder(this)
            .setTitle(L.t("关于 v$VERSION · 作者 ", "About v$VERSION · ") + L.AUTHOR)
            .setMessage(L.t(zhNotes, enNotes))
            .setPositiveButton(L.t("知道了", "OK"), null)
            .setNeutralButton(L.t("第三方组件", "Third-party"), null)
            .create()
            .apply {
                setOnShowListener { dlg ->
                    (dlg as AlertDialog).getButton(AlertDialog.BUTTON_NEUTRAL)
                        .setOnClickListener { showThirdPartyNotices() }
                }
            }
            .show()
    }

    /** 展示随包分发的第三方组件与许可声明（assets/THIRD-PARTY-NOTICES.txt） */
    private fun showThirdPartyNotices() {
        val text = try {
            assets.open("THIRD-PARTY-NOTICES.txt").bufferedReader().use { it.readText() }
        } catch (e: Exception) {
            L.t("无法读取许可文件：", "Cannot read the notices file: ") + e.message
        }
        val pad = (14 * resources.displayMetrics.density).toInt()
        val view = TextView(this).apply {
            setText(text)
            setTextIsSelectable(true)
            textSize = 10f
            typeface = Typeface.MONOSPACE
            setPadding(pad, pad, pad, pad)
        }
        AlertDialog.Builder(this)
            .setTitle(L.t("第三方组件与许可", "Third-party components & licenses"))
            .setView(ScrollView(this).apply { addView(view) })
            .setPositiveButton(L.t("关闭", "Close"), null)
            .show()
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    // ---------------- UiBus 回调 ----------------

    override fun onState(state: Int, detail: String) = renderState(state, detail)

    override fun onStats(rxBytes: Long, txBytes: Long, rxPkts: Long, txPkts: Long) {
        statsText.text = L.t(
            "收发 ${humanBytes(rxBytes)} / ${humanBytes(txBytes)}（${rxPkts} / ${txPkts} 包）",
            "Traffic ${humanBytes(rxBytes)} / ${humanBytes(txBytes)} " +
                "(${rxPkts} / ${txPkts} pkts)")
    }

    override fun onLogAppended() {
        runOnUiThread { refreshLog(scrollToEnd = true) }
    }

    private fun renderState(state: Int, detail: String) {
        val name = when (state) {
            VpnCore.STATE_CONNECTING -> L.t("正在连接", "Connecting")
            VpnCore.STATE_AUTHENTICATING -> L.t("认证中", "Authenticating")
            VpnCore.STATE_CONNECTED -> L.t("已连接", "Connected")
            VpnCore.STATE_RECONNECTING -> L.t("重连中", "Reconnecting")
            VpnCore.STATE_DISCONNECTED -> L.t("已断开", "Disconnected")
            VpnCore.STATE_FAILED -> L.t("连接失败", "Failed")
            else -> L.t("未连接", "Not connected")
        }
        statusText.text = if (detail.isBlank()) name else "$name · $detail"
        val running = state == VpnCore.STATE_CONNECTED ||
                state == VpnCore.STATE_CONNECTING ||
                state == VpnCore.STATE_AUTHENTICATING ||
                state == VpnCore.STATE_RECONNECTING
        btnConnect.isEnabled = !running
        btnDisconnect.isEnabled = running
        applyConfigLock(running)
        if (state == VpnCore.STATE_CONNECTED) {
            val info = VpnCore.tunnelInfo()
            if (info.localIp.isNotBlank())
                statusText.append(L.t(
                    "\n本机 ${info.localIp}  服务器 ${info.peerIp}  DNS ${info.dns1}",
                    "\nLocal ${info.localIp}  Server ${info.peerIp}  DNS ${info.dns1}"))
        }
    }

    /**
     * 连接中 / 认证中 / 已连接 / 重连中：所有配置项锁住不可改。
     *
     * 这些参数只在点"连接"那一刻被读进 Service（ConnArgs），连上之后再改
     * 也不会影响正在跑的会话；以前允许改，用户改完发现没反应，或者误以为
     * 已经生效。断开 / 失败后自动解锁。
     */
    private fun applyConfigLock(locked: Boolean) {
        val alpha = if (locked) 0.45f else 1f
        listOf<View>(
            protoSpinner, certSpinner, hostInput, portInput, userInput,
            passInput, routeAllBox, vpnDnsBox, debugBox
        ).forEach {
            it.isEnabled = !locked
            it.alpha = alpha
        }
        if (locked) {
            currentFocus?.clearFocus()
            try {
                (getSystemService(INPUT_METHOD_SERVICE) as InputMethodManager)
                    .hideSoftInputFromWindow(window.decorView.windowToken, 0)
            } catch (e: Exception) {
                // 输入法服务不可用时忽略，不影响状态机
            }
        }
    }

    private fun refreshLog(scrollToEnd: Boolean) {
        if (!::logText.isInitialized) return
        logText.text = UiBus.logText()
        if (scrollToEnd) {
            scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
        }
    }
}
