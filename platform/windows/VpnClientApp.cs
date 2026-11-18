using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace VpnClient
{
    /// <summary>
    /// Windows 外壳（控制台版）：core 负责协议，Wintun 负责虚拟网卡。
    ///
    /// 时序：先用 "无 TUN" 模式连接 → STATE_CONNECTED 拿到服务器分配的地址 →
    /// 建 Wintun 适配器 + 配置 IP/路由 → 把读/写回调挂给核心。
    ///
    /// 用法：VpnClientApp.exe --host vpn.example.com --port 443 --user u --pass p [--proto sstp]
    /// </summary>
    internal static class Program
    {
        private const int StateConnected = 3;
        private const int StateFailed = 6;

        private static WintunSession _session;
        private static IntPtr _handle = IntPtr.Zero;
        private static volatile bool _running = true;

        private static Native.StateFn _onState = OnState;
        private static Native.StatsFn _onStats = OnStats;
        private static Native.TunReadFn _tunRead = TunRead;
        private static Native.TunWriteFn _tunWrite = TunWrite;
        private static Native.TunDestroyFn _tunDestroy = TunDestroy;

        private sealed class Args
        {
            public string Host = "";
            public int Port;
            public string User = "";
            public string Pass = "";
            public int Proto; // 0=SSTP 1=L2TP 2=PPTP
            public string CaFile = "";
            public bool IgnoreCert;
            public int Mtu = 1400;
            public string Adapter = "VPNClient";
        }

        private static int Main(string[] argv)
        {
            Args a;
            try
            {
                a = Parse(argv);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
                Console.Error.WriteLine(
                    "用法: VpnClientApp --host <地址> [--port 端口] --user <用户名> --pass <密码> " +
                    "[--proto sstp|l2tp|pptp] [--ca ca.pem] [--ignore-cert] [--mtu 1400]");
                return 2;
            }

            Native.vpn_capi_set_log_level(2);
            IntPtr handle = BuildConfig(a);
            if (handle == IntPtr.Zero)
                return 1;
            _handle = handle;

            int rc = Native.vpn_capi_start(_handle);
            if (rc != 0)
            {
                Console.Error.WriteLine("启动失败: " + Native.ErrorText(rc));
                Native.vpn_capi_destroy(_handle);
                return 1;
            }

            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                _running = false;
            };

            int waitRc = Native.vpn_capi_wait(_handle, 30000);
            if (waitRc != 0)
            {
                Console.Error.WriteLine("连接失败: " + Native.ErrorText(waitRc));
                Native.vpn_capi_destroy(_handle);
                return 1;
            }
            Console.WriteLine("已连接，Ctrl+C 退出");

            while (_running)
            {
                PrintStats();
                Thread.Sleep(3000);
            }

            Native.vpn_capi_stop(_handle);
            Native.vpn_capi_destroy(_handle);
            _session?.Dispose();
            return 0;
        }

        // ---- 连接成功 → 建 Wintun 并挂接 ----
        private static void OnState(int state, IntPtr detail, IntPtr user)
        {
            string text = Native.Utf8ToString(detail);
            Console.WriteLine($"[state] {state} {text}");
            if (state != StateConnected) return;

            IntPtr h = _handle;
            if (h == IntPtr.Zero) return;

            // 在工作线程外建立适配器，避免阻塞协议回调
            new Thread(() =>
            {
                try
                {
                    Native.vpn_capi_get_stats(h, out Native.CapiStats st);
                    string addr = string.IsNullOrEmpty(st.LocalIp) ? "10.111.222.2" : st.LocalIp;

                    _session = new WintunSession(CurrentAdapterName);
                    ConfigureInterface(CurrentAdapterName, addr);

                    var tun = new Native.CapiTun
                    {
                        read = Marshal.GetFunctionPointerForDelegate(_tunRead),
                        write = Marshal.GetFunctionPointerForDelegate(_tunWrite),
                        destroy = Marshal.GetFunctionPointerForDelegate(_tunDestroy),
                        ctx = IntPtr.Zero
                    };
                    int rc = Native.vpn_capi_attach_tun(h, ref tun);
                    Console.WriteLine(rc == 0 ? $"隧道已挂接 {addr}" : $"挂接 TUN 失败 {rc}");
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("建立隧道失败: " + e.Message);
                }
            }) { IsBackground = true }.Start();
        }

        private static string CurrentAdapterName = "VPNClient";

        private static void OnStats(IntPtr statsPtr, IntPtr user)
        {
            if (statsPtr == IntPtr.Zero) return;
            var st = Marshal.PtrToStructure<Native.CapiStats>(statsPtr);
            Console.WriteLine($"[stats] rx={st.rxBytes}B tx={st.txBytes}B rtt={st.rttMs}ms " +
                              $"cipher={st.Cipher} state={st.state}");
        }

        // ---- Wintun 读写回调（由核心 worker 线程调用） ----
        private static byte[] _readBuf = new byte[65536];

        private static int TunRead(IntPtr ctx, IntPtr buf, int cap, int timeoutMs)
        {
            WintunSession s = _session;
            if (s == null) return 0;
            int n = s.Read(_readBuf, timeoutMs);
            if (n <= 0) return n;
            if (n > cap) n = cap;
            Marshal.Copy(_readBuf, 0, buf, n);
            return n;
        }

        private static int TunWrite(IntPtr ctx, IntPtr buf, int len)
        {
            WintunSession s = _session;
            if (s == null || len <= 0) return -1;
            byte[] tmp = new byte[len];
            Marshal.Copy(buf, tmp, 0, len);
            return s.Write(tmp, len);
        }

        private static void TunDestroy(IntPtr ctx)
        {
            if (_session != null) _session.Dispose();
            _session = null;
        }

        // ---- 用 netsh 给虚拟网卡配地址（生产环境建议走 IP Helper API） ----
        private static void ConfigureInterface(string name, string localIp)
        {
            Run("netsh", $"interface ip set address name=\"{name}\" source=static addr={localIp} mask=255.255.255.255");
        }

        private static void Run(string exe, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(8000);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"执行 {exe} 失败: {e.Message}");
            }
        }

        private static void PrintStats()
        {
            if (_handle == IntPtr.Zero) return;
            Native.vpn_capi_get_stats(_handle, out Native.CapiStats st);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] rx={st.rxBytes / 1024}KB tx={st.txBytes / 1024}KB " +
                              $"rtt={st.rttMs}ms reconnects={st.reconnects} ip={st.LocalIp}");
        }

        private static Args Parse(string[] argv)
        {
            var a = new Args();
            for (int i = 0; i < argv.Length; i++)
            {
                switch (argv[i])
                {
                    case "--host": a.Host = argv[++i]; break;
                    case "--port": a.Port = int.Parse(argv[++i]); break;
                    case "--user": a.User = argv[++i]; break;
                    case "--pass": a.Pass = argv[++i]; break;
                    case "--ca": a.CaFile = argv[++i]; break;
                    case "--mtu": a.Mtu = int.Parse(argv[++i]); break;
                    case "--adapter": a.Adapter = argv[++i]; break;
                    case "--ignore-cert": a.IgnoreCert = true; break;
                    case "--proto":
                        string p = argv[++i].ToLowerInvariant();
                        a.Proto = p switch { "l2tp" => 1, "pptp" => 2, _ => 0 };
                        break;
                    default:
                        throw new ArgumentException("未知参数: " + argv[i]);
                }
            }
            if (a.Host.Length == 0 || a.User.Length == 0)
                throw new ArgumentException("必须提供 --host 与 --user");
            CurrentAdapterName = a.Adapter;
            return a;
        }

        private static IntPtr BuildConfig(Args a)
        {
            // 保留所有原生字符串指针，直到 vpn_capi_create 返回
            var keep = new System.Collections.Generic.List<IntPtr>();
            IntPtr S(string s)
            {
                if (string.IsNullOrEmpty(s)) return IntPtr.Zero;
                IntPtr p = Native.Utf8(s);
                keep.Add(p);
                return p;
            }

            var cfg = new Native.CapiConfig
            {
                proto = a.Proto,
                host = S(a.Host),
                port = a.Port,
                username = S(a.User),
                password = S(a.Pass),
                psk = IntPtr.Zero,
                auth = 3,                       // AUTO
                certMode = a.IgnoreCert ? 1 : 0, // 1 = 忽略证书
                caFile = S(a.CaFile),
                caDir = IntPtr.Zero,
                serverName = IntPtr.Zero,
                verifyHostname = a.IgnoreCert ? 0 : 1,
                mtu = a.Mtu,
                keepaliveS = 30,
                reconnectDelayS = 5,
                maxRetries = 3,
                connectTimeoutS = 20,
                ioSec = 20,
                localIp = IntPtr.Zero,
                dns1 = IntPtr.Zero,
                dns2 = IntPtr.Zero,
                logLevel = 2,
                tunFd = -1
            };

            byte[] err = new byte[192];
            IntPtr handle = Native.vpn_capi_create(ref cfg, _onState, _onStats, IntPtr.Zero,
                                                   err, err.Length);
            foreach (IntPtr p in keep) Marshal.FreeHGlobal(p);
            if (handle == IntPtr.Zero)
            {
                int n = Array.IndexOf(err, (byte)0);
                Console.Error.WriteLine("创建失败: " +
                    Encoding.UTF8.GetString(err, 0, n < 0 ? err.Length : n));
                return IntPtr.Zero;
            }
            return handle;
        }

    }
}
