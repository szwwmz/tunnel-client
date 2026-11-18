// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 wwm-spec. All rights reserved.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace VpnClient
{
    /// <summary>
    /// vpncore.dll（C ABI，见 core/include/vpncore/vpn_capi.h）的 P/Invoke 声明。
    /// 字符串统一按 UTF-8 传递，避免 Windows 侧 wchar_t 与 C 层 char 不一致。
    /// </summary>
    internal static class Native
    {
        private const string Dll = "vpncore.dll";

        // ---- 结构体（字段顺序必须与 vpn_capi.h 完全一致） ----
        [StructLayout(LayoutKind.Sequential)]
        internal struct CapiConfig
        {
            public int proto;
            public IntPtr host;
            public int port;
            public IntPtr username;
            public IntPtr password;
            public IntPtr psk;
            public int auth;
            public int certMode;
            public IntPtr caFile;
            public IntPtr caDir;
            public IntPtr serverName;
            public int verifyHostname;
            public int mtu;
            public int keepaliveS;
            public int reconnectDelayS;
            public int maxRetries;
            public int connectTimeoutS;
            public int ioSec;
            public IntPtr localIp;
            public IntPtr dns1;
            public IntPtr dns2;
            public int logLevel;
            public int tunFd;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CapiStats
        {
            public ulong rxBytes;
            public ulong txBytes;
            public ulong rxPackets;
            public ulong txPackets;
            public ulong dropped;
            public uint reconnects;
            public uint rttMs;
            public long connectedSinceMs;
            public int state;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] localIp;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] peerIp;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] dns1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] dns2;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)] public byte[] cipher;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)] public byte[] certFp;

            public string LocalIp => Ascii(localIp);
            public string PeerIp => Ascii(peerIp);
            public string Dns1 => Ascii(dns1);
            public string Dns2 => Ascii(dns2);
            public string Cipher => Ascii(cipher);
            public string CertFingerprint => Ascii(certFp);

            private static string Ascii(byte[] b)
            {
                if (b == null) return string.Empty;
                int n = Array.IndexOf(b, (byte)0);
                if (n < 0) n = b.Length;
                return Encoding.UTF8.GetString(b, 0, n);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CapiTun
        {
            public IntPtr read;
            public IntPtr write;
            public IntPtr destroy;
            public IntPtr ctx;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void StateFn(int state, IntPtr detail, IntPtr user);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void StatsFn(IntPtr stats, IntPtr user);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void LogFn(int level, IntPtr message, IntPtr user);

        // TUN 回调（签名见 vpn_capi_tun）
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int TunReadFn(IntPtr ctx, IntPtr buf, int cap, int timeoutMs);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int TunWriteFn(IntPtr ctx, IntPtr buf, int len);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void TunDestroyFn(IntPtr ctx);

        // ---- 导出函数 ----
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr vpn_capi_create_ex(
            ref CapiConfig cfg, ref CapiTun tun,
            StateFn onState, StatsFn onStats, IntPtr user,
            StringBuilder err, int errLen);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr vpn_capi_create(
            ref CapiConfig cfg,
            StateFn onState, StatsFn onStats, IntPtr user,
            byte[] err, int errLen);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int vpn_capi_attach_tun(IntPtr h, ref CapiTun tun);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int vpn_capi_start(IntPtr h);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int vpn_capi_wait(IntPtr h, int timeoutMs);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void vpn_capi_stop(IntPtr h);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void vpn_capi_destroy(IntPtr h);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int vpn_capi_state(IntPtr h);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void vpn_capi_get_stats(IntPtr h, out CapiStats stats);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void vpn_capi_set_log_level(int level);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Ansi, ExactSpelling = true)]
        internal static extern IntPtr vpn_capi_strerror(int code);

        /// <summary>把核心返回的 UTF-8 C 字符串转成托管串。</summary>
        internal static string Utf8ToString(IntPtr p)
        {
            if (p == IntPtr.Zero) return string.Empty;
            int len = 0;
            while (Marshal.ReadByte(p, len) != 0) len++;
            if (len == 0) return string.Empty;
            byte[] buf = new byte[len];
            Marshal.Copy(p, buf, 0, len);
            return Encoding.UTF8.GetString(buf);
        }

        internal static string ErrorText(int code)
        {
            IntPtr p = vpn_capi_strerror(code);
            return p == IntPtr.Zero ? $"error {code}" : Marshal.PtrToStringAnsi(p);
        }

        /// <summary>把托管字符串编成 UTF-8 原生内存，交给 SafeHandle 统一释放。</summary>
        internal static IntPtr Utf8(string s)
        {
            if (string.IsNullOrEmpty(s)) return IntPtr.Zero;
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            IntPtr p = Marshal.AllocHGlobal(bytes.Length + 1);
            Marshal.Copy(bytes, 0, p, bytes.Length);
            Marshal.WriteByte(p, bytes.Length, 0);
            return p;
        }
    }
}
