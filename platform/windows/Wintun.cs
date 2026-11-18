using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace VpnClient
{
    /// <summary>
    /// Wintun 用户态 TUN（https://www.wintun.net）的最小封装。
    /// 只用到创建适配器 + 会话 + 收发环形缓冲。
    /// </summary>
    internal sealed class WintunSession : IDisposable
    {
        private const string Dll = "wintun.dll";
        private const int RingCapacity = 0x20000; // 128 KiB，够 1400 MTU 双向并发

        private IntPtr _adapter;
        private IntPtr _session;
        private IntPtr _readEvent;
        private bool _disposed;

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr WintunCreateAdapter(string name, string tunnelType, IntPtr requestedGuid);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern void WintunCloseAdapter(IntPtr adapter);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern IntPtr WintunStartSession(IntPtr adapter, int capacity);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern void WintunEndSession(IntPtr session);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern IntPtr WintunGetReadWaitEvent(IntPtr session);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern IntPtr WintunReceivePacket(IntPtr session, out int packetSize);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern IntPtr WintunAllocateSendPacket(IntPtr session, int packetSize);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern void WintunSendPacket(IntPtr session, IntPtr packet);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        public WintunSession(string adapterName = "VPNClient", string tunnelType = "VPN Client")
        {
            string dllPath = Path.Combine(AppContext.BaseDirectory, "wintun.dll");
            if (!File.Exists(dllPath))
                throw new FileNotFoundException(
                    "未找到 wintun.dll，请从 https://www.wintun.net 下载对应架构的 DLL 放到程序目录");

            _adapter = WintunCreateAdapter(adapterName, tunnelType, IntPtr.Zero);
            if (_adapter == IntPtr.Zero)
                throw new InvalidOperationException(
                    $"WintunCreateAdapter 失败（管理员权限？已被占用？）错误码 {Marshal.GetLastWin32Error()}");

            _session = WintunStartSession(_adapter, RingCapacity);
            if (_session == IntPtr.Zero)
            {
                WintunCloseAdapter(_adapter);
                throw new InvalidOperationException(
                    $"WintunStartSession 失败，错误码 {Marshal.GetLastWin32Error()}");
            }
            _readEvent = WintunGetReadWaitEvent(_session);
        }

        /// <summary>读取一个 IP 包到 buf，返回长度；0 表示超时。</summary>
        public int Read(byte[] buf, int timeoutMs)
        {
            for (;;)
            {
                IntPtr pkt = WintunReceivePacket(_session, out int size);
                if (pkt != IntPtr.Zero)
                {
                    try
                    {
                        if (size <= buf.Length)
                        {
                            Marshal.Copy(pkt, buf, 0, size);
                            return size;
                        }
                        return 0; // 包比缓冲大，丢弃
                    }
                    finally
                    {
                        WintunReleaseReceivePacket(_session, pkt);
                    }
                }
                // ERROR_NO_MORE_ITEMS：当前无包，等读事件
                if (Marshal.GetLastWin32Error() != 259)
                    return -1;

                uint wait = timeoutMs < 0 ? 0xFFFFFFFF : (uint)timeoutMs;
                uint rc = WaitForSingleObject(_readEvent, wait);
                if (rc == 258 /* WAIT_TIMEOUT */)
                    return 0;
                if (rc != 0 /* WAIT_OBJECT_0 */)
                    return -1;
            }
        }

        public int Write(byte[] buf, int len)
        {
            IntPtr pkt = WintunAllocateSendPacket(_session, len);
            if (pkt == IntPtr.Zero)
                return -1;
            Marshal.Copy(buf, 0, pkt, len);
            WintunSendPacket(_session, pkt);
            return len;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_session != IntPtr.Zero)
            {
                WintunEndSession(_session);
                _session = IntPtr.Zero;
            }
            if (_adapter != IntPtr.Zero)
            {
                WintunCloseAdapter(_adapter);
                _adapter = IntPtr.Zero;
            }
        }
    }
}
