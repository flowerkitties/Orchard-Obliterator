using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace OrchardObliterator
{
    sealed class OpenFile
    {
        public string Path;
        public bool Gone;
        public byte[] Data;
    }

    static class Handles
    {
        const int SystemExtendedHandleInformation = 64;
        const uint LengthMismatch = 0xC0000004;
        const uint PROCESS_DUP_HANDLE = 0x0040;
        const uint DUPLICATE_SAME_ACCESS = 2;
        const int FILE_TYPE_DISK = 1;
        const int Entry = 40;

        [DllImport("ntdll.dll")]
        static extern uint NtQuerySystemInformation(int cls, IntPtr buffer, int length, out int returned);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern int GetFileType(IntPtr file);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetFinalPathNameByHandle(IntPtr file, StringBuilder path, int size, int flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileSizeEx(IntPtr file, out long size);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFilePointerEx(IntPtr file, long distance, out long position, int method);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(IntPtr file, byte[] buffer, int count, out int read, ref NativeOverlapped overlapped);

        public static List<OpenFile> Archives(int pid, long maxSize)
        {
            var result = new List<OpenFile>();
            IntPtr proc = Native.OpenProcess(PROCESS_DUP_HANDLE, false, pid);
            if (proc == IntPtr.Zero) return result;

            IntPtr table = IntPtr.Zero;
            try
            {
                int size = 1 << 22, needed;
                while (true)
                {
                    table = Marshal.AllocHGlobal(size);
                    uint status = NtQuerySystemInformation(SystemExtendedHandleInformation, table, size, out needed);
                    if (status == 0) break;
                    Marshal.FreeHGlobal(table);
                    table = IntPtr.Zero;
                    if (status != LengthMismatch || size > 1 << 28) return result;
                    size = Math.Max(size * 2, needed + 65536);
                }

                long count = Marshal.ReadIntPtr(table).ToInt64();
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (long i = 0; i < count; i++)
                {
                    IntPtr row = table + 16 + (int)(i * Entry);
                    if (Marshal.ReadIntPtr(row, 8).ToInt64() != pid) continue;
                    uint access = (uint)Marshal.ReadInt32(row, 24);
                    if ((access & 1) == 0) continue;

                    IntPtr dup;
                    if (!DuplicateHandle(proc, Marshal.ReadIntPtr(row, 16), GetCurrentProcess(), out dup, 0, false, DUPLICATE_SAME_ACCESS)) continue;
                    try
                    {
                        if (GetFileType(dup) != FILE_TYPE_DISK) continue;
                        var sb = new StringBuilder(1024);
                        if (GetFinalPathNameByHandle(dup, sb, sb.Capacity, 0) <= 0) continue;
                        string path = sb.ToString();
                        if (path.StartsWith(@"\\?\")) path = path.Substring(4);
                        if (!seen.Add(path)) continue;

                        bool gone = path.Contains(@"\$Extend\$Deleted\") || !File.Exists(path);
                        if (!gone) continue;

                        long length;
                        if (!GetFileSizeEx(dup, out length) || length < 64 || length > maxSize) continue;
                        var data = ReadAll(dup, length);
                        if (data == null || data[0] != 'P' || data[1] != 'K') continue;
                        result.Add(new OpenFile { Path = path, Gone = true, Data = data });
                    }
                    finally
                    {
                        Native.CloseHandle(dup);
                    }
                }
            }
            catch
            {
            }
            finally
            {
                if (table != IntPtr.Zero) Marshal.FreeHGlobal(table);
                Native.CloseHandle(proc);
            }
            return result;
        }

        static byte[] ReadAll(IntPtr file, long length)
        {
            long before;
            bool restore = SetFilePointerEx(file, 0, out before, 1);
            try
            {
                var data = new byte[length];
                long off = 0;
                var chunk = new byte[1 << 20];
                while (off < length)
                {
                    var ov = new NativeOverlapped { OffsetLow = (int)(off & 0xFFFFFFFF), OffsetHigh = (int)(off >> 32) };
                    int want = (int)Math.Min(chunk.Length, length - off), got;
                    if (!ReadFile(file, chunk, want, out got, ref ov) || got <= 0) return null;
                    Buffer.BlockCopy(chunk, 0, data, (int)off, got);
                    off += got;
                }
                return data;
            }
            finally
            {
                long ignored;
                if (restore) SetFilePointerEx(file, before, out ignored, 0);
            }
        }
    }
}
