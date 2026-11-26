using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace OrchardObliterator
{
    sealed class ZipItem
    {
        public string Name;
        public int Method;
        public int Flags;
        public long Packed;
        public long Size;
        public long Offset;

        public bool IsDirectory { get { return Name.EndsWith("/"); } }
    }

    sealed class Zip
    {
        const int MaxInflate = 96 * 1024 * 1024;

        readonly byte[] data;
        public readonly long Shift;
        public readonly List<ZipItem> Items = new List<ZipItem>();
        readonly Dictionary<string, ZipItem> byName = new Dictionary<string, ZipItem>(StringComparer.Ordinal);

        Zip(byte[] data, long shift)
        {
            this.data = data;
            Shift = shift;
        }

        public static bool LooksLikeZip(byte[] head, int headLen, byte[] tail, int tailLen)
        {
            if (headLen >= 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4)
                return true;
            for (int i = tailLen - 22; i >= 0; i--)
                if (tail[i] == 'P' && tail[i + 1] == 'K' && tail[i + 2] == 5 && tail[i + 3] == 6)
                    return true;
            return false;
        }

        public static Zip Open(byte[] data)
        {
            try { return Parse(data); }
            catch { return null; }
        }

        static Zip Parse(byte[] data)
        {
            int eocd = -1;
            int floor = Math.Max(0, data.Length - 22 - 65535);
            for (int i = data.Length - 22; i >= floor; i--)
            {
                if (data[i] == 'P' && data[i + 1] == 'K' && data[i + 2] == 5 && data[i + 3] == 6)
                {
                    eocd = i;
                    break;
                }
            }
            if (eocd < 0) return null;

            long count = U16(data, eocd + 10);
            long dirSize = U32(data, eocd + 12);
            long dirOffset = U32(data, eocd + 16);
            long anchor = eocd;

            if (dirOffset == 0xFFFFFFFF || count == 0xFFFF || dirSize == 0xFFFFFFFF)
            {
                int loc = eocd - 20;
                if (loc < 0 || U32(data, loc) != 0x07064b50) return null;
                int z = -1;
                for (long probe = loc - 56; probe >= 0 && probe >= loc - 56 - 4096; probe--)
                {
                    if (U32(data, (int)probe) == 0x06064b50) { z = (int)probe; break; }
                }
                if (z < 0) return null;
                count = (long)U64(data, z + 32);
                dirSize = (long)U64(data, z + 40);
                dirOffset = (long)U64(data, z + 48);
                anchor = z;
            }

            long dirStart = anchor - dirSize;
            if (dirStart < 0) return null;
            var zip = new Zip(data, dirStart - dirOffset);

            int p = (int)dirStart;
            for (long n = 0; n < count && p + 46 <= data.Length; n++)
            {
                if (U32(data, p) != 0x02014b50) break;
                int flags = U16(data, p + 8);
                int nameLen = U16(data, p + 28);
                int extraLen = U16(data, p + 30);
                int commentLen = U16(data, p + 32);
                if (p + 46 + nameLen > data.Length) break;

                var enc = (flags & 0x800) != 0 ? Encoding.UTF8 : Encoding.GetEncoding(437);
                var item = new ZipItem
                {
                    Flags = flags,
                    Method = U16(data, p + 10),
                    Packed = U32(data, p + 20),
                    Size = U32(data, p + 24),
                    Offset = U32(data, p + 42),
                    Name = enc.GetString(data, p + 46, nameLen).Replace('\\', '/')
                };
                zip.Items.Add(item);
                if (!zip.byName.ContainsKey(item.Name)) zip.byName[item.Name] = item;
                p += 46 + nameLen + extraLen + commentLen;
            }
            return zip.Items.Count == 0 ? null : zip;
        }

        public ZipItem Find(string name)
        {
            ZipItem item;
            return byName.TryGetValue(name, out item) ? item : null;
        }

        public byte[] Read(ZipItem item)
        {
            if ((item.Flags & 1) != 0) return null;
            if (item.Packed == 0xFFFFFFFF || item.Size > MaxInflate) return null;
            long local = item.Offset + Shift;
            if (local < 0 || local + 30 > data.Length) return null;
            if (U32(data, (int)local) != 0x04034b50) return null;

            long start = local + 30 + U16(data, (int)local + 26) + U16(data, (int)local + 28);
            long packed = item.Packed;
            if (start + packed > data.Length) packed = data.Length - start;
            if (packed < 0) return null;

            try
            {
                if (item.Method == 0)
                {
                    var raw = new byte[packed];
                    Buffer.BlockCopy(data, (int)start, raw, 0, (int)packed);
                    return raw;
                }
                if (item.Method != 8) return null;

                using (var src = new MemoryStream(data, (int)start, (int)packed, false))
                using (var inflate = new DeflateStream(src, CompressionMode.Decompress))
                using (var dst = new MemoryStream(item.Size > 0 ? (int)item.Size : 4096))
                {
                    var buf = new byte[16384];
                    int got;
                    while ((got = inflate.Read(buf, 0, buf.Length)) > 0)
                    {
                        dst.Write(buf, 0, got);
                        if (dst.Length > MaxInflate) return null;
                    }
                    return dst.ToArray();
                }
            }
            catch
            {
                return null;
            }
        }

        public byte[] Peek(ZipItem item, int count)
        {
            if ((item.Flags & 1) != 0) return null;
            long local = item.Offset + Shift;
            if (local < 0 || local + 30 > data.Length || U32(data, (int)local) != 0x04034b50) return null;
            long start = local + 30 + U16(data, (int)local + 26) + U16(data, (int)local + 28);
            int avail = (int)Math.Min(item.Packed, data.Length - start);
            if (avail <= 0) return null;
            try
            {
                if (item.Method == 0)
                {
                    var raw = new byte[Math.Min(count, avail)];
                    Buffer.BlockCopy(data, (int)start, raw, 0, raw.Length);
                    return raw;
                }
                if (item.Method != 8) return null;
                using (var inflate = new DeflateStream(new MemoryStream(data, (int)start, avail, false), CompressionMode.Decompress))
                {
                    var buf = new byte[count];
                    int got = 0, n;
                    while (got < count && (n = inflate.Read(buf, got, count - got)) > 0) got += n;
                    if (got < count) Array.Resize(ref buf, got);
                    return buf;
                }
            }
            catch
            {
                return null;
            }
        }

        public string ReadText(ZipItem item)
        {
            var bytes = item == null ? null : Read(item);
            return bytes == null ? null : Encoding.UTF8.GetString(bytes);
        }

        static int U16(byte[] b, int i) { return b[i] | (b[i + 1] << 8); }
        static long U32(byte[] b, int i) { return (uint)(b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)); }
        static ulong U64(byte[] b, int i) { return (ulong)U32(b, i) | ((ulong)U32(b, i + 4) << 32); }
    }
}
