using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace OrchardObliterator
{
    sealed class Trace
    {
        public string Where;
        public string What;
        public int Tier;
    }

    static class Traces
    {
        public static readonly List<Trace> Found = new List<Trace>();
        public static readonly List<string> ExtraFiles = new List<string>();

        static readonly Regex ModLine = new Regex(@"^\s*[-|\\]+\s*([a-z0-9_.\-]+)\s+(\S+)", RegexOptions.Compiled);
        static readonly Regex Hashy = new Regex(@"^q?[0-9a-f]{16,}$", RegexOptions.Compiled);

        public const int Noise = 0, Lead = 1, Proof = 2;

        static Regex logPattern;

        static void Note(string where, string what, int tier)
        {
            lock (Found)
            {
                if (Found.Any(t => t.Where == where && t.What == what)) return;
                Found.Add(new Trace { Where = where, What = what, Tier = tier });
            }
        }

        public static bool IsAdmin()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        public static void Logs(string gameDir)
        {
            var files = new List<string>();
            foreach (var sub in new[] { "logs", "crash-reports" })
            {
                string d = Path.Combine(gameDir, sub);
                if (!Directory.Exists(d)) continue;
                try { files.AddRange(Directory.GetFiles(d)); } catch { }
            }
            files.RemoveAll(f =>
            {
                string lower = f.ToLowerInvariant();
                return !(lower.EndsWith(".log") || lower.EndsWith(".log.gz") || lower.EndsWith(".txt"));
            });
            Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = 8 }, f =>
            {
                string text = ReadLog(f);
                if (text != null) ScanLogText(f, text);
            });
        }

        static string ReadLog(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    Stream s = fs;
                    if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) s = new GZipStream(fs, CompressionMode.Decompress);
                    using (var r = new StreamReader(s, Encoding.UTF8))
                    {
                        var sb = new StringBuilder();
                        var buf = new char[65536];
                        int n;
                        while (sb.Length < 32 * 1024 * 1024 && (n = r.Read(buf, 0, buf.Length)) > 0)
                            sb.Append(buf, 0, n);
                        return sb.ToString();
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        static void ScanLogText(string file, string text)
        {
            if (logPattern == null)
                logPattern = new Regex(string.Join("|", Fingerprints.LogPatterns.Select(Regex.Escape)), RegexOptions.IgnoreCase | RegexOptions.Compiled);
            bool patterns = Fingerprints.LogPatterns.Count > 0 && logPattern.IsMatch(text);
            if (!patterns && text.IndexOf(" mods:", StringComparison.Ordinal) < 0) return;
            var lines = text.Split('\n');
            bool inModList = false;
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].TrimEnd('\r');
                if (line.Contains("Loading ") && line.Contains(" mods:")) { inModList = true; continue; }
                if (inModList)
                {
                    var m = ModLine.Match(line);
                    if (!m.Success) { inModList = false; }
                    else
                    {
                        string id = m.Groups[1].Value;
                        if (id == "orchard")
                            Note(file, string.Format("line {0}: mod list contains \"{1} {2}\"", i + 1, id, m.Groups[2].Value), Proof);
                        else if (id.Contains("orchard"))
                            Note(file, string.Format("line {0}: mod list contains \"{1} {2}\"", i + 1, id, m.Groups[2].Value), Lead);
                        else if (Hashy.IsMatch(id))
                            Note(file, string.Format("line {0}: mod with a hashed id \"{1}\"", i + 1, id), Noise);
                        continue;
                    }
                }
                if (patterns && logPattern.IsMatch(line))
                {
                    string snip = line.Trim();
                    if (snip.Length > 160) snip = snip.Substring(0, 160) + "...";
                    Note(file, string.Format("line {0}: {1}", i + 1, snip), Proof);
                }
            }
        }

        public static void LaunchConfigs(string gameDir)
        {
            var files = new List<string>();
            foreach (var name in new[] { "launcher_profiles.json", "launcher_profiles_microsoft_store.json", "instance.cfg", "mmc-pack.json", "profile.json", "minecraftinstance.json" })
            {
                string a = Path.Combine(gameDir, name);
                string b = Path.Combine(Path.GetDirectoryName(gameDir) ?? gameDir, name);
                if (File.Exists(a)) files.Add(a);
                if (File.Exists(b) && b != a) files.Add(b);
            }
            string versions = Path.Combine(gameDir, "versions");
            if (Directory.Exists(versions))
            {
                try { files.AddRange(Directory.GetFiles(versions, "*.json", SearchOption.AllDirectories)); } catch { }
            }

            foreach (var f in files)
            {
                string text;
                try { text = File.ReadAllText(f); } catch { continue; }
                foreach (Match m in Regex.Matches(text, @"(-javaagent:[^""\s,]+|-agentpath:[^""\s,]+|-Dfabric\.addMods=[^""\s,]+)"))
                    Note(f, "launch argument " + m.Value, Noise);
                foreach (Match m in Regex.Matches(text, @"""url""\s*:\s*""(https?://[^""/]+)"))
                {
                    string host = m.Groups[1].Value.ToLowerInvariant();
                    if (!Fingerprints.TrustedHosts.Any(h => host.EndsWith(h)))
                        Note(f, "library pulled from unusual host " + host, Noise);
                }
            }
        }

        public static void RecycleBin()
        {
            string sid = WindowsIdentity.GetCurrent().User.Value;
            foreach (var root in Locations.FixedDrives())
            {
                string bin = Path.Combine(root, "$Recycle.Bin", sid);
                if (!Directory.Exists(bin)) continue;
                string[] infos;
                try { infos = Directory.GetFiles(bin, "$I*"); } catch { continue; }
                foreach (var info in infos)
                {
                    string original = ParseRecycleInfo(info);
                    if (original == null) continue;
                    string data = Path.Combine(bin, "$R" + Path.GetFileName(info).Substring(2));
                    bool jarish = original.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) || original.ToLowerInvariant().Contains("orchard");
                    if (File.Exists(data) && Locations.IsArchive(data, 512, 400L * 1024 * 1024))
                    {
                        ExtraFiles.Add(data);
                        if (jarish) Note(data, "deleted archive waiting in the Recycle Bin, was " + original, Noise);
                    }
                    else if (jarish)
                    {
                        Note(info, "Recycle Bin record for " + original, original.ToLowerInvariant().Contains("orchard") ? Lead : Noise);
                    }
                }
            }
        }

        static string ParseRecycleInfo(string path)
        {
            try
            {
                var b = File.ReadAllBytes(path);
                long version = BitConverter.ToInt64(b, 0);
                if (version == 2)
                {
                    int chars = BitConverter.ToInt32(b, 24);
                    return Encoding.Unicode.GetString(b, 28, Math.Max(0, (chars - 1) * 2));
                }
                if (version == 1) return Encoding.Unicode.GetString(b, 24, 520).TrimEnd('\0');
            }
            catch
            {
            }
            return null;
        }

        public static void RecentItems()
        {
            string recent = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
            string[] links;
            try { links = Directory.GetFiles(recent, "*.lnk"); } catch { return; }
            var rx = new Regex(@"[A-Za-z]:\\[^\0""<>|*?]{2,240}?\.(jar|zip)", RegexOptions.IgnoreCase);
            foreach (var lnk in links)
            {
                string name = Path.GetFileName(lnk).ToLowerInvariant();
                byte[] b;
                try { b = File.ReadAllBytes(lnk); } catch { continue; }
                var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (Match m in rx.Matches(Encoding.GetEncoding(1252).GetString(b))) targets.Add(m.Value);
                foreach (Match m in rx.Matches(Encoding.Unicode.GetString(b))) targets.Add(m.Value);
                foreach (Match m in rx.Matches(Encoding.Unicode.GetString(b, 1, b.Length - 1))) targets.Add(m.Value);

                foreach (var t in targets)
                {
                    bool orchard = t.ToLowerInvariant().Contains("orchard") || name.Contains("orchard");
                    if (File.Exists(t))
                    {
                        if (t.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)) ExtraFiles.Add(t);
                        if (orchard) Note(lnk, "recently opened " + t, Lead);
                    }
                    else if (orchard || t.ToLowerInvariant().Contains("\\mods\\"))
                    {
                        Note(lnk, "recently opened " + t + " (file is gone now)", orchard ? Lead : Noise);
                    }
                }
                if (name.Contains("orchard") && targets.Count == 0)
                    Note(lnk, "recent item shortcut named " + Path.GetFileName(lnk), Lead);
            }
        }

        public static string ZoneIdentifier(string path)
        {
            try
            {
                using (var h = Native.CreateFile(path + ":Zone.Identifier", Native.GENERIC_READ, Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, IntPtr.Zero, Native.OPEN_EXISTING, 0, IntPtr.Zero))
                {
                    if (h.IsInvalid) return null;
                    using (var fs = new FileStream(h, FileAccess.Read))
                    using (var r = new StreamReader(fs))
                    {
                        var lines = r.ReadToEnd().Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith("HostUrl=") || l.StartsWith("ReferrerUrl="));
                        string joined = string.Join("  ", lines);
                        return joined.Length == 0 ? null : joined;
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct StreamData
        {
            public long Size;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string Name;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr FindFirstStreamW(string file, int level, out StreamData data, int flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool FindNextStreamW(IntPtr find, out StreamData data);

        [DllImport("kernel32.dll")]
        static extern bool FindClose(IntPtr find);

        public static void AlternateStreams(string path)
        {
            StreamData sd;
            IntPtr find = FindFirstStreamW(path, 0, out sd, 0);
            if (find == new IntPtr(-1)) return;
            try
            {
                do
                {
                    string name = sd.Name ?? "";
                    if (name == "::$DATA" || name.StartsWith(":Zone.Identifier") || name.StartsWith(":SmartScreen") || name.StartsWith(":com.dropbox")) continue;
                    string stream = path + name.Replace(":$DATA", "");
                    Note(path, string.Format("hidden alternate data stream {0} ({1:N0} bytes)", name, sd.Size), Noise);
                    if (sd.Size > 512) ExtraFiles.Add(stream);
                }
                while (FindNextStreamW(find, out sd));
            }
            finally
            {
                FindClose(find);
            }
        }

        public static byte[] ReadStream(string streamPath)
        {
            using (var h = Native.CreateFile(streamPath, Native.GENERIC_READ, Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, IntPtr.Zero, Native.OPEN_EXISTING, 0, IntPtr.Zero))
            {
                if (h.IsInvalid) return null;
                using (var fs = new FileStream(h, FileAccess.Read))
                using (var ms = new MemoryStream())
                {
                    fs.CopyTo(ms);
                    return ms.ToArray();
                }
            }
        }

        public static void Prefetch()
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
            string[] files;
            try { files = Directory.GetFiles(dir, "JAVA*.pf"); }
            catch
            {
                Report.Dim("prefetch: no access (run as administrator)");
                return;
            }
            var rx = new Regex(@"\\VOLUME\{[^}]+\}(\\[^\0]+?\.(JAR|ZIP))", RegexOptions.IgnoreCase);
            foreach (var pf in files)
            {
                byte[] raw = Decompress(pf);
                if (raw == null) continue;
                var text = Encoding.Unicode.GetString(raw);
                foreach (Match m in rx.Matches(text))
                {
                    string tail = m.Groups[1].Value;
                    string lower = tail.ToLowerInvariant();
                    string onDisk = Locations.FixedDrives().Select(d => d.TrimEnd('\\') + tail).FirstOrDefault(File.Exists);
                    bool orchard = lower.Contains("orchard");
                    bool modsDir = lower.Contains("\\mods\\") || lower.Contains("\\temp\\") || lower.Contains("\\downloads\\");
                    if (onDisk != null)
                    {
                        if (modsDir || orchard) ExtraFiles.Add(onDisk);
                        if (orchard) Note(pf, "java loaded " + onDisk, Lead);
                    }
                    else if (modsDir || orchard)
                    {
                        Note(pf, "java loaded " + tail + " which no longer exists", orchard ? Lead : Noise);
                    }
                }
            }
        }

        static byte[] Decompress(string pf)
        {
            byte[] b;
            try { b = File.ReadAllBytes(pf); } catch { return null; }
            if (b.Length < 8) return null;
            if (b[0] == 'M' && b[1] == 'A' && b[2] == 'M')
            {
                int size = BitConverter.ToInt32(b, 4);
                uint ws, fs;
                if (Native.RtlGetCompressionWorkSpaceSize(4, out ws, out fs) != 0) return null;
                var work = new byte[ws];
                var input = new byte[b.Length - 8];
                Buffer.BlockCopy(b, 8, input, 0, input.Length);
                var output = new byte[size];
                int final;
                if (Native.RtlDecompressBufferEx(4, output, size, input, input.Length, out final, work) != 0) return null;
                return output;
            }
            return b;
        }

        public static void UsnJournal(int days)
        {
            DateTime since = DateTime.UtcNow.AddDays(-days);
            foreach (var root in Locations.FixedDrives())
            {
                string vol = @"\\.\" + root.TrimEnd('\\');
                using (var h = Native.CreateFile(vol, Native.GENERIC_READ, Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero, Native.OPEN_EXISTING, 0, IntPtr.Zero))
                {
                    if (h.IsInvalid)
                    {
                        Report.Dim("usn journal " + root + ": no access (run as administrator)");
                        continue;
                    }
                    ReadJournal(h, root, since);
                }
            }
        }

        static void ReadJournal(SafeFileHandle h, string root, DateTime since)
        {
            var q = new byte[80];
            int got;
            if (!Native.DeviceIoControl(h, Native.FSCTL_QUERY_USN_JOURNAL, null, 0, q, q.Length, out got, IntPtr.Zero)) return;
            long journalId = BitConverter.ToInt64(q, 0);
            long next = BitConverter.ToInt64(q, 8);
            long end = BitConverter.ToInt64(q, 16);

            var input = new byte[40];
            var output = new byte[1 << 20];
            var pendingRename = new Dictionary<string, string>();
            int scanned = 0;

            while (next < end)
            {
                BitConverter.GetBytes(next).CopyTo(input, 0);
                BitConverter.GetBytes(0x3300u).CopyTo(input, 8);
                BitConverter.GetBytes(0).CopyTo(input, 12);
                BitConverter.GetBytes(0L).CopyTo(input, 16);
                BitConverter.GetBytes(0L).CopyTo(input, 24);
                BitConverter.GetBytes(journalId).CopyTo(input, 32);
                if (!Native.DeviceIoControl(h, Native.FSCTL_READ_USN_JOURNAL, input, input.Length, output, output.Length, out got, IntPtr.Zero)) break;
                if (got <= 8) break;
                long after = BitConverter.ToInt64(output, 0);

                int p = 8;
                while (p + 60 <= got)
                {
                    int len = BitConverter.ToInt32(output, p);
                    if (len <= 0 || p + len > got) break;
                    int major = BitConverter.ToUInt16(output, p + 4);
                    int refLen = major >= 3 ? 16 : 8;
                    int at = p + 8 + refLen * 2;
                    long stamp = BitConverter.ToInt64(output, at + 8);
                    uint reason = BitConverter.ToUInt32(output, at + 16);
                    int nameLen = BitConverter.ToUInt16(output, at + 32);
                    int nameOff = BitConverter.ToUInt16(output, at + 34);
                    string fileRef = BitConverter.ToString(output, p + 8, refLen);
                    string name = Encoding.Unicode.GetString(output, p + nameOff, nameLen);
                    scanned++;

                    DateTime when = DateTime.FromFileTimeUtc(stamp);
                    if (when >= since) Classify(root, fileRef, name, reason, when.ToLocalTime(), pendingRename);
                    p += len;
                }
                if (after <= next) break;
                next = after;
            }
            Report.Dim(string.Format("usn journal {0}: {1:N0} records read", root, scanned));
        }

        static void Classify(string root, string fileRef, string name, uint reason, DateTime when, Dictionary<string, string> pendingRename)
        {
            string lower = name.ToLowerInvariant();
            string where = "USN " + root;
            if ((reason & 0x1000) != 0) pendingRename[fileRef] = name;
            if ((reason & 0x2000) != 0)
            {
                string old;
                if (pendingRename.TryGetValue(fileRef, out old))
                {
                    pendingRename.Remove(fileRef);
                    bool wasJar = old.EndsWith(".jar", StringComparison.OrdinalIgnoreCase);
                    bool isJar = lower.EndsWith(".jar");
                    if (wasJar != isJar || old.ToLowerInvariant().Contains("orchard") || lower.Contains("orchard"))
                        Note(where, string.Format("{0:yyyy-MM-dd HH:mm:ss} renamed {1} -> {2}", when, old, name), old.ToLowerInvariant().Contains("orchard") || lower.Contains("orchard") ? Lead : Noise);
                }
            }
            if (lower.Contains("orchard") && (lower.EndsWith(".jar") || lower.EndsWith(".zip")))
            {
                string what = (reason & 0x200) != 0 ? "deleted" : (reason & 0x100) != 0 ? "created" : null;
                if (what != null) Note(where, string.Format("{0:yyyy-MM-dd HH:mm:ss} {1} {2}", when, what, name), Lead);
            }
        }
    }
}
