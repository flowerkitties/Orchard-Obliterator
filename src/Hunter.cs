using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;

namespace OrchardObliterator
{
    sealed class GameProcess
    {
        public int Pid;
        public string Name;
        public string Exe;
        public string CommandLine;
        public string GameDir;
        public bool Fabric;
        public readonly List<string> ArgJars = new List<string>();
        public readonly List<string> Flags = new List<string>();
        public readonly HashSet<string> CarvedJars = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> ForeignModules = new List<string>();
        public readonly List<string> UnbackedImages = new List<string>();
        public readonly List<string> JarsInUse = new List<string>();
        public readonly List<string> DeletedOpen = new List<string>();
        public int MixinClasses;
        public Evidence Memory;
        public long Scanned;
        public bool Denied;
    }

    static class Hunter
    {
        const int Chunk = 8 * 1024 * 1024;
        const int Overlap = 512;
        const int MaxCarved = 20000;
        const int MaxMixins = 20000;
        const int Window = 256 * 1024;

        static readonly byte[] MixinTag = Encoding.ASCII.GetBytes("Lorg/spongepowered/asm/mixin/Mixin;");

        static readonly HashSet<string> Roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "net", "com", "org", "io", "me", "dev", "de", "xyz", "gg", "cc", "fr", "ru", "uk", "nl", "pl", "it",
            "club", "top", "site", "github", "mod", "mods", "mixin", "mixins", "client", "lol", "ac", "app"
        };

        static readonly string[] NativeAllow =
        {
            "lwjgl", "glfw", "openal", "jemalloc", "jinput", "jna", "jcef", "libcef", "discord", "sapiwrapper",
            "flite", "theseus", "imgui", "rtss", "graphics-hook", "nvspcap", "nvapi", "obs", "steam", "overlay"
        };

        public static List<GameProcess> FindJava()
        {
            var found = new List<GameProcess>();
            try
            {
                using (var q = new ManagementObjectSearcher("SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process"))
                {
                    foreach (ManagementObject mo in q.Get())
                    {
                        string name = (mo["Name"] as string) ?? "";
                        string cmd = (mo["CommandLine"] as string) ?? "";
                        string exe = (mo["ExecutablePath"] as string) ?? "";
                        string lname = name.ToLowerInvariant();
                        bool jvm = lname == "java.exe" || lname == "javaw.exe"
                                   || cmd.Contains("net.fabricmc") || cmd.Contains("net.minecraft")
                                   || cmd.Contains("-Djava.library.path") || cmd.Contains("cpw.mods") || cmd.Contains("-Xmx");
                        if (!jvm) continue;
                        if (lname == "orchardobliterator.exe") continue;

                        var gp = new GameProcess
                        {
                            Pid = Convert.ToInt32(mo["ProcessId"]),
                            Name = name,
                            Exe = exe,
                            CommandLine = cmd
                        };
                        ParseCommandLine(gp);
                        found.Add(gp);
                    }
                }
            }
            catch (Exception e)
            {
                Report.Warn("process list via WMI failed: " + e.Message);
                foreach (var p in Process.GetProcesses())
                {
                    string n = p.ProcessName.ToLowerInvariant();
                    if (n == "java" || n == "javaw")
                        found.Add(new GameProcess { Pid = p.Id, Name = p.ProcessName + ".exe", CommandLine = "" });
                }
            }
            return found;
        }

        static void ParseCommandLine(GameProcess gp)
        {
            var args = Split(gp.CommandLine);
            for (int i = 0; i < args.Count; i++)
            {
                string a = args[i];
                string next = i + 1 < args.Count ? args[i + 1] : "";

                if (a == "--gameDir") gp.GameDir = next;
                else if (a.Contains("KnotClient") || a.Contains("net.fabricmc.loader")) gp.Fabric = true;
                else if (a.StartsWith("-Dfabric.addMods=", StringComparison.OrdinalIgnoreCase))
                {
                    gp.Flags.Add("extra mods injected with " + a);
                    foreach (var p in a.Substring(17).Split(';'))
                        if (p.Length > 0) gp.ArgJars.Add(p.TrimStart('@'));
                }
                else if (a.StartsWith("-javaagent:", StringComparison.OrdinalIgnoreCase))
                {
                    string jar = a.Substring(11);
                    int eq = jar.IndexOf('=');
                    if (eq > 0) jar = jar.Substring(0, eq);
                    gp.Flags.Add("java agent attached: " + jar);
                    gp.ArgJars.Add(jar);
                }
                else if (a.StartsWith("-agentpath:", StringComparison.OrdinalIgnoreCase) || a.StartsWith("-agentlib:", StringComparison.OrdinalIgnoreCase))
                {
                    gp.Flags.Add("native JVMTI agent: " + a);
                }
                else if (a == "-cp" || a == "-classpath" || a == "--class-path")
                {
                    foreach (var p in next.Split(';'))
                        if (p.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)) gp.ArgJars.Add(p);
                }
                else if (a.StartsWith("-Dfabric.debug.", StringComparison.OrdinalIgnoreCase) || a.StartsWith("-Dmixin.", StringComparison.OrdinalIgnoreCase))
                {
                    gp.Flags.Add("loader debug switch: " + a);
                }
            }
            if (gp.Fabric && string.IsNullOrEmpty(gp.GameDir))
                gp.GameDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ".minecraft");
        }

        static List<string> Split(string cmd)
        {
            var list = new List<string>();
            var sb = new StringBuilder();
            bool quoted = false;
            foreach (char c in cmd ?? "")
            {
                if (c == '"') { quoted = !quoted; continue; }
                if (c == ' ' && !quoted)
                {
                    if (sb.Length > 0) { list.Add(sb.ToString()); sb.Clear(); }
                    continue;
                }
                sb.Append(c);
            }
            if (sb.Length > 0) list.Add(sb.ToString());
            return list;
        }

        public static void Inspect(GameProcess gp)
        {
            gp.Memory = new Evidence(string.Format("{0} pid {1} (live memory)", gp.Name, gp.Pid));
            Modules(gp);

            IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_INFORMATION | Native.PROCESS_VM_READ, false, gp.Pid);
            if (h == IntPtr.Zero)
            {
                gp.Denied = true;
                return;
            }

            var sigs = Fingerprints.Memory;
            var counts = new int[sigs.Count];
            var asciiJar = Encoding.ASCII.GetBytes(".jar");
            var asciiJarUp = Encoding.ASCII.GetBytes(".JAR");
            var wideJar = Encoding.Unicode.GetBytes(".jar");
            var buf = new byte[Chunk + Overlap];
            var window = new byte[Window * 2];
            var parsedAt = new HashSet<long>();
            var mixins = new Dictionary<string, ClassFile>(StringComparer.Ordinal);
            var sw = Stopwatch.StartNew();

            try
            {
                long addr = 0;
                Native.MemoryInfo mi;
                var miSize = (IntPtr)System.Runtime.InteropServices.Marshal.SizeOf(typeof(Native.MemoryInfo));
                while (Native.VirtualQueryEx(h, (IntPtr)addr, out mi, miSize) != IntPtr.Zero)
                {
                    long start = mi.BaseAddress.ToInt64();
                    long size = mi.RegionSize.ToInt64();
                    if (size <= 0) break;

                    bool readable = mi.State == Native.MEM_COMMIT && (mi.Protect & (Native.PAGE_NOACCESS | Native.PAGE_GUARD)) == 0 && mi.Protect != 0;
                    if (readable)
                    {
                        bool exec = (mi.Protect & 0xF0) != 0;
                        if (exec && mi.Type == 0x20000) CheckPe(h, start, gp);

                        for (long off = 0; off < size; off += Chunk)
                        {
                            int want = (int)Math.Min(Chunk + Overlap, size - off);
                            IntPtr read;
                            if (!Native.ReadProcessMemory(h, (IntPtr)(start + off), buf, (IntPtr)want, out read)) continue;
                            int n = read.ToInt32();
                            if (n <= 0) continue;
                            gp.Scanned += Math.Min(n, Chunk);

                            for (int s = 0; s < sigs.Count; s++)
                                counts[s] += Count(buf, n, sigs[s].Bytes);

                            if (mixins.Count < MaxMixins)
                                CarveMixins(h, buf, n, start + off, window, parsedAt, mixins);

                            if (gp.CarvedJars.Count < MaxCarved)
                            {
                                CarveAscii(buf, n, asciiJar, gp.CarvedJars);
                                CarveAscii(buf, n, asciiJarUp, gp.CarvedJars);
                                CarveWide(buf, n, wideJar, gp.CarvedJars);
                            }
                        }
                        if (sw.ElapsedMilliseconds > 250)
                        {
                            Report.Progress(string.Format("  pid {0}: {1:N0} MB scanned", gp.Pid, gp.Scanned >> 20));
                            sw.Restart();
                        }
                    }

                    long nextAddr = start + size;
                    if (nextAddr <= addr) break;
                    addr = nextAddr;
                }
            }
            finally
            {
                Native.CloseHandle(h);
                Report.ClearProgress();
            }

            gp.MixinClasses = mixins.Count;
            MixinFootprint(gp, mixins.Values);

            foreach (var open in Handles.Archives(gp.Pid, 256L * 1024 * 1024))
            {
                var ev = JarScanner.Inspect(open.Data, open.Path, Path.GetExtension(open.Path), 0);
                if (ev.Level != Level.Confirmed) continue;
                gp.DeletedOpen.Add(open.Path);
                gp.Memory.Absorb(ev, "deleted but still open " + open.Path + ": ");
            }

            for (int s = 0; s < sigs.Count; s++)
            {
                if (counts[s] == 0) continue;
                gp.Memory.Add(sigs[s].Kind, sigs[s].Weight, string.Format("\"{0}\" resident in memory x{1:N0}", sigs[s].Text, counts[s]));
            }
            foreach (var u in gp.UnbackedImages)
                gp.Memory.Add("injection", 30, u);
        }

        static void CarveMixins(IntPtr h, byte[] buf, int n, long baseAddr, byte[] window, HashSet<long> parsedAt, Dictionary<string, ClassFile> sink)
        {
            int i = 0, last = n - MixinTag.Length;
            while (i <= last && sink.Count < MaxMixins)
            {
                i = Array.IndexOf(buf, MixinTag[0], i, last - i + 1);
                if (i < 0) return;
                int k = 1;
                while (k < MixinTag.Length && buf[i + k] == MixinTag[k]) k++;
                if (k == MixinTag.Length)
                {
                    var cf = ClassAround(h, buf, n, i, baseAddr, window, parsedAt);
                    if (cf != null && cf.IsMixin && cf.Name != null && !sink.ContainsKey(cf.Name)) sink[cf.Name] = cf;
                    i += MixinTag.Length;
                    continue;
                }
                i++;
            }
        }

        static ClassFile ClassAround(IntPtr h, byte[] buf, int n, int hit, long baseAddr, byte[] window, HashSet<long> parsedAt)
        {
            int s = Magic(buf, hit, Math.Max(0, hit - Window));
            if (s >= 0)
            {
                if (!parsedAt.Add(baseAddr + s)) return null;
                var cf = ClassFile.Parse(buf, s);
                if (cf != null && cf.Complete && s + cf.Length <= n) return cf;
                return Remote(h, baseAddr + s, window);
            }
            if (hit >= Window) return null;

            long from = Math.Max(0, baseAddr + hit - Window);
            int rel = (int)(baseAddr + hit - from);
            if (ReadAt(h, from, window, Window) < rel) return null;
            s = Magic(window, rel, 0);
            if (s < 0 || !parsedAt.Add(from + s)) return null;
            return Remote(h, from + s, window);
        }

        static ClassFile Remote(IntPtr h, long addr, byte[] window)
        {
            int got = ReadAt(h, addr, window, window.Length);
            var cf = got > 10 ? ClassFile.Parse(window, 0) : null;
            return cf != null && cf.Complete && cf.Length <= got ? cf : null;
        }

        static int ReadAt(IntPtr h, long addr, byte[] into, int count)
        {
            IntPtr read;
            Native.ReadProcessMemory(h, (IntPtr)addr, into, (IntPtr)count, out read);
            return read.ToInt32();
        }

        static int Magic(byte[] b, int from, int floor)
        {
            for (int s = from - 8; s >= floor; s--)
            {
                if (b[s] != 0xCA || b[s + 1] != 0xFE || b[s + 2] != 0xBA || b[s + 3] != 0xBE) continue;
                int major = (b[s + 6] << 8) | b[s + 7];
                if (major >= 45 && major <= 90) return s;
            }
            return -1;
        }

        static void MixinFootprint(GameProcess gp, IEnumerable<ClassFile> mixins)
        {
            var groups = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
            var members = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var cf in mixins)
            {
                var parts = cf.Name.Split('/');
                for (int depth = 1; depth < parts.Length; depth++)
                {
                    if (depth == 1 && (Roots.Contains(parts[0]) || parts[0].Length < 4)) continue;
                    string pkg = string.Join("/", parts, 0, depth);
                    HashSet<string> set;
                    if (!groups.TryGetValue(pkg, out set))
                    {
                        groups[pkg] = set = new HashSet<string>(StringComparer.Ordinal);
                        members[pkg] = 0;
                    }
                    members[pkg]++;
                    foreach (var f in cf.Footprint()) set.Add(f);
                }
            }

            string best = null;
            int bestShared = 0;
            foreach (var g in groups)
            {
                int shared = g.Value.Count(f => Fingerprints.Footprint.Contains(f));
                if (shared > bestShared || (shared == bestShared && shared > 0 && g.Key.Length > best.Length))
                {
                    best = g.Key;
                    bestShared = shared;
                }
            }
            if (best == null) return;

            var ev = new Evidence(best);
            JarScanner.Footprint(ev, groups[best], members[best]);
            gp.Memory.Absorb(ev, "loaded mixins in " + best.Replace('/', '.') + ": ");
        }

        static void Modules(GameProcess gp)
        {
            try
            {
                var p = Process.GetProcessById(gp.Pid);
                string javaHome = "";
                if (!string.IsNullOrEmpty(gp.Exe))
                {
                    var bin = Path.GetDirectoryName(gp.Exe);
                    javaHome = (Path.GetDirectoryName(bin) ?? bin).ToLowerInvariant();
                }
                string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
                foreach (ProcessModule m in p.Modules)
                {
                    string file = (m.FileName ?? "").ToLowerInvariant();
                    if (file.StartsWith(win) || (javaHome.Length > 3 && file.StartsWith(javaHome))) continue;
                    if (file.Contains("\\program files")) continue;
                    string leaf = Path.GetFileName(file);
                    if (NativeAllow.Any(a => leaf.StartsWith(a) || leaf.Contains(a))) continue;
                    gp.ForeignModules.Add(m.FileName);
                    bool userDir = file.Contains("\\temp\\") || file.Contains("\\downloads\\") || file.Contains("\\desktop\\") || file.Contains("\\appdata\\");
                    if (userDir) gp.Memory.Add("injection", 20, "native module from a user folder: " + m.FileName);
                }
            }
            catch
            {
            }
        }

        static void CheckPe(IntPtr h, long start, GameProcess gp)
        {
            var head = new byte[0x400];
            IntPtr read;
            if (!Native.ReadProcessMemory(h, (IntPtr)start, head, (IntPtr)head.Length, out read) || read.ToInt32() < 0x100) return;
            if (head[0] != 'M' || head[1] != 'Z') return;
            int lfanew = BitConverter.ToInt32(head, 0x3C);
            if (lfanew <= 0 || lfanew > 0x3F0) return;
            if (head[lfanew] == 'P' && head[lfanew + 1] == 'E' && head[lfanew + 2] == 0 && head[lfanew + 3] == 0)
                gp.UnbackedImages.Add(string.Format("PE image in private executable memory at 0x{0:X} (manually mapped / injected)", start));
        }

        static int Count(byte[] buf, int n, byte[] needle)
        {
            int c = 0, i = 0, last = n - needle.Length;
            byte first = needle[0];
            while (i <= last)
            {
                i = Array.IndexOf(buf, first, i, last - i + 1);
                if (i < 0) break;
                int k = 1;
                while (k < needle.Length && buf[i + k] == needle[k]) k++;
                if (k == needle.Length) c++;
                i++;
            }
            return c;
        }

        static bool PathChar(int c)
        {
            return c >= 0x20 && c < 0x7f && c != '"' && c != '<' && c != '>' && c != '|' && c != '*' && c != '?' && c != ';';
        }

        static void CarveAscii(byte[] buf, int n, byte[] pattern, HashSet<string> sink)
        {
            int i = 0;
            while (i <= n - 4)
            {
                i = Array.IndexOf(buf, pattern[0], i, n - 4 - i + 1);
                if (i < 0) return;
                if (buf[i + 1] == pattern[1] && buf[i + 2] == pattern[2] && buf[i + 3] == pattern[3])
                {
                    int s = i;
                    while (s > 0 && i - s < 400 && PathChar(buf[s - 1])) s--;
                    Keep(Encoding.ASCII.GetString(buf, s, i + 4 - s), sink);
                }
                i++;
            }
        }

        static void CarveWide(byte[] buf, int n, byte[] pattern, HashSet<string> sink)
        {
            int i = 0;
            while (i <= n - 8)
            {
                i = Array.IndexOf(buf, pattern[0], i, n - 8 - i + 1);
                if (i < 0) return;
                bool hit = true;
                for (int k = 1; k < 8; k++)
                {
                    if (buf[i + k] != pattern[k] && !(k % 2 == 0 && buf[i + k] == char.ToUpperInvariant((char)pattern[k])))
                    {
                        hit = false;
                        break;
                    }
                }
                if (hit && (i & 1) == 0)
                {
                    int s = i;
                    while (s > 1 && i - s < 800 && buf[s - 1] == 0 && PathChar(buf[s - 2])) s -= 2;
                    Keep(Encoding.Unicode.GetString(buf, s, i + 8 - s), sink);
                }
                i++;
            }
        }

        static readonly Regex Drive = new Regex(@"[A-Za-z]:[\\/]", RegexOptions.RightToLeft);

        static void Keep(string raw, HashSet<string> sink)
        {
            var m = Drive.Match(raw);
            if (!m.Success) return;
            string path = raw.Substring(m.Index);
            if (path.Contains("%"))
            {
                try { path = Uri.UnescapeDataString(path); } catch { }
            }
            path = path.Replace('/', '\\');
            if (path.Length < 8 || path.Contains("\\\\") || path.Contains("..")) return;
            if (sink.Count < MaxCarved) sink.Add(path);
        }

        public static bool Kill(int pid)
        {
            try
            {
                var p = Process.GetProcessById(pid);
                p.Kill();
                p.WaitForExit(5000);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
