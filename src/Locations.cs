using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace OrchardObliterator
{
    static class Locations
    {
        static readonly string AppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        static readonly string Home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        static readonly string[] SkipDirs =
        {
            "\\windows\\", "\\windowsapps\\", "\\system volume information\\", "\\$recycle.bin\\",
            "\\$windows.~bt\\", "\\$winreagent\\", "\\assets\\objects\\", "\\node_modules\\", "\\.git\\",
            "\\saves\\", "\\.bobby\\", "\\xaero", "\\.voxy\\", "\\replay_recordings\\", "\\distant_horizons",
            "\\webcache2\\", "\\gpucache\\", "\\flashback\\"
        };

        static readonly HashSet<string> DeadEnds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "node_modules", ".git", ".gradle", ".m2", ".cargo", ".rustup", ".nuget", "saves", ".bobby", ".voxy",
            "objects", "replay_recordings", "webcache2", "gpucache", "winsxs", "$recycle.bin", "windowsapps",
            "system volume information", "$windows.~bt", "$winreagent", "assets", "libraries", "jre", "runtime"
        };

        static readonly string[] LauncherConfigs = { "prismlauncher.cfg", "polymc.cfg", "multimc.cfg", "pollymc.cfg", "ultimmc.cfg" };

        static List<string> discovered;

        public static List<string> GameDirs()
        {
            var dirs = new List<string>();
            foreach (var d in Discover()) Add(dirs, d);
            Add(dirs, Path.Combine(AppData, ".minecraft"));
            Add(dirs, Path.Combine(AppData, ".tlauncher"));
            Add(dirs, Path.Combine(AppData, ".feather"));
            Add(dirs, Path.Combine(Home, ".lunarclient"));
            Add(dirs, Path.Combine(AppData, ".technic", "modpacks"));

            foreach (var root in new[]
            {
                Path.Combine(AppData, "PrismLauncher", "instances"),
                Path.Combine(AppData, "PolyMC", "instances"),
                Path.Combine(AppData, "MultiMC", "instances"),
                Path.Combine(AppData, "ModrinthApp", "profiles"),
                Path.Combine(AppData, "com.modrinth.theseus", "profiles"),
                Path.Combine(Home, "curseforge", "minecraft", "Instances"),
                Path.Combine(AppData, "ATLauncher", "instances"),
                Path.Combine(AppData, "gdlauncher_next", "instances"),
                Path.Combine(AppData, "gdlauncher_carbon", "data", "instances")
            })
            {
                if (!Directory.Exists(root)) continue;
                foreach (var d in SafeDirs(root))
                {
                    if (Directory.Exists(Path.Combine(d, ".minecraft"))) Add(dirs, Path.Combine(d, ".minecraft"));
                    else if (Directory.Exists(Path.Combine(d, "minecraft"))) Add(dirs, Path.Combine(d, "minecraft"));
                    else Add(dirs, d);
                }
            }
            return dirs;
        }

        public static List<string> Discover()
        {
            if (discovered != null) return discovered;
            discovered = new List<string>();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var instanceRoots = new List<string>();

            var roots = new List<KeyValuePair<string, int>>
            {
                new KeyValuePair<string, int>(AppData, 7),
                new KeyValuePair<string, int>(local, 7),
                new KeyValuePair<string, int>(Home, 7)
            };
            foreach (var drive in FixedDrives()) roots.Add(new KeyValuePair<string, int>(drive, 6));

            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var root in roots)
            {
                var stack = new Stack<KeyValuePair<string, int>>();
                stack.Push(root);
                while (stack.Count > 0 && visited.Count < 600000 && sw.Elapsed.TotalSeconds < 45)
                {
                    var cur = stack.Pop();
                    if (!visited.Add(cur.Key)) continue;
                    if (visited.Count % 2000 == 0) Report.Progress("  looking for game folders: " + cur.Key);

                    if (IsGameDir(cur.Key)) Add(discovered, cur.Key);
                    foreach (var cfg in LauncherConfigs)
                    {
                        string path = Path.Combine(cur.Key, cfg);
                        if (File.Exists(path)) instanceRoots.AddRange(InstanceDirsFrom(path));
                    }

                    if (cur.Value <= 0) continue;
                    string[] subs;
                    try { subs = Directory.GetDirectories(cur.Key); } catch { continue; }
                    foreach (var s in subs)
                    {
                        string leaf = Path.GetFileName(s);
                        if (DeadEnds.Contains(leaf)) continue;
                        if (cur.Key.Length <= 3 && (leaf.Equals("Windows", StringComparison.OrdinalIgnoreCase) || leaf.Equals("Users", StringComparison.OrdinalIgnoreCase))) continue;
                        try
                        {
                            if ((File.GetAttributes(s) & FileAttributes.ReparsePoint) != 0) continue;
                        }
                        catch
                        {
                            continue;
                        }
                        stack.Push(new KeyValuePair<string, int>(s, cur.Value - 1));
                    }
                }
            }

            foreach (var root in instanceRoots.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                foreach (var d in SafeDirs(root))
                {
                    foreach (var c in new[] { Path.Combine(d, ".minecraft"), Path.Combine(d, "minecraft"), d })
                        if (IsGameDir(c)) { Add(discovered, c); break; }
                }
            }
            Report.ClearProgress();
            return discovered;
        }

        static bool IsGameDir(string dir)
        {
            try
            {
                if (!Directory.Exists(Path.Combine(dir, "mods"))) return false;
                string leaf = Path.GetFileName(dir).ToLowerInvariant();
                return leaf == ".minecraft" || leaf == "minecraft"
                       || File.Exists(Path.Combine(dir, "options.txt"))
                       || Directory.Exists(Path.Combine(dir, "config"))
                       || Directory.Exists(Path.Combine(dir, "logs"))
                       || Directory.Exists(Path.Combine(dir, "saves"));
            }
            catch
            {
                return false;
            }
        }

        static IEnumerable<string> InstanceDirsFrom(string cfg)
        {
            var found = new List<string>();
            string baseDir = Path.GetDirectoryName(cfg);
            try
            {
                foreach (var line in File.ReadAllLines(cfg))
                {
                    if (!line.StartsWith("InstanceDir=", StringComparison.OrdinalIgnoreCase)) continue;
                    string v = line.Substring(12).Trim().Trim('"');
                    if (v.Length == 0) continue;
                    found.Add(Path.IsPathRooted(v) ? v : Path.Combine(baseDir, v));
                }
            }
            catch
            {
            }
            found.Add(Path.Combine(baseDir, "instances"));
            return found.Where(Directory.Exists);
        }

        public static List<string> LooseDirs()
        {
            var list = new List<string>();
            Add(list, Path.Combine(Home, "Downloads"));
            Add(list, Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
            Add(list, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            Add(list, Path.GetTempPath());
            Add(list, Path.Combine(AppData, "..", "LocalLow"));
            return list;
        }

        static void Add(List<string> list, string path)
        {
            try
            {
                path = Path.GetFullPath(path).TrimEnd('\\');
                if (Directory.Exists(path) && !list.Any(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase)))
                    list.Add(path);
            }
            catch
            {
            }
        }

        public static void AddUnique(List<string> list, string path)
        {
            Add(list, path);
        }

        static IEnumerable<string> SafeDirs(string root)
        {
            try { return Directory.GetDirectories(root); }
            catch { return new string[0]; }
        }

        public static IEnumerable<string> Walk(string root, int maxDepth)
        {
            var stack = new Stack<KeyValuePair<string, int>>();
            stack.Push(new KeyValuePair<string, int>(root, 0));
            while (stack.Count > 0)
            {
                var cur = stack.Pop();
                string dir = cur.Key;
                string probe = dir.ToLowerInvariant() + "\\";
                if (SkipDirs.Any(s => probe.Contains(s)) && cur.Value > 0) continue;

                string[] files = null, subs = null;
                try { files = Directory.GetFiles(dir); } catch { }
                try { subs = Directory.GetDirectories(dir); } catch { }

                if (files != null)
                    foreach (var f in files) yield return f;

                if (subs == null || cur.Value >= maxDepth) continue;
                foreach (var s in subs)
                {
                    try
                    {
                        var attr = File.GetAttributes(s);
                        if ((attr & FileAttributes.ReparsePoint) != 0)
                        {
                            ReparsePoints.Add(s);
                            continue;
                        }
                    }
                    catch
                    {
                        continue;
                    }
                    stack.Push(new KeyValuePair<string, int>(s, cur.Value + 1));
                }
            }
        }

        public static readonly List<string> ReparsePoints = new List<string>();

        public static bool IsArchive(string path, long minSize, long maxSize)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (fs.Length < minSize || fs.Length > maxSize) return false;
                    var head = new byte[4];
                    int h = fs.Read(head, 0, 4);
                    if (h == 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4) return true;

                    int tailLen = (int)Math.Min(fs.Length, 1024);
                    var tail = new byte[tailLen];
                    fs.Seek(-tailLen, SeekOrigin.End);
                    int t = 0;
                    while (t < tailLen)
                    {
                        int got = fs.Read(tail, t, tailLen - t);
                        if (got <= 0) break;
                        t += got;
                    }
                    return Zip.LooksLikeZip(head, h, tail, t);
                }
            }
            catch
            {
                return false;
            }
        }

        public static IEnumerable<string> FixedDrives()
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                bool ok = false;
                try { ok = d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable); } catch { }
                if (ok) yield return d.RootDirectory.FullName;
            }
        }
    }
}
