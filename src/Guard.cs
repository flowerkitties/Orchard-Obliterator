using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace OrchardObliterator
{
    static class Guard
    {
        static readonly ConcurrentDictionary<string, DateTime> queue = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        static readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();

        public static void Run(Dictionary<string, Evidence> cache, Func<string, Evidence> probe)
        {
            Report.Section("Guard");
            var dirs = Locations.GameDirs();
            foreach (var d in Locations.LooseDirs()) Locations.AddUnique(dirs, d);
            foreach (var d in dirs) Watch(d);
            Report.Info(string.Format("watching {0} folders and every new java process. Ctrl+C to stop.", watchers.Count));

            var known = new HashSet<int>(Process.GetProcesses().Select(p => p.Id));
            var pending = new Dictionary<int, DateTime>();
            bool stop = false;
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; stop = true; };

            while (!stop)
            {
                Thread.Sleep(700);

                foreach (var kv in queue.ToArray())
                {
                    if ((DateTime.Now - kv.Value).TotalMilliseconds < 1200) continue;
                    DateTime dummy;
                    queue.TryRemove(kv.Key, out dummy);
                    if (!File.Exists(kv.Key) || !Locations.IsArchive(kv.Key, 300, 400L * 1024 * 1024)) continue;
                    cache.Remove(kv.Key);
                    var ev = probe(kv.Key);
                    if (ev.Level == Level.Confirmed)
                    {
                        Report.Bad(string.Format("{0:HH:mm:ss} Orchard dropped into {1}", DateTime.Now, kv.Key));
                        Quarantine.Lock(kv.Key);
                    }
                }

                foreach (var gp in Hunter.FindJava())
                {
                    if (known.Contains(gp.Pid) && !pending.ContainsKey(gp.Pid)) continue;
                    if (!known.Contains(gp.Pid))
                    {
                        known.Add(gp.Pid);
                        pending[gp.Pid] = DateTime.Now;
                        Report.Info(string.Format("{0:HH:mm:ss} new {1} pid {2}", DateTime.Now, gp.Name, gp.Pid));
                        if (!string.IsNullOrEmpty(gp.GameDir)) Watch(gp.GameDir);
                        if (QuickCheck(gp, cache, probe)) { pending.Remove(gp.Pid); continue; }
                    }
                    if ((DateTime.Now - pending[gp.Pid]).TotalSeconds < 20) continue;
                    pending.Remove(gp.Pid);

                    Hunter.Inspect(gp);
                    if (gp.Memory.Level == Level.Confirmed)
                    {
                        Report.Evidence(gp.Memory);
                        Terminate(gp, "Orchard classes found in memory");
                    }
                    else
                    {
                        Report.Good(string.Format("pid {0} memory clean ({1:N0} MB read)", gp.Pid, gp.Scanned >> 20));
                    }
                }
            }
            foreach (var w in watchers) w.Dispose();
        }

        static bool QuickCheck(GameProcess gp, Dictionary<string, Evidence> cache, Func<string, Evidence> probe)
        {
            var jars = new List<string>(gp.ArgJars);
            if (!string.IsNullOrEmpty(gp.GameDir) && Directory.Exists(Path.Combine(gp.GameDir, "mods")))
                jars.AddRange(Locations.Walk(Path.Combine(gp.GameDir, "mods"), 4));

            var bad = new List<string>();
            foreach (var j in jars.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!File.Exists(j)) continue;
                cache.Remove(j);
                if (probe(j).Level == Level.Confirmed) bad.Add(j);
            }
            if (bad.Count == 0) return false;
            Terminate(gp, "launching with " + bad[0]);
            foreach (var b in bad) Quarantine.Lock(b);
            return true;
        }

        static void Terminate(GameProcess gp, string why)
        {
            if (Hunter.Kill(gp.Pid)) Report.Bad(string.Format("{0:HH:mm:ss} killed {1} pid {2}: {3}", DateTime.Now, gp.Name, gp.Pid, why));
            else Report.Warn(string.Format("could not kill pid {0} ({1})", gp.Pid, why));
        }

        static void Watch(string dir)
        {
            if (!Directory.Exists(dir) || watchers.Any(w => string.Equals(w.Path, dir, StringComparison.OrdinalIgnoreCase))) return;
            try
            {
                var w = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024
                };
                FileSystemEventHandler touch = (s, e) => queue[e.FullPath] = DateTime.Now;
                w.Created += touch;
                w.Changed += touch;
                w.Renamed += (s, e) => queue[e.FullPath] = DateTime.Now;
                w.EnableRaisingEvents = true;
                watchers.Add(w);
            }
            catch
            {
            }
        }
    }
}
