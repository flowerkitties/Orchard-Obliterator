using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;

namespace OrchardObliterator
{
    static class Program
    {
        static bool deep, block, guard, noMemory, verbose, only;
        static int days = 30;
        static string reportPath;
        static readonly List<string> extraPaths = new List<string>();

        static readonly Dictionary<string, Evidence> probed = new Dictionary<string, Evidence>(StringComparer.OrdinalIgnoreCase);
        static readonly List<GameProcess> live = new List<GameProcess>();
        static readonly List<string> missingLoaded = new List<string>();

        static int Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            try { Console.Title = "Orchard Obliterator"; } catch { }

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--deep": deep = true; break;
                    case "--block": block = true; break;
                    case "--guard": guard = true; block = true; break;
                    case "--no-mem": noMemory = true; break;
                    case "--only": only = true; break;
                    case "--verbose": case "-v": verbose = true; break;
                    case "--quiet": Report.Quiet = true; break;
                    case "--path": if (i + 1 < args.Length) extraPaths.Add(args[++i]); break;
                    case "--days": if (i + 1 < args.Length) int.TryParse(args[++i], out days); break;
                    case "--out": if (i + 1 < args.Length) reportPath = args[++i]; break;
                    case "--fingerprint":
                        Fingerprints.Load();
                        JarScanner.DumpFingerprint(args[i + 1], Console.Out);
                        return 0;
                    case "--help": case "-h": case "/?":
                        Usage();
                        return 0;
                    default:
                        if (File.Exists(args[i]) || Directory.Exists(args[i])) extraPaths.Add(args[i]);
                        else { Console.Error.WriteLine("unknown option " + args[i]); Usage(); return 64; }
                        break;
                }
            }

            Banner();
            Fingerprints.Load();
            Report.Dim(string.Format("signatures: {0} ({1} hooks, {2} assets, {3} memory)", Fingerprints.LoadedFrom, Fingerprints.Footprint.Count, Fingerprints.Assets.Count, Fingerprints.Memory.Count));
            bool admin = Traces.IsAdmin();
            if (!admin) Report.Warn("not elevated: prefetch, USN journal and elevated games are skipped. Run as admin for the full sweep.");

            var clock = Stopwatch.StartNew();
            Scan(admin);
            int code = Summary();
            Report.Dim(string.Format("took {0:0.0}s", clock.Elapsed.TotalSeconds));

            if (block) Obliterate();
            string saved = Report.Save(reportPath);
            Report.Dim("report saved to " + saved);

            if (guard) Guard.Run(probed, Probe);
            return code;
        }

        static void Usage()
        {
            Console.WriteLine("OrchardObliterator [options] [file|folder ...]");
            Console.WriteLine();
            Console.WriteLine("  --deep            sweep every fixed drive for archives, any extension");
            Console.WriteLine("  --block           kill the game and quarantine Orchard jars it finds");
            Console.WriteLine("  --guard           stay running, watch game folders and new java processes, block on sight");
            Console.WriteLine("  --no-mem          skip reading java process memory");
            Console.WriteLine("  --path <p>        also scan this file or folder (repeatable)");
            Console.WriteLine("  --only            scan just the --path targets, skip the rest");
            Console.WriteLine("  --days <n>        how far back to read the USN journal (default 30)");
            Console.WriteLine("  --out <file>      where to write the report");
            Console.WriteLine("  --verbose         list clean archives too");
            Console.WriteLine("  --fingerprint <f> print hooks/asset keys of a sample, for orchard.sig");
        }

        static void Banner()
        {
            Report.Section("Orchard Obliterator 1.0");
            Report.Dim(string.Format("{0} / {1} / {2:yyyy-MM-dd HH:mm:ss}", Environment.MachineName, Environment.UserName, DateTime.Now));
        }

        static void Scan(bool admin)
        {
            var gameDirs = only ? new List<string>() : Locations.GameDirs();

            Report.Section("Running game");
            var procs = Hunter.FindJava();
            if (procs.Count == 0) Report.Info("no java processes running");
            foreach (var gp in procs)
            {
                live.Add(gp);
                Report.Info(string.Format("{0} pid {1}{2}", gp.Name, gp.Pid, gp.Fabric ? " (fabric)" : ""));
                if (!string.IsNullOrEmpty(gp.GameDir))
                {
                    Report.Dim("gameDir " + gp.GameDir);
                    Locations.AddUnique(gameDirs, gp.GameDir);
                }
                if (verbose) foreach (var f in gp.Flags) Report.Dim(f);

                if (!noMemory)
                {
                    Hunter.Inspect(gp);
                    if (gp.Denied) Report.Warn("could not open process memory (game runs elevated? rerun as admin)");
                    else Report.Dim(string.Format("{0:N0} MB of memory read, {1} mixin classes recovered, {2} jar paths carved", gp.Scanned >> 20, gp.MixinClasses, gp.CarvedJars.Count));
                    foreach (var d in gp.DeletedOpen) Report.Bad(string.Format("pid {0} still holds deleted jar {1}", gp.Pid, d));
                    if (verbose) foreach (var m in gp.ForeignModules) Report.Dim("non-JDK native module: " + m);
                    if (gp.Memory.Level == Level.Confirmed || (verbose && gp.Memory.Hits.Count > 0)) Report.Evidence(gp.Memory);
                }

                var candidates = new List<string>(gp.ArgJars);
                candidates.AddRange(gp.CarvedJars);
                if (!string.IsNullOrEmpty(gp.GameDir) && Directory.Exists(Path.Combine(gp.GameDir, "mods")))
                    candidates.AddRange(Locations.Walk(Path.Combine(gp.GameDir, "mods"), 4));

                foreach (var c in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    if (File.Exists(c))
                    {
                        var ev = Probe(c);
                        if (ev != null && ev.Level == Level.Confirmed)
                        {
                            gp.JarsInUse.Add(c);
                            Report.Bad(string.Format("jar in use by pid {0}: {1}", gp.Pid, c));
                        }
                    }
                    else if (LooksLikeModPath(c) && (verbose || c.ToLowerInvariant().Contains("orchard") || (gp.Memory != null && gp.Memory.Level == Level.Confirmed)))
                    {
                        missingLoaded.Add(c);
                        Report.Warn(string.Format("pid {0} has {1} in memory but the file is gone", gp.Pid, c));
                    }
                }
            }

            if (only)
            {
                Report.Section("Selected paths");
                ScanExtra();
                return;
            }

            Report.Section("Game folders");
            var spent = new Dictionary<string, Stopwatch>();
            Func<string, Stopwatch> clock = k =>
            {
                Stopwatch w;
                if (!spent.TryGetValue(k, out w)) spent[k] = w = new Stopwatch();
                return w;
            };
            foreach (var dir in gameDirs)
            {
                var whole = Stopwatch.StartNew();
                Report.Info(dir);
                foreach (var sub in new[] { "mods", ".fabric", "versions", "libraries", "config", "shaderpacks", "resourcepacks" })
                {
                    string d = Path.Combine(dir, sub);
                    if (!Directory.Exists(d)) continue;
                    clock(sub).Start();
                    SweepFolder(d, 12, sub == "mods" || sub == "config");
                    clock(sub).Stop();
                }
                clock("root").Start();
                foreach (var f in SafeFiles(dir)) { Traces.AlternateStreams(f); ProbeIfArchive(f); }
                clock("root").Stop();
                clock("logs").Start();
                Traces.Logs(dir);
                clock("logs").Stop();
                clock("launch configs").Start();
                Traces.LaunchConfigs(dir);
                clock("launch configs").Stop();
                if (verbose && whole.Elapsed.TotalSeconds > 5) Report.Dim(string.Format("{0:0.0}s in this folder", whole.Elapsed.TotalSeconds));
            }
            if (verbose)
                Report.Dim("time by step: " + string.Join(", ", spent.OrderByDescending(kv => kv.Value.Elapsed).Select(kv => string.Format("{0} {1:0.0}s", kv.Key, kv.Value.Elapsed.TotalSeconds))));
            if (verbose)
                foreach (var r in Locations.ReparsePoints.Distinct()) Report.Warn("folder is a junction/symlink (could point at a USB stick): " + r);

            Report.Section("Loose files");
            foreach (var dir in Locations.LooseDirs())
            {
                Report.Progress("  " + dir);
                SweepFolder(dir, dir.StartsWith(Path.GetTempPath().TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ? 5 : 3, false);
            }
            ScanExtra();
            if (deep)
            {
                foreach (var drive in Locations.FixedDrives())
                {
                    Report.Info("deep sweep " + drive);
                    SweepFolder(drive, 40, false);
                }
            }
            Report.ClearProgress();

            Report.Section("Traces left behind");
            Traces.RecycleBin();
            Traces.RecentItems();
            if (admin)
            {
                Traces.Prefetch();
                Traces.UsnJournal(days);
            }
            foreach (var f in Traces.ExtraFiles.Distinct(StringComparer.OrdinalIgnoreCase).ToList())
            {
                if (f.IndexOf(':', 2) > 0) ProbeStream(f);
                else Probe(f);
            }
            if (!Traces.Found.Any(t => t.Tier > Traces.Noise))
                Report.Good("no Orchard traces in logs, recycle bin, recent items" + (admin ? ", prefetch or USN journal" : ""));
            foreach (var t in Traces.Found.OrderByDescending(t => t.Tier))
            {
                if (t.Tier == Traces.Proof) Report.Bad(t.What);
                else if (t.Tier == Traces.Lead) Report.Warn(t.What + "  (name only, not proof)");
                else if (verbose) Report.Dim(t.What);
                else continue;
                Report.Dim(t.Where);
            }
        }

        static void ScanExtra()
        {
            foreach (var p in extraPaths)
            {
                if (File.Exists(p)) { Traces.AlternateStreams(p); Probe(p); }
                else SweepFolder(p, 30, true);
            }
            foreach (var f in Traces.ExtraFiles.Distinct(StringComparer.OrdinalIgnoreCase).ToList())
                if (f.IndexOf(':', 2) > 0) ProbeStream(f);
        }

        static bool LooksLikeModPath(string p)
        {
            string l = p.ToLowerInvariant();
            return l.Contains("\\mods\\") || l.Contains("orchard") || l.Contains("\\temp\\") || l.Contains("\\downloads\\") || l.Contains("\\desktop\\");
        }

        static IEnumerable<string> SafeFiles(string dir)
        {
            try { return Directory.GetFiles(dir); }
            catch { return new string[0]; }
        }

        static void SweepFolder(string root, int depth, bool streams)
        {
            var files = new List<string>();
            foreach (var f in Locations.Walk(root, depth))
            {
                if (files.Count % 200 == 0) Report.Progress("  " + f);
                if (streams) Traces.AlternateStreams(f);
                if (!probed.ContainsKey(f)) files.Add(f);
            }
            ProbeMany(files);
        }

        static void ProbeMany(List<string> files)
        {
            var results = new Evidence[files.Count];
            var options = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(2, Math.Min(8, Environment.ProcessorCount)) };
            Parallel.For(0, files.Count, options, i =>
            {
                if (!Locations.IsArchive(files[i], 300, 400L * 1024 * 1024)) return;
                var sw = Stopwatch.StartNew();
                var ev = JarScanner.InspectFile(files[i]);
                if (verbose && sw.ElapsedMilliseconds > 1500)
                    ev.Notes.Add(string.Format("slow: {0:N0} ms", sw.ElapsedMilliseconds));
                results[i] = ev;
            });
            for (int i = 0; i < files.Count; i++)
            {
                if (results[i] == null || probed.ContainsKey(files[i])) continue;
                probed[files[i]] = results[i];
                Show(results[i]);
            }
        }

        static void ProbeIfArchive(string f)
        {
            if (probed.ContainsKey(f)) return;
            if (!Locations.IsArchive(f, 300, 400L * 1024 * 1024)) return;
            Probe(f);
        }

        static Evidence Probe(string path)
        {
            Evidence ev;
            if (probed.TryGetValue(path, out ev)) return ev;
            var sw = Stopwatch.StartNew();
            ev = JarScanner.InspectFile(path);
            probed[path] = ev;
            if (verbose && sw.ElapsedMilliseconds > 1500)
                ev.Notes.Add(string.Format("slow: {0:N0} ms", sw.ElapsedMilliseconds));
            Show(ev);
            return ev;
        }

        static void ProbeStream(string stream)
        {
            if (probed.ContainsKey(stream)) return;
            byte[] data = null;
            try { data = Traces.ReadStream(stream); } catch { }
            if (data == null) return;
            var ev = JarScanner.Inspect(data, stream, ".stream", 0);
            probed[stream] = ev;
            Show(ev);
        }

        static void Show(Evidence ev)
        {
            if (ev.Level != Level.Clean || verbose)
            {
                Report.ClearProgress();
                Report.Evidence(ev);
                if (ev.Level != Level.Clean)
                {
                    string zone = Traces.ZoneIdentifier(ev.Source);
                    if (zone != null) Report.Dim("downloaded from: " + (zone.Length > 220 ? zone.Substring(0, 220) + "..." : zone));
                }
            }
        }

        static int Summary()
        {
            var confirmed = probed.Values.Where(e => e.Level == Level.Confirmed).ToList();
            var liveHits = live.Where(g => g.Memory != null && g.Memory.Level == Level.Confirmed).ToList();
            var proof = Traces.Found.Where(t => t.Tier == Traces.Proof).ToList();
            var leads = Traces.Found.Where(t => t.Tier == Traces.Lead).ToList();

            Report.Section("Verdict");
            foreach (var g in liveHits) Report.Bad(string.Format("Orchard is running right now in {0} pid {1} (score {2})", g.Name, g.Pid, g.Memory.Score));
            foreach (var e in confirmed) Report.Bad("Orchard jar: " + e.Source);
            if (liveHits.Count > 0 && confirmed.Count == 0)
                Report.Bad("the running cheat has no jar on disk: it was loaded and then deleted, renamed or pulled from removable media");
            foreach (var m in missingLoaded) Report.Warn("loaded but missing: " + m);
            if (proof.Count > 0) Report.Bad(proof.Count + " log/crash entr" + (proof.Count == 1 ? "y proves" : "ies prove") + " Orchard ran on this PC");
            if (leads.Count > 0) Report.Warn(leads.Count + " name-only lead(s) above; filenames are not proof");

            Report.Info(string.Format("{0} archives checked, {1} java process(es) inspected", probed.Count, live.Count));
            Report.Info("");
            if (liveHits.Count > 0 || confirmed.Count > 0)
            {
                Report.Bad("RESULT: ORCHARD DETECTED");
                return 2;
            }
            if (proof.Count > 0)
            {
                Report.Bad("RESULT: ORCHARD WAS USED (no jar left on disk)");
                return 2;
            }
            Report.Good("RESULT: NO ORCHARD");
            return 0;
        }

        static void Obliterate()
        {
            Report.Section("Blocking");
            foreach (var g in live)
            {
                bool usesJar = g.JarsInUse.Count > 0;
                bool hot = g.Memory != null && g.Memory.Level == Level.Confirmed;
                if (!hot && !usesJar) continue;
                if (Hunter.Kill(g.Pid)) Report.Bad(string.Format("killed {0} pid {1}", g.Name, g.Pid));
                else Report.Warn(string.Format("could not kill pid {0}", g.Pid));
            }
            foreach (var e in probed.Values.Where(x => x.Level == Level.Confirmed).ToList())
                Quarantine.Lock(e.Source);
        }
    }
}
