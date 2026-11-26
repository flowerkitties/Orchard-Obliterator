using System;
using System.IO;
using System.Text;

namespace OrchardObliterator
{
    static class Report
    {
        static readonly StringBuilder log = new StringBuilder();
        static readonly object gate = new object();
        public static bool Quiet;

        static readonly System.Diagnostics.Stopwatch phase = System.Diagnostics.Stopwatch.StartNew();
        static string current;

        public static void Section(string title)
        {
            if (current != null && phase.Elapsed.TotalSeconds >= 0.5)
                Line(string.Format("     ({0} took {1:0.0}s)", current.ToLowerInvariant(), phase.Elapsed.TotalSeconds), ConsoleColor.DarkGray);
            current = title;
            phase.Restart();
            Line("", ConsoleColor.Gray);
            Line("== " + title + " " + new string('=', Math.Max(3, 66 - title.Length)), ConsoleColor.DarkCyan);
        }

        public static void Info(string text) { Line("   " + text, ConsoleColor.Gray); }
        public static void Dim(string text) { Line("     " + text, ConsoleColor.DarkGray); }
        public static void Good(string text) { Line(" + " + text, ConsoleColor.Green); }
        public static void Warn(string text) { Line(" ? " + text, ConsoleColor.Yellow); }
        public static void Bad(string text) { Line(" ! " + text, ConsoleColor.Red); }

        public static void Evidence(Evidence ev)
        {
            var level = ev.Level;
            string tag = level == Level.Confirmed ? "ORCHARD" : "clean";
            string head = string.Format("[{0} {1}] {2}", tag, ev.Score, ev.Source);
            if (level == Level.Confirmed) Bad(head);
            else Info(head);

            foreach (var n in ev.Notes) Dim(n);
            foreach (var h in ev.Hits) Dim(string.Format("{0,-9} +{1,-3} {2}", h.Kind, h.Weight, h.Detail));
        }

        public static void Progress(string text)
        {
            if (Quiet || Console.IsOutputRedirected) return;
            lock (gate)
            {
                int width = 78;
                try { width = Math.Max(20, Console.WindowWidth - 1); } catch { }
                if (text.Length > width) text = "..." + text.Substring(text.Length - width + 3);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("\r" + text.PadRight(width) + "\r");
                Console.ResetColor();
            }
        }

        public static void ClearProgress()
        {
            Progress("");
        }

        static void Line(string text, ConsoleColor color)
        {
            lock (gate)
            {
                log.AppendLine(text);
                if (Quiet) return;
                Console.ForegroundColor = color;
                Console.WriteLine(text);
                Console.ResetColor();
            }
        }

        public static string Save(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                string name = string.Format("OrchardObliterator_{0}_{1:yyyyMMdd_HHmmss}.txt", Environment.MachineName, DateTime.Now);
                path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, name);
            }
            try
            {
                File.WriteAllText(path, log.ToString(), Encoding.UTF8);
            }
            catch
            {
                path = Path.Combine(Path.GetTempPath(), Path.GetFileName(path));
                File.WriteAllText(path, log.ToString(), Encoding.UTF8);
            }
            return path;
        }
    }
}
