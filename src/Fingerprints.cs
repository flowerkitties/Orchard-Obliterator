using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace OrchardObliterator
{
    sealed class MemorySignature
    {
        public string Kind;
        public int Weight;
        public string Text;
        public byte[] Bytes;
    }

    static class Fingerprints
    {
        public static readonly Dictionary<string, string> KnownFiles = new Dictionary<string, string>();
        public static readonly List<string> NameTokens = new List<string>();
        public static readonly Dictionary<string, string> Assets = new Dictionary<string, string>();
        public static readonly HashSet<string> Footprint = new HashSet<string>(StringComparer.Ordinal);
        public static readonly Dictionary<string, string> StealthHooks = new Dictionary<string, string>();
        public static readonly Dictionary<string, string> CombatHooks = new Dictionary<string, string>();
        public static readonly HashSet<string> Watermarks = new HashSet<string>();
        public static readonly HashSet<string> LoaderApis = new HashSet<string>();
        public static readonly List<MemorySignature> Memory = new List<MemorySignature>();
        public static readonly List<string> LogPatterns = new List<string>();
        public static readonly List<string> TrustedHosts = new List<string>();
        public static string LoadedFrom = "built-in";

        public static void Load()
        {
            string local = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "orchard.sig");
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("orchard.sig"))
            using (var r = new StreamReader(s, Encoding.UTF8))
                Parse(r);

            if (File.Exists(local))
            {
                using (var r = new StreamReader(local, Encoding.UTF8))
                    Parse(r);
                LoadedFrom = "built-in + " + local;
            }
        }

        static void Parse(TextReader r)
        {
            string line;
            while ((line = r.ReadLine()) != null)
            {
                line = line.Trim();
                if (line.Length == 0 || line[0] == '#') continue;
                var parts = line.Split(new[] { ' ' }, 3);
                string rest = parts.Length > 2 ? parts[2] : "";
                switch (parts[0])
                {
                    case "file": KnownFiles[parts[1]] = rest; break;
                    case "token": NameTokens.Add(parts[1]); break;
                    case "asset": Assets[parts[1]] = rest; break;
                    case "hook": Footprint.Add(parts[1]); break;
                    case "stealth": StealthHooks[parts[1]] = rest; break;
                    case "combat": CombatHooks[parts[1]] = rest; break;
                    case "watermark": Watermarks.Add(Unescape(line.Substring(10))); break;
                    case "loader": LoaderApis.Add(parts[1]); break;
                    case "log": LogPatterns.Add(line.Substring(4)); break;
                    case "host": TrustedHosts.Add(parts[1]); break;
                    case "mem":
                        var bits = line.Split(new[] { ' ' }, 4);
                        string text = Unescape(bits[3]);
                        Memory.Add(new MemorySignature
                        {
                            Kind = bits[1],
                            Weight = int.Parse(bits[2]),
                            Text = text,
                            Bytes = Encoding.UTF8.GetBytes(text)
                        });
                        break;
                }
            }
        }

        static string Unescape(string s)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == '\\' && i + 5 < s.Length && s[i + 1] == 'u')
                {
                    sb.Append((char)Convert.ToInt32(s.Substring(i + 2, 4), 16));
                    i += 5;
                }
                else sb.Append(s[i]);
            }
            return sb.ToString();
        }
    }
}
