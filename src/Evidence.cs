using System;
using System.Collections.Generic;
using System.Linq;

namespace OrchardObliterator
{
    enum Level
    {
        Clean,
        Confirmed
    }

    sealed class Hit
    {
        public string Kind;
        public string Detail;
        public int Weight;
    }

    sealed class Evidence
    {
        public const int ConfirmAt = 100;

        static readonly Dictionary<string, int> Caps = new Dictionary<string, int>
        {
            { "hash", 100 },
            { "meta", 100 },
            { "namespace", 105 },
            { "footprint", 100 },
            { "asset", 80 },
            { "lang", 40 },
            { "integrity", 70 },
            { "packer", 60 },
            { "stealth", 60 },
            { "combat", 32 },
            { "hiding", 40 },
            { "injection", 60 }
        };

        static readonly HashSet<string> OrchardOnly = new HashSet<string> { "hash", "meta", "namespace", "footprint", "asset", "lang" };

        public readonly string Source;
        public readonly List<Hit> Hits = new List<Hit>();
        public readonly List<string> Notes = new List<string>();
        readonly HashSet<string> seen = new HashSet<string>();

        public Evidence(string source)
        {
            Source = source;
        }

        public void Add(string kind, int weight, string detail)
        {
            if (!seen.Add(kind + "|" + detail)) return;
            Hits.Add(new Hit { Kind = kind, Weight = weight, Detail = detail });
        }

        public void Absorb(Evidence child, string prefix)
        {
            foreach (var h in child.Hits)
                Add(h.Kind, h.Weight, prefix + h.Detail);
        }

        public static bool IsOrchardOnly(string kind)
        {
            return OrchardOnly.Contains(kind);
        }

        int Sum(Func<Hit, bool> filter)
        {
            int total = 0;
            foreach (var g in Hits.Where(filter).GroupBy(h => h.Kind))
            {
                int sum = g.Sum(h => h.Weight);
                int cap;
                total += Caps.TryGetValue(g.Key, out cap) ? Math.Min(sum, cap) : sum;
            }
            return total;
        }

        public int OrchardScore
        {
            get { return Sum(h => OrchardOnly.Contains(h.Kind)); }
        }

        public int Score
        {
            get { return OrchardScore >= ConfirmAt ? Sum(h => true) : OrchardScore; }
        }

        public Level Level
        {
            get { return OrchardScore >= ConfirmAt ? Level.Confirmed : Level.Clean; }
        }
    }
}
