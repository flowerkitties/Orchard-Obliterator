using System;
using System.Collections.Generic;
using System.Text;

namespace OrchardObliterator
{
    sealed class ClassFile
    {
        public readonly List<string> Strings = new List<string>();
        public readonly List<string> MixinTargets = new List<string>();
        public readonly List<string> HookedMethods = new List<string>();
        public string DebugExtension;
        public string Name;
        public bool IsMixin;
        public bool Complete;
        public int Length;

        string[] utf8;
        int[] classNameIndex;
        byte[] b;
        int p;

        public static ClassFile Parse(byte[] data)
        {
            return Parse(data, 0);
        }

        public static ClassFile Parse(byte[] data, int offset)
        {
            if (data == null || offset < 0 || data.Length - offset < 10) return null;
            if (data[offset] != 0xCA || data[offset + 1] != 0xFE || data[offset + 2] != 0xBA || data[offset + 3] != 0xBE) return null;
            var cf = new ClassFile();
            try
            {
                cf.b = data;
                cf.p = offset + 8;
                cf.Read();
                cf.Complete = true;
                cf.Length = cf.p - offset;
            }
            catch
            {
            }
            cf.b = null;
            return cf;
        }

        void Read()
        {
            int count = U2();
            utf8 = new string[count];
            classNameIndex = new int[count];
            for (int i = 1; i < count; i++)
            {
                int tag = b[p++];
                switch (tag)
                {
                    case 1:
                        int len = U2();
                        utf8[i] = DecodeModifiedUtf8(b, p, len);
                        Strings.Add(utf8[i]);
                        p += len;
                        break;
                    case 7:
                        classNameIndex[i] = U2();
                        break;
                    case 3: case 4: case 9: case 10: case 11: case 12: case 17: case 18:
                        p += 4;
                        break;
                    case 5: case 6:
                        p += 8;
                        i++;
                        break;
                    case 8: case 16: case 19: case 20:
                        p += 2;
                        break;
                    case 15:
                        p += 3;
                        break;
                    default:
                        throw new FormatException();
                }
            }

            p += 2;
            int self = U2();
            if (self > 0 && self < count) Name = Utf(classNameIndex[self]);
            p += 2;
            int interfaces = U2();
            p += interfaces * 2;

            SkipMembers(false);
            SkipMembers(true);

            int attrs = U2();
            for (int i = 0; i < attrs; i++)
            {
                string name = Utf(U2());
                int len = U4();
                int end = p + len;
                if (name == "RuntimeInvisibleAnnotations" || name == "RuntimeVisibleAnnotations")
                    ReadAnnotations(true);
                else if (name == "SourceDebugExtension")
                    DebugExtension = DecodeModifiedUtf8(b, p, Math.Min(len, 512));
                p = end;
            }
        }

        void SkipMembers(bool methods)
        {
            int n = U2();
            for (int i = 0; i < n; i++)
            {
                p += 6;
                int attrs = U2();
                for (int a = 0; a < attrs; a++)
                {
                    string name = Utf(U2());
                    int len = U4();
                    int end = p + len;
                    if (methods && (name == "RuntimeInvisibleAnnotations" || name == "RuntimeVisibleAnnotations"))
                        ReadAnnotations(false);
                    p = end;
                }
            }
        }

        void ReadAnnotations(bool onClass)
        {
            int n = U2();
            for (int i = 0; i < n; i++)
                ReadAnnotation(onClass, 0);
        }

        void ReadAnnotation(bool onClass, int depth)
        {
            string type = Utf(U2()) ?? "";
            int pairs = U2();
            bool mixin = onClass && depth == 0 && type == "Lorg/spongepowered/asm/mixin/Mixin;";
            bool hook = !onClass && depth == 0 && (type.StartsWith("Lorg/spongepowered/asm/mixin/injection/") || type.StartsWith("Lcom/llamalad7/mixinextras/injector/"));
            if (mixin) IsMixin = true;

            for (int i = 0; i < pairs; i++)
            {
                string key = Utf(U2());
                var values = new List<string>();
                ReadElement(values, depth);
                if (mixin && (key == "value" || key == "targets"))
                {
                    foreach (var v in values) MixinTargets.Add(ShortName(v));
                }
                else if (hook && key == "method")
                {
                    foreach (var v in values)
                    {
                        string m = v;
                        int cut = m.IndexOf('(');
                        if (cut > 0) m = m.Substring(0, cut);
                        int owner = m.LastIndexOf(';');
                        if (owner >= 0) m = m.Substring(owner + 1);
                        if (m.Length > 0) HookedMethods.Add(m);
                    }
                }
            }
        }

        void ReadElement(List<string> sink, int depth)
        {
            char tag = (char)b[p++];
            switch (tag)
            {
                case 's':
                    sink.Add(Utf(U2()));
                    break;
                case 'c':
                    sink.Add(Utf(U2()));
                    break;
                case 'e':
                    p += 4;
                    break;
                case '@':
                    ReadAnnotation(false, depth + 1);
                    break;
                case '[':
                    int n = U2();
                    for (int i = 0; i < n; i++) ReadElement(sink, depth);
                    break;
                default:
                    p += 2;
                    break;
            }
        }

        public static string ShortName(string v)
        {
            if (string.IsNullOrEmpty(v)) return "?";
            string s = v;
            if (s.StartsWith("L") && s.EndsWith(";")) s = s.Substring(1, s.Length - 2);
            s = s.Replace('.', '/');
            int slash = s.LastIndexOf('/');
            return slash >= 0 ? s.Substring(slash + 1) : s;
        }

        public IEnumerable<string> Footprint()
        {
            foreach (var t in MixinTargets)
            {
                if (HookedMethods.Count == 0) yield return t;
                foreach (var m in HookedMethods) yield return t + "." + m;
            }
        }

        string Utf(int index)
        {
            return index > 0 && index < utf8.Length ? utf8[index] : null;
        }

        int U2()
        {
            int v = (b[p] << 8) | b[p + 1];
            p += 2;
            return v;
        }

        int U4()
        {
            int v = (b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3];
            p += 4;
            return v;
        }

        static string DecodeModifiedUtf8(byte[] data, int start, int len)
        {
            var sb = new StringBuilder(len);
            int i = start, end = start + len;
            while (i < end)
            {
                int c = data[i];
                if (c < 0x80) { sb.Append((char)c); i++; }
                else if ((c & 0xE0) == 0xC0 && i + 1 < end)
                {
                    sb.Append((char)(((c & 0x1F) << 6) | (data[i + 1] & 0x3F)));
                    i += 2;
                }
                else if ((c & 0xF0) == 0xE0 && i + 2 < end)
                {
                    sb.Append((char)(((c & 0x0F) << 12) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F)));
                    i += 3;
                }
                else { sb.Append('?'); i++; }
            }
            return sb.ToString();
        }
    }
}
