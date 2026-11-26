using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace OrchardObliterator
{
    static class JarScanner
    {
        const int MaxDepth = 4;
        const int MaxClasses = 12000;

        static readonly Regex RandomSegment = new Regex(@"^(q?[0-9a-f]{16,}[ab]*|[Il1]{6,}|[ab]{7,}|[O0]{6,}|[Ѐ-ӿ一-鿿]{3,})$", RegexOptions.Compiled);
        static readonly Regex HexToken = new Regex(@"q[0-9a-f]{12,}", RegexOptions.Compiled);
        static readonly Regex Comments = new Regex(@"//[^\n]*|/\*.*?\*/", RegexOptions.Compiled | RegexOptions.Singleline);
        static readonly Regex Spaces = new Regex(@"\s+", RegexOptions.Compiled);

        public static Evidence InspectFile(string path)
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            string dirKey = null;
            try
            {
                Zip directory;
                long shift;
                dirKey = DirectoryKey(path, ext, out directory, out shift);
                Evidence seenBefore;
                if (dirKey != null && byDirectory.TryGetValue(dirKey, out seenBefore))
                    return CopyOf(seenBefore, path);
                if (directory != null && !NeedsFullRead(path, directory, ext, shift))
                {
                    var skim = new Evidence(path);
                    byDirectory[dirKey] = skim;
                    return skim;
                }
            }
            catch
            {
                dirKey = null;
            }

            var full = InspectWhole(path);
            if (dirKey != null) byDirectory[dirKey] = full;
            return full;
        }

        static readonly ConcurrentDictionary<string, Evidence> byDirectory = new ConcurrentDictionary<string, Evidence>();

        static Evidence CopyOf(Evidence known, string path)
        {
            var copy = new Evidence(path);
            copy.Notes.AddRange(known.Notes.Where(n => !n.StartsWith("same file as")));
            if (known.Hits.Count > 0) copy.Notes.Add("same file as " + known.Source);
            copy.Absorb(known, "");
            return copy;
        }

        static string DirectoryKey(string path, string ext, out Zip directory, out long shift)
        {
            directory = null;
            shift = 0;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                long len = fs.Length;
                int tailLen = (int)Math.Min(len, 22 + 65535 + 64);
                var tail = ReadAt(fs, len - tailLen, tailLen);
                int eocd = -1;
                for (int i = tail.Length - 22; i >= 0; i--)
                    if (tail[i] == 'P' && tail[i + 1] == 'K' && tail[i + 2] == 5 && tail[i + 3] == 6) { eocd = i; break; }
                if (eocd < 0) return null;

                long dirSize = BitConverter.ToUInt32(tail, eocd + 12);
                long dirOffset = BitConverter.ToUInt32(tail, eocd + 16);
                if (dirSize == 0xFFFFFFFF || dirOffset == 0xFFFFFFFF || dirSize > 64L * 1024 * 1024) return null;

                long eocdAt = len - tailLen + eocd;
                long dirAt = eocdAt - dirSize;
                if (dirAt < 0) return null;
                var block = ReadAt(fs, dirAt, (int)(len - dirAt));
                directory = Zip.Open(block);
                shift = dirAt - dirOffset;
                string shiftNote = dirAt != dirOffset ? "|shift" + (dirAt - dirOffset) : "";
                return Sha256(block) + "|" + len + "|" + ext + shiftNote;
            }
        }

        static bool NeedsFullRead(string path, Zip directory, string ext, long shift)
        {
            if (ext != ".jar" && ext != ".zip" && ext != ".disabled") return true;
            int classes = 0, random = 0;
            foreach (var item in directory.Items)
            {
                string n = item.Name;
                if (n == "fabric.mod.json" || n == "quilt.mod.json" || n == "META-INF/mods.toml" || n == "META-INF/neoforge.mods.toml" || n == "mcmod.info")
                    return true;
                if (n.EndsWith(".mixins.json") || n.EndsWith(".accesswidener")) return true;
                if (n.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) || n.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) return true;
                if (Fingerprints.NameTokens.Any(t => n.IndexOf(t, StringComparison.Ordinal) >= 0)) return true;
                if (n.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    classes++;
                    if (IsRandomPath(n)) random++;
                }
                if (n == "META-INF/MANIFEST.MF" && IsAgentManifest(path, item, shift)) return true;
            }
            return classes >= 30 && random * 10 >= classes * 6;
        }

        static bool IsAgentManifest(string path, ZipItem item, long shift)
        {
            if (item.Packed > 1024 * 1024 || shift != 0) return true;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var head = ReadAt(fs, item.Offset, 30);
                if (BitConverter.ToUInt32(head, 0) != 0x04034b50) return true;
                long start = item.Offset + 30 + BitConverter.ToUInt16(head, 26) + BitConverter.ToUInt16(head, 28);
                var packed = ReadAt(fs, start, (int)item.Packed);
                string text;
                if (item.Method == 0) text = Encoding.UTF8.GetString(packed);
                else
                {
                    using (var inflate = new System.IO.Compression.DeflateStream(new MemoryStream(packed), System.IO.Compression.CompressionMode.Decompress))
                    using (var r = new StreamReader(inflate, Encoding.UTF8))
                        text = r.ReadToEnd();
                }
                return text.Contains("Premain-Class") || text.Contains("Agent-Class");
            }
        }

        static byte[] ReadAt(FileStream fs, long offset, int count)
        {
            var buf = new byte[count];
            fs.Seek(offset, SeekOrigin.Begin);
            int off = 0;
            while (off < count)
            {
                int got = fs.Read(buf, off, count - off);
                if (got <= 0) break;
                off += got;
            }
            return buf;
        }

        static Evidence InspectWhole(string path)
        {
            byte[] data;
            try { data = ReadShared(path); }
            catch (Exception e)
            {
                var ev = new Evidence(path);
                ev.Notes.Add("unreadable: " + e.Message);
                return ev;
            }
            string key = Sha256(data) + "|" + Path.GetExtension(path).ToLowerInvariant();
            Evidence known;
            if (bySha.TryGetValue(key, out known))
            {
                var copy = new Evidence(path);
                copy.Notes.AddRange(known.Notes);
                copy.Notes.Add("same file as " + known.Source);
                copy.Absorb(known, "");
                return copy;
            }
            var fresh = Inspect(data, path, Path.GetExtension(path), 0);
            bySha[key] = fresh;
            return fresh;
        }

        static readonly ConcurrentDictionary<string, Evidence> bySha = new ConcurrentDictionary<string, Evidence>();

        public static byte[] ReadShared(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var buf = new byte[fs.Length];
                int off = 0;
                while (off < buf.Length)
                {
                    int got = fs.Read(buf, off, buf.Length - off);
                    if (got <= 0) break;
                    off += got;
                }
                return buf;
            }
        }

        public static Evidence Inspect(byte[] data, string source, string extension, int depth)
        {
            var ev = new Evidence(source);
            string sha = Sha256(data);
            if (Fingerprints.KnownFiles.ContainsKey(sha))
                ev.Add("hash", 100, "known build " + Fingerprints.KnownFiles[sha]);

            var zip = Zip.Open(data);
            if (zip == null)
            {
                RawTokenSweep(data, ev);
                return ev;
            }

            Disguise(ev, zip, extension, depth);
            Names(ev, zip);

            var classes = zip.Items.Where(i => !i.IsDirectory && i.Name.EndsWith(".class", StringComparison.OrdinalIgnoreCase)).ToList();
            int randomNames = classes.Count(c => IsRandomPath(c.Name));
            bool hashedTree = classes.Count >= 30 && randomNames * 10 >= classes.Count * 6;

            if (!LooksLikeMod(zip, ev, hashedTree))
            {
                NestedOnly(ev, zip, source, depth);
                return ev;
            }
            Metadata(ev, zip);

            var footprint = new HashSet<string>();
            int mixins = 0;
            var declared = MixinClasses(zip);
            IEnumerable<ZipItem> mixinItems = declared.Count > 0
                ? declared.Select(n => zip.Find(n)).Where(i => i != null)
                : (hashedTree ? classes.Take(MaxClasses) : Enumerable.Empty<ZipItem>());
            foreach (var item in mixinItems)
            {
                var cf = ClassFile.Parse(zip.Read(item));
                if (cf == null || !cf.IsMixin) continue;
                mixins++;
                foreach (var f in cf.Footprint()) footprint.Add(f);
            }
            Footprint(ev, footprint, mixins);

            foreach (var item in zip.Items)
            {
                if (item.IsDirectory || item.Size < 64 || item.Size > 64L * 1024 * 1024) continue;
                if (item.Name.EndsWith(".class", StringComparison.OrdinalIgnoreCase)) continue;
                var head = zip.Peek(item, 4);
                if (head == null || head.Length < 4 || head[0] != 'P' || head[1] != 'K' || head[2] != 3 || head[3] != 4) continue;
                if (depth >= MaxDepth) continue;
                var bytes = zip.Read(item);
                if (bytes == null) continue;
                var child = Inspect(bytes, source + "!/" + item.Name, Path.GetExtension(item.Name), depth + 1);
                if (child.Hits.Count == 0) continue;
                if (!item.Name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) && !item.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                    ev.Add("hiding", 15, "jar stored under a fake name: " + item.Name);
                ev.Absorb(child, "inside " + item.Name + ": ");
            }

            if (hashedTree || ev.Hits.Any(h => Evidence.IsOrchardOnly(h.Kind)))
                Corroborate(ev, zip, classes, randomNames, hashedTree);
            return ev;
        }

        static List<string> MixinClasses(Zip zip)
        {
            var found = new List<string>();
            int configs = 0;
            foreach (var item in zip.Items)
            {
                if (!item.Name.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || item.Size > 256 * 1024) continue;
                if (item.Name.StartsWith("assets/") || item.Name.StartsWith("data/")) continue;
                if (++configs > 64) break;
                var text = zip.ReadText(item);
                if (text == null) continue;
                var pkg = Regex.Match(text, "\"package\"\\s*:\\s*\"([^\"]+)\"");
                if (!pkg.Success) continue;
                string prefix = pkg.Groups[1].Value.Replace('.', '/') + "/";
                foreach (Match arr in Regex.Matches(text, "\"(?:mixins|client|server)\"\\s*:\\s*\\[([^\\]]*)\\]"))
                    foreach (Match name in Regex.Matches(arr.Groups[1].Value, "\"([^\"]+)\""))
                        found.Add(prefix + name.Groups[1].Value.Replace('.', '/') + ".class");
            }
            return found;
        }

        static void Corroborate(Evidence ev, Zip zip, List<ZipItem> classes, int randomNames, bool hashedTree)
        {
            int encrypted = 0;
            var watermarks = new HashSet<string>();
            var fakeSmap = new HashSet<string>();
            var loaderApis = new HashSet<string>();

            foreach (var item in classes.Take(MaxClasses))
            {
                var cf = ClassFile.Parse(zip.Read(item));
                if (cf == null) continue;

                if (cf.DebugExtension != null && !cf.DebugExtension.StartsWith("SMAP"))
                {
                    string tag = cf.DebugExtension.Trim();
                    if (tag.Length > 40) tag = tag.Substring(0, 40);
                    if (Fingerprints.Watermarks.Contains(tag)) watermarks.Add(tag);
                    else fakeSmap.Add(tag);
                }

                bool st = false, cn = false, iso = false;
                foreach (var s in cf.Strings)
                {
                    if (s == "getStackTrace") st = true;
                    else if (s == "getClassName") cn = true;
                    else if (s == "ISO-8859-1") iso = true;
                    else if (Fingerprints.LoaderApis.Contains(s)) loaderApis.Add(s);
                }
                if (st && cn && iso) encrypted++;
            }

            if (hashedTree)
                ev.Add("packer", 30, string.Format("hash-renamed class tree ({0} of {1} classes)", randomNames, classes.Count));
            foreach (var w in watermarks)
                ev.Add("packer", 25, "obfuscator watermark \"" + w + "\"");
            if (fakeSmap.Count > 0)
                ev.Add("packer", 15, "junk SourceDebugExtension in place of SMAP (" + string.Join(", ", fakeSmap.Take(3)) + ")");
            if (encrypted >= 10 && encrypted * 5 >= classes.Count)
                ev.Add("packer", 20, string.Format("stack-trace keyed string encryption in {0} classes", encrypted));
            if (loaderApis.Count > 0 && HasModMeta(zip))
                ev.Add("hiding", 10, "runtime class loading APIs: " + string.Join(", ", loaderApis));

            bool corroborated = ev.Hits.Any(h => Evidence.IsOrchardOnly(h.Kind));
            Dictionary<string, bool> classHashes = null;
            var fileLevel = new Dictionary<string, string>();
            int assetHits = 0, blobs = 0, biggestSize = 0;
            string biggest = null;
            foreach (var item in zip.Items)
            {
                if (item.IsDirectory || item.Name.EndsWith(".class", StringComparison.OrdinalIgnoreCase)) continue;
                if (item.Size > 4L * 1024 * 1024) continue;
                var bytes = zip.Read(item);
                if (bytes == null) continue;

                if (bytes.Length >= 680 && bytes.Length % 68 == 0 && IsHex(bytes, 0, 64))
                {
                    if (classHashes == null) classHashes = HashClasses(zip, classes);
                    IntegrityTable(ev, item.Name, bytes, classHashes, classes.Count);
                }

                foreach (var key in AssetKeys(item.Name, bytes, corroborated))
                {
                    string label;
                    if (Fingerprints.Assets.TryGetValue(key, out label) && !fileLevel.ContainsKey(label))
                    {
                        fileLevel[label] = item.Name;
                        assetHits++;
                    }
                }

                if (bytes.Length >= 32 * 1024 && IsOpaque(item.Name) && Entropy(bytes) > 7.95)
                {
                    blobs++;
                    if (biggest == null || bytes.Length > biggestSize) { biggest = item.Name; biggestSize = bytes.Length; }
                }
            }

            if (assetHits > 0)
            {
                var sample = fileLevel.First();
                ev.Add("asset", Math.Min(corroborated ? 80 : 30, assetHits * 20), string.Format("{0} Orchard assets matched by content (e.g. {1} stored as {2})", assetHits, sample.Key, sample.Value));
            }
            if (blobs > 0)
                ev.Add("hiding", blobs >= 5 ? 20 : 10, string.Format("{0} encrypted-looking blob(s), largest {1} ({2:N0} bytes)", blobs, biggest, biggestSize));
        }

        static bool HasModMeta(Zip zip)
        {
            return zip.Find("fabric.mod.json") != null || zip.Find("quilt.mod.json") != null
                   || zip.Find("META-INF/mods.toml") != null || zip.Find("META-INF/neoforge.mods.toml") != null;
        }

        static bool LooksLikeMod(Zip zip, Evidence ev, bool hashedTree)
        {
            if (hashedTree || zip.Shift > 0 || ev.Hits.Any(h => h.Kind != "hiding")) return true;
            foreach (var item in zip.Items)
            {
                string n = item.Name;
                if (n == "fabric.mod.json" || n == "quilt.mod.json" || n == "META-INF/mods.toml" || n == "META-INF/neoforge.mods.toml" || n == "mcmod.info")
                    return true;
                if (n.EndsWith(".mixins.json") || n.EndsWith(".accesswidener")) return true;
            }
            var manifest = zip.ReadText(zip.Find("META-INF/MANIFEST.MF"));
            if (manifest != null && (manifest.Contains("Premain-Class") || manifest.Contains("Agent-Class") || manifest.Contains("Launcher-Agent-Class")))
            {
                ev.Notes.Add("java agent jar (" + Regex.Match(manifest, @"(Premain|Agent|Launcher-Agent)-Class:\s*(\S+)").Value + ")");
                return true;
            }
            return false;
        }

        static void NestedOnly(Evidence ev, Zip zip, string source, int depth)
        {
            if (depth >= MaxDepth) return;
            foreach (var item in zip.Items)
            {
                if (!item.Name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) || item.Size > 64L * 1024 * 1024) continue;
                var bytes = zip.Read(item);
                if (bytes == null) continue;
                var child = Inspect(bytes, source + "!/" + item.Name, ".jar", depth + 1);
                if (child.Hits.Count > 0) ev.Absorb(child, "inside " + item.Name + ": ");
            }
        }

        static void Disguise(Evidence ev, Zip zip, string extension, int depth)
        {
            var ex = (extension ?? "").ToLowerInvariant();
            if (depth == 0 && ex != ".jar" && ex != ".zip")
                ev.Add("hiding", 10, "archive wearing a " + (ex.Length == 0 ? "blank" : ex) + " extension");
            if (zip.Shift > 0)
                ev.Add("hiding", 15, string.Format("archive starts {0:N0} bytes into the file (polyglot)", zip.Shift));
            int dupes = zip.Items.Count - zip.Items.Select(i => i.Name).Distinct().Count();
            if (dupes > 0)
                ev.Add("hiding", 10, dupes + " duplicate entry names (anti-unzip trick)");
        }

        static void Names(Evidence ev, Zip zip)
        {
            foreach (var token in Fingerprints.NameTokens)
            {
                int n = zip.Items.Count(i => i.Name.IndexOf(token, StringComparison.Ordinal) >= 0);
                if (n > 0) ev.Add("namespace", 35, string.Format("Orchard namespace {0}… ({1} entries)", token.Substring(0, 12), n));
            }
        }

        static void Metadata(Evidence ev, Zip zip)
        {
            foreach (var metaName in new[] { "fabric.mod.json", "quilt.mod.json" })
            {
                var text = zip.ReadText(zip.Find(metaName));
                if (text == null) continue;

                var id = Regex.Match(text, "\"id\"\\s*:\\s*\"([^\"]*)\"");
                var ver = Regex.Match(text, "\"version\"\\s*:\\s*\"([^\"]*)\"");
                var name = Regex.Match(text, "\"name\"\\s*:\\s*\"([^\"]*)\"");
                ev.Notes.Add(string.Format("{0}: id={1} name={2} version={3}", metaName,
                    id.Success ? id.Groups[1].Value : "?", name.Success ? name.Groups[1].Value : "?", ver.Success ? ver.Groups[1].Value : "?"));

                if (id.Success && id.Groups[1].Value.ToLowerInvariant().Contains("orchard"))
                    ev.Add("meta", 40, "mod id \"" + id.Groups[1].Value + "\"");
                if (name.Success && name.Groups[1].Value.ToLowerInvariant().Contains("orchard"))
                    ev.Add("meta", 20, "mod name \"" + name.Groups[1].Value + "\"");
                if (text.Contains("orchard_build") || text.Contains("orchard_subversion"))
                    ev.Add("meta", 50, "orchard_build custom field");
                if (text.IndexOf("LicenseRef-Orchard", StringComparison.OrdinalIgnoreCase) >= 0)
                    ev.Add("meta", 50, "LicenseRef-Orchard license tag");

                var entry = Regex.Match(text, "\"(?:client|main)\"\\s*:\\s*\\[\\s*\"([^\"]+)\"");
                if (entry.Success && entry.Groups[1].Value.Split('.').Count(s => RandomSegment.IsMatch(s)) >= 2)
                    ev.Add("packer", 10, "entrypoint is a hashed name");
            }

            foreach (var item in zip.Items)
            {
                if (!Regex.IsMatch(item.Name, @"^assets/[^/]+/lang/[^/]+\.json$")) continue;
                var text = zip.ReadText(item);
                if (text == null) continue;
                if (text.Contains("key.nsc.profile_") || text.Contains("\"key.nsc.panel\""))
                    ev.Add("lang", 40, "Orchard keybind table (key.nsc.*) in " + item.Name);
            }
        }

        internal static void Footprint(Evidence ev, HashSet<string> footprint, int mixins)
        {
            if (footprint.Count == 0) return;
            var reference = Fingerprints.Footprint;
            int shared = footprint.Count(f => reference.Contains(f));
            double ratio = reference.Count == 0 ? 0 : (double)shared / reference.Count;

            int weight = ratio >= 0.70 ? 100 : ratio >= 0.50 ? 60 : 0;
            if (weight > 0)
                ev.Add("footprint", weight, string.Format("mixin footprint matches Orchard {0:P0} ({1}/{2} hooks, {3} mixins)", ratio, shared, reference.Count, mixins));

            foreach (var kv in Fingerprints.StealthHooks)
                if (footprint.Contains(kv.Key)) ev.Add("stealth", 15, kv.Value);
            foreach (var kv in Fingerprints.CombatHooks)
                if (footprint.Contains(kv.Key)) ev.Add("combat", 8, kv.Value);
        }

        static void IntegrityTable(Evidence ev, string name, byte[] table, Dictionary<string, bool> classHashes, int classCount)
        {
            int records = table.Length / 68, matched = 0;
            for (int i = 0; i < records; i++)
            {
                if (!IsHex(table, i * 68, 64)) return;
                if (classHashes.ContainsKey(Encoding.ASCII.GetString(table, i * 68, 64))) matched++;
            }
            if (matched >= 10)
                ev.Add("integrity", 70, string.Format("self-integrity table {0}: {1} of {2} classes pinned by SHA-256", name, matched, classCount));
            else
                ev.Add("integrity", 35, string.Format("integrity table layout in {0} ({1} records)", name, records));
        }

        static Dictionary<string, bool> HashClasses(Zip zip, List<ZipItem> classes)
        {
            var map = new Dictionary<string, bool>();
            foreach (var c in classes)
            {
                var b = zip.Read(c);
                if (b != null) map[Sha256(b)] = true;
            }
            return map;
        }

        static void RawTokenSweep(byte[] data, Evidence ev)
        {
            foreach (var token in Fingerprints.NameTokens)
                if (IndexOf(data, Encoding.ASCII.GetBytes(token), 0) >= 0)
                    ev.Add("namespace", 35, "Orchard namespace " + token.Substring(0, 12) + "… in unparseable archive");
        }

        public static IEnumerable<string> AssetKeys(string name, byte[] bytes, bool decode)
        {
            yield return "sha:" + Sha256(bytes);
            if (!decode) yield break;
            string lower = name.ToLowerInvariant();
            if (lower.EndsWith(".png"))
            {
                var px = PixelHash(bytes);
                if (px != null) yield return "px:" + px;
            }
            else if (lower.EndsWith(".fsh") || lower.EndsWith(".vsh") || lower.EndsWith(".glsl") || lower.EndsWith(".json"))
            {
                yield return "txt:" + NormalizedHash(bytes);
            }
        }

        static string NormalizedHash(byte[] bytes)
        {
            string text = Encoding.UTF8.GetString(bytes);
            text = Comments.Replace(text, "");
            text = HexToken.Replace(text, "#");
            text = Spaces.Replace(text, "");
            return Sha256(Encoding.UTF8.GetBytes(text));
        }

        static string PixelHash(byte[] png)
        {
            try
            {
                using (var ms = new MemoryStream(png))
                using (var src = new Bitmap(ms))
                using (var bmp = new Bitmap(src.Width, src.Height, PixelFormat.Format32bppArgb))
                {
                    using (var g = Graphics.FromImage(bmp))
                    {
                        g.CompositingMode = System.Drawing.Drawing2D.CompositingMode.SourceCopy;
                        g.DrawImage(src, 0, 0, src.Width, src.Height);
                    }
                    var rect = new Rectangle(0, 0, bmp.Width, bmp.Height);
                    var lk = bmp.LockBits(rect, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
                    try
                    {
                        int row = bmp.Width * 4;
                        var pixels = new byte[row * bmp.Height + 8];
                        BitConverter.GetBytes(bmp.Width).CopyTo(pixels, 0);
                        BitConverter.GetBytes(bmp.Height).CopyTo(pixels, 4);
                        for (int y = 0; y < bmp.Height; y++)
                            Marshal.Copy(lk.Scan0 + y * lk.Stride, pixels, 8 + y * row, row);
                        return Sha256(pixels);
                    }
                    finally
                    {
                        bmp.UnlockBits(lk);
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        static bool IsRandomPath(string name)
        {
            var parts = name.Substring(0, name.Length - 6).Split('/');
            return parts.Length > 0 && parts.All(s => RandomSegment.IsMatch(s));
        }

        static bool IsOpaque(string name)
        {
            string e = Path.GetExtension(name).ToLowerInvariant();
            return e != ".png" && e != ".ogg" && e != ".jpg" && e != ".gz" && e != ".zip" && e != ".jar" && e != ".ttf" && e != ".otf" && e != ".nbt" && e != ".so" && e != ".dll" && e != ".dylib";
        }

        static bool IsHex(byte[] b, int start, int len)
        {
            if (start + len > b.Length) return false;
            for (int i = start; i < start + len; i++)
            {
                byte c = b[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            }
            return true;
        }

        static double Entropy(byte[] b)
        {
            var counts = new int[256];
            foreach (var x in b) counts[x]++;
            double e = 0;
            foreach (var c in counts)
            {
                if (c == 0) continue;
                double p = (double)c / b.Length;
                e -= p * Math.Log(p, 2);
            }
            return e;
        }

        public static int IndexOf(byte[] hay, byte[] needle, int start)
        {
            int last = hay.Length - needle.Length;
            byte first = needle[0];
            for (int i = start; i <= last; i++)
            {
                i = Array.IndexOf(hay, first, i, last - i + 1);
                if (i < 0) return -1;
                int k = 1;
                while (k < needle.Length && hay[i + k] == needle[k]) k++;
                if (k == needle.Length) return i;
            }
            return -1;
        }

        public static string Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                var h = sha.ComputeHash(data);
                var sb = new StringBuilder(64);
                foreach (var x in h) sb.Append(x.ToString("x2"));
                return sb.ToString();
            }
        }

        public static void DumpFingerprint(string path, TextWriter w)
        {
            var data = ReadShared(path);
            var zip = Zip.Open(data);
            if (zip == null)
            {
                w.WriteLine("not an archive");
                return;
            }
            w.WriteLine("file " + Sha256(data));
            var footprint = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var item in zip.Items)
            {
                if (item.IsDirectory) continue;
                var bytes = zip.Read(item);
                if (bytes == null) continue;
                if (item.Name.EndsWith(".class"))
                {
                    var cf = ClassFile.Parse(bytes);
                    if (cf != null && cf.IsMixin) foreach (var f in cf.Footprint()) footprint.Add(f);
                    continue;
                }
                if (item.Name.StartsWith("META-INF/") || item.Name.EndsWith(".mod.json") || item.Name.EndsWith(".mixins.json")) continue;
                if (item.Name.EndsWith("ofl.txt") || item.Name.EndsWith("/lang/en_us.json") || item.Name.EndsWith("sounds.json")) continue;
                if (bytes.Length < 512) continue;
                string tail = item.Name.Substring(item.Name.LastIndexOf('/') + 1);
                foreach (var key in AssetKeys(item.Name, bytes, true))
                    w.WriteLine("asset " + key + " " + Path.GetExtension(tail).TrimStart('.') + ":" + tail.Substring(0, Math.Min(9, tail.Length)));
            }
            foreach (var f in footprint) w.WriteLine("hook " + f);
        }
    }
}
