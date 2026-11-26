using System;
using System.IO;

namespace OrchardObliterator
{
    static class Quarantine
    {
        public static string Folder
        {
            get
            {
                string root = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string dir = Path.Combine(root, "OrchardObliterator", "quarantine");
                try
                {
                    Directory.CreateDirectory(dir);
                    return dir;
                }
                catch
                {
                    dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OrchardObliterator", "quarantine");
                    Directory.CreateDirectory(dir);
                    return dir;
                }
            }
        }

        public static bool Lock(string path)
        {
            if (!File.Exists(path))
            {
                Report.Warn("cannot quarantine " + path + " (not a plain file)");
                return false;
            }

            string dir = Folder;
            string sha = "";
            try { sha = JarScanner.Sha256(JarScanner.ReadShared(path)); } catch { }
            string target = Path.Combine(dir, string.Format("{0:yyyyMMdd_HHmmss}_{1}.quarantined", DateTime.Now, Path.GetFileName(path)));

            for (int attempt = 0; attempt < 10; attempt++)
            {
                try
                {
                    File.Move(path, target);
                    File.SetAttributes(target, FileAttributes.ReadOnly);
                    File.AppendAllText(Path.Combine(dir, "manifest.txt"),
                        string.Format("{0:yyyy-MM-dd HH:mm:ss}\t{1}\t{2}\t{3}{4}", DateTime.Now, sha, path, target, Environment.NewLine));
                    Report.Bad("quarantined " + path);
                    Report.Dim("moved to " + target);
                    return true;
                }
                catch (IOException)
                {
                    System.Threading.Thread.Sleep(300);
                }
                catch (UnauthorizedAccessException)
                {
                    break;
                }
            }
            Report.Warn("could not move " + path + " (still locked or no permission)");
            return false;
        }
    }
}
