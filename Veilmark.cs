using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

[assembly: AssemblyTitle("Veilmark — Local Text Redaction")]
[assembly: AssemblyProduct("Veilmark")]
[assembly: AssemblyDescription("Local text redaction and configurable pseudonymisation.")]
[assembly: AssemblyVersion("1.3.0.0")]
[assembly: AssemblyFileVersion("1.3.0.0")]

namespace VeilmarkApp
{
    internal sealed class Rule
    {
        public string Id, Name, Replacement, RandomTemplate, Exact;
        public bool Enabled = true, Randomise;
        public Rule Copy() { return (Rule)MemberwiseClone(); }
        public static List<Rule> Defaults()
        {
            string[] ids = { "password", "encryption-key", "api-key", "bearer-token", "credential", "name", "address", "email" };
            string[] names = { "Passwords", "Encryption / private keys", "API keys", "Bearer tokens", "Other credentials", "Names", "Addresses", "Email addresses" };
            return ids.Select((id, i) => new Rule { Id = id, Name = names[i], Replacement = "[REDACTED_" + id.Replace('-', '_').ToUpperInvariant() + "]", RandomTemplate = id == "email" ? "person-{random}@example.invalid" : "[{type}-{random}]", Exact = "" }).ToList();
        }
    }
    internal sealed class Preferences
    {
        public List<Rule> Rules = Rule.Defaults();
        public bool Repeats = true;
        public WindowPreferences Windows = new WindowPreferences();
    }
    internal sealed class WindowPreferences
    {
        public Rectangle MainBounds, ExactBounds;
        public bool Maximized;
        public double SplitRatio = 0.5;
        public int ExactCategory, OnWidth = 48, ExactWidth = 55;
        public float[] FillWeights = { 22, 12, 33, 33 };
    }
    internal sealed class SettingsStore
    {
        public static readonly string DefaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Veilmark", "settings.dat");
        private readonly string path;
        public SettingsStore(string path) { this.path = Path.GetFullPath(path); }
        public Preferences Load()
        {
            var preferences = new Preferences();
            if (!File.Exists(path)) return preferences;
            if (new FileInfo(path).Length > 32000000) throw new InvalidDataException();
            byte[] plain = ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser);
            try
            {
                using (var stream = new MemoryStream(plain, false))
                using (var reader = new BinaryReader(stream, Encoding.UTF8))
                {
                    string format = reader.ReadString();
                    if (format != "Veilmark.Settings.1" && format != "Veilmark.Settings.2") throw new InvalidDataException();
                    preferences.Repeats = reader.ReadBoolean();
                    int count = reader.ReadInt32();
                    if (count != preferences.Rules.Count) throw new InvalidDataException();
                    var seen = new HashSet<string>();
                    for (int i = 0; i < count; i++)
                    {
                        string id = reader.ReadString();
                        Rule rule = preferences.Rules.SingleOrDefault(r => r.Id == id);
                        if (rule == null || !seen.Add(id)) throw new InvalidDataException();
                        rule.Enabled = reader.ReadBoolean(); rule.Randomise = reader.ReadBoolean();
                        rule.Replacement = reader.ReadString(); rule.RandomTemplate = reader.ReadString(); rule.Exact = reader.ReadString();
                        Validate(rule);
                    }
                    if (format == "Veilmark.Settings.2")
                    {
                        WindowPreferences windows = preferences.Windows;
                        windows.MainBounds = ReadBounds(reader); windows.Maximized = reader.ReadBoolean();
                        windows.SplitRatio = reader.ReadDouble(); windows.ExactBounds = ReadBounds(reader);
                        windows.ExactCategory = reader.ReadInt32(); windows.OnWidth = reader.ReadInt32(); windows.ExactWidth = reader.ReadInt32();
                        for (int i = 0; i < windows.FillWeights.Length; i++) windows.FillWeights[i] = reader.ReadSingle();
                        ValidateWindows(windows);
                    }
                    if (stream.Position != stream.Length) throw new InvalidDataException();
                }
                return preferences;
            }
            finally { Array.Clear(plain, 0, plain.Length); }
        }
        private static void Validate(Rule rule)
        {
            if (rule.Replacement == null || rule.RandomTemplate == null || rule.Exact == null || rule.Replacement.Length > 100000 || rule.RandomTemplate.Length > 100000 || rule.Exact.Length > 1000000) throw new InvalidDataException();
        }
        private static Rectangle ReadBounds(BinaryReader reader)
        { return new Rectangle(reader.ReadInt32(), reader.ReadInt32(), reader.ReadInt32(), reader.ReadInt32()); }
        private static void WriteBounds(BinaryWriter writer, Rectangle bounds)
        { writer.Write(bounds.X); writer.Write(bounds.Y); writer.Write(bounds.Width); writer.Write(bounds.Height); }
        private static void ValidateWindows(WindowPreferences windows)
        {
            foreach (Rectangle bounds in new[] { windows.MainBounds, windows.ExactBounds })
                if (Math.Abs((long)bounds.X) > 100000 || Math.Abs((long)bounds.Y) > 100000 || bounds.Width < 0 || bounds.Width > 20000 || bounds.Height < 0 || bounds.Height > 20000) throw new InvalidDataException();
            if (Double.IsNaN(windows.SplitRatio) || windows.SplitRatio < 0 || windows.SplitRatio > 1 || windows.ExactCategory < 0 || windows.ExactCategory > 7 || windows.OnWidth < 40 || windows.OnWidth > 20000 || windows.ExactWidth < 55 || windows.ExactWidth > 20000) throw new InvalidDataException();
            if (windows.FillWeights.Length != 4 || windows.FillWeights.Any(w => Single.IsNaN(w) || w <= 0 || w > 65535)) throw new InvalidDataException();
        }
        public void Save(List<Rule> rules, bool repeats, WindowPreferences windows = null)
        {
            windows = windows ?? new WindowPreferences(); ValidateWindows(windows);
            byte[] encrypted;
            using (var memory = new MemoryStream())
            {
                try
                {
                    using (var writer = new BinaryWriter(memory, Encoding.UTF8, true))
                    {
                        writer.Write("Veilmark.Settings.2"); writer.Write(repeats); writer.Write(rules.Count);
                        foreach (Rule rule in rules)
                        {
                            Validate(rule);
                            writer.Write(rule.Id); writer.Write(rule.Enabled); writer.Write(rule.Randomise);
                            writer.Write(rule.Replacement); writer.Write(rule.RandomTemplate); writer.Write(rule.Exact);
                        }
                        WriteBounds(writer, windows.MainBounds); writer.Write(windows.Maximized); writer.Write(windows.SplitRatio);
                        WriteBounds(writer, windows.ExactBounds); writer.Write(windows.ExactCategory); writer.Write(windows.OnWidth); writer.Write(windows.ExactWidth);
                        foreach (float weight in windows.FillWeights) writer.Write(weight);
                    }
                    byte[] plain = memory.ToArray();
                    try { encrypted = ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser); }
                    finally { Array.Clear(plain, 0, plain.Length); }
                }
                finally { Array.Clear(memory.GetBuffer(), 0, (int)memory.Length); }
            }
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { file.Write(encrypted, 0, encrypted.Length); file.Flush(true); }
                if (File.Exists(path)) File.Replace(temporary, path, null);
                else File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
    internal sealed class Hit
    {
        public int Start, Length, Priority;
        public Rule Rule;
        public string Value;
    }
    internal sealed class Result
    {
        public string Text;
        public int Count;
        public Dictionary<string, int> Counts = new Dictionary<string, int>();
    }
    internal sealed class Engine
    {
        // Salt stays in memory. HMAC gives stable session aliases without retaining source values in a map.
        private readonly byte[] salt = new byte[32];
        private const int MaxHits = 30000;
        public Engine() { using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(salt); }
        private static Regex Rx(string pattern) { return new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(350)); }
        private static void Scan(List<Hit> hits, string input, Rule rule, string pattern, int priority, CancellationToken cancel)
        {
            foreach (Match m in Rx(pattern).Matches(input))
            {
                cancel.ThrowIfCancellationRequested();
                Group g = m.Groups["value"].Success ? m.Groups["value"] : m.Groups[0];
                if (g.Length == 0) continue;
                hits.Add(new Hit { Start = g.Index, Length = g.Length, Rule = rule, Value = g.Value, Priority = priority });
                if (hits.Count > MaxHits) throw new InvalidOperationException("Too many matches. Process a smaller section of text.");
            }
        }
        private static string Label(string names, bool lineValue)
        {
            string v = lineValue ? "[^\\r\\n,;}#]+" : "[^\\s,;}\\]\\\"'<>]+";
            // A label can be a JSON property, environment variable, CLI option or prose field.
            return "(?im)(?<![\\w])(?:--)?[\\\"']?(?:" + names + ")[\\\"']?[ \\t]*(?:[:=]|[ \\t]+(?=[\\\"']))[ \\t]*(?:\\\"(?<value>(?:\\\\.|[^\\\"\\\\\\r\\n])*)\\\"|'(?<value>(?:\\\\.|[^'\\\\\\r\\n])*)'|(?<value>" + v + "))";
        }
        public Result Process(string input, List<Rule> rules, bool repeats, CancellationToken cancel)
        {
            if (input.Length > 1000000) throw new InvalidOperationException("The limit is 1,000,000 characters. Process a smaller section.");
            var hits = new List<Hit>();
            foreach (Rule r in rules.Where(x => x.Enabled))
            {
                cancel.ThrowIfCancellationRequested();
                string labels = null;
                bool line = false;
                switch (r.Id)
                {
                    case "password":
                        labels = "(?:[a-z0-9]+[_-])*?(?:password|passwd|pwd|passphrase)(?:[_-][a-z0-9]+)*|[a-z0-9]*(?:Password|Passphrase)";
                        Scan(hits, input, r, @"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:(?<value>[^\s/@]+)@", 90, cancel);
                        Scan(hits, input, r, @"(?im)(?<!\w)--(?:password|passwd|pwd|passphrase)[ \t]+(?:""(?<value>[^""\r\n]+)""|'(?<value>[^'\r\n]+)'|(?<value>[^\s]+))", 80, cancel);
                        break;
                    case "encryption-key":
                        labels = "(?:[a-z0-9]+[_-])*(?:encryption[_ -]?key|private[_ -]?key|secret[_ -]?key|aes[_ -]?key|ssh[_ -]?key)(?:[_-][a-z0-9]+)*";
                        Scan(hits, input, r, @"(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\z)", 120, cancel);
                        Scan(hits, input, r, @"(?s)-----BEGIN PGP PRIVATE KEY BLOCK-----.*?(?:-----END PGP PRIVATE KEY BLOCK-----|\z)", 120, cancel);
                        break;
                    case "api-key":
                        labels = "(?:[a-z0-9]+[_-])*(?:api[_ -]?key|apikey|api[_ -]?token|access[_ -]?key(?:[_ -]?id)?|subscription[_ -]?key)(?:[_-][a-z0-9]+)*";
                        Scan(hits, input, r, @"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{12,})\b", 75, cancel);
                        break;
                    case "bearer-token":
                        labels = "(?:[a-z0-9]+[_-])*(?:bearer[_ -]?token|access[_ -]?token|refresh[_ -]?token|id[_ -]?token)(?:[_-][a-z0-9]+)*";
                        Scan(hits, input, r, @"(?i)\bBearer[ \t]+(?<value>[A-Za-z0-9._~+/=-]+)", 100, cancel);
                        Scan(hits, input, r, @"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", 70, cancel);
                        break;
                    case "credential":
                        labels = "(?:[a-z0-9]+[_-])*(?:username|user[_ -]?name|user[_ -]?id|login|uid|client[_ -]?secret|credential|session[_ -]?id|session[_ -]?token|account[_ -]?key|shared[_ -]?access[_ -]?signature|recovery[_ -]?code)(?:[_-][a-z0-9]+)*|(?<![a-z0-9_-])(?:secret|token)(?![a-z0-9_-])";
                        Scan(hits, input, r, @"(?i)\bBasic[ \t]+(?<value>[A-Za-z0-9+/=]+)", 100, cancel);
                        Scan(hits, input, r, @"(?im)^[ \t]*(?:Set-Cookie|Cookie)[ \t]*:[ \t]*(?<value>[^\r\n]+)", 110, cancel);
                        Scan(hits, input, r, @"(?i)\b[a-z][a-z0-9+.-]*://(?<value>[^\s/:@]+)(?=:[^\s/@]+@|@)", 85, cancel);
                        break;
                    case "name":
                        labels = "(?:full[_ -]?name|first[_ -]?name|last[_ -]?name|given[_ -]?name|surname|display[_ -]?name|customer[_ -]?name|contact[_ -]?name|name)";
                        line = true; break;
                    case "address":
                        labels = "(?:home[_ -]?address|postal[_ -]?address|billing[_ -]?address|shipping[_ -]?address|street[_ -]?address|address(?:[_ -]?(?:line)?[12])?|postcode|postal[_ -]?code|zip[_ -]?code)";
                        line = true;
                        Scan(hits, input, r, @"(?i)\b\d{1,5}[A-Z]?[ \t]+(?:[A-Z][A-Z.'-]*[ \t]+){1,5}(?:Street|Road|Avenue|Lane|Drive|Close|Crescent|Boulevard|Way|Court|Terrace|Place|St|Rd|Ave|Ln|Blvd)\b(?:[ \t]+(?:Apt|Flat|Unit)[ \t]*[A-Z0-9-]+)?", 45, cancel);
                        Scan(hits, input, r, @"(?i)\b(?:GIR[ \t]?0AA|[A-Z]{1,2}[0-9][A-Z0-9]?[ \t]?[0-9][A-Z]{2})\b", 30, cancel);
                        break;
                    case "email":
                        Scan(hits, input, r, @"(?i)(?<![\w.!#$%&'*+/=?^`{|}~-])[A-Z0-9.!#$%&'*+/=?^`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+", 65, cancel);
                        break;
                }
                if (labels != null)
                {
                    Scan(hits, input, r, Label(labels, line), 95, cancel);
                    Scan(hits, input, r, "(?im)^(?<indent>[ \\t]*)[\\\"']?(?:" + labels + ")[\\\"']?[ \\t]*:[ \\t]*(?<value>[|>][-+]?[ \\t]*(?:\\r?\\n\\k<indent>[ \\t]+[^\\r\\n]*)+)", 105, cancel);
                    Scan(hits, input, r, "(?is)<(?<tag>" + labels + ")\\b[^>]*>(?<value>.*?)</\\k<tag>[ \\t]*>", 105, cancel);
                }
                foreach (string term in (r.Exact ?? "").Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase))
                    Scan(hits, input, r, "(?i)(?<![\\p{L}\\p{N}_])" + Regex.Escape(term) + "(?![\\p{L}\\p{N}_])", 115, cancel);
            }
            if (repeats)
            {
                var unique = hits.Where(h => h.Length >= 4).GroupBy(h => h.Value).Select(g => g.OrderByDescending(h => h.Priority).First()).ToArray();
                if (unique.Length > 1500) throw new InvalidOperationException("Too many distinct values for repeat matching. Turn off 'Match repeated values' or use a smaller section.");
                foreach (Hit h in unique)
                {
                    cancel.ThrowIfCancellationRequested();
                    // Repeat matching is literal, case-sensitive and bounded by word characters.
                    int at = 0;
                    while ((at = input.IndexOf(h.Value, at, StringComparison.Ordinal)) >= 0)
                    {
                        cancel.ThrowIfCancellationRequested();
                        int end = at + h.Length;
                        if ((at == 0 || !Word(input[at - 1])) && (end == input.Length || !Word(input[end])))
                            hits.Add(new Hit { Start = at, Length = h.Length, Rule = h.Rule, Value = h.Value, Priority = h.Priority - 1 });
                        at = end;
                        if (hits.Count > MaxHits) throw new InvalidOperationException("Too many matches. Process a smaller section.");
                    }
                }
            }
            // Merge overlapping spans, so a short higher-priority match cannot expose the rest of a secret.
            var ordered = hits.OrderBy(h => h.Start).ThenByDescending(h => h.Length).ToList();
            var merged = new List<Hit>();
            foreach (Hit h in ordered)
            {
                cancel.ThrowIfCancellationRequested();
                Hit last = merged.LastOrDefault();
                if (last != null && h.Start < last.Start + last.Length)
                {
                    int end = Math.Max(last.Start + last.Length, h.Start + h.Length);
                    if (h.Priority > last.Priority) { last.Rule = h.Rule; last.Priority = h.Priority; }
                    last.Length = end - last.Start;
                    last.Value = input.Substring(last.Start, last.Length);
                }
                else merged.Add(new Hit { Start = h.Start, Length = h.Length, Value = h.Value, Priority = h.Priority, Rule = h.Rule });
            }
            var result = new Result();
            var b = new StringBuilder();
            var numbering = new Dictionary<string, int>();
            int cursor = 0;
            foreach (Hit h in merged)
            {
                cancel.ThrowIfCancellationRequested();
                b.Append(input, cursor, h.Start - cursor);
                string key = h.Rule.Id + "\0" + h.Value;
                int number;
                if (!numbering.TryGetValue(key, out number)) { number = numbering.Count + 1; numbering.Add(key, number); }
                string template = h.Rule.Randomise ? h.Rule.RandomTemplate : h.Rule.Replacement;
                b.Append(template.Replace("{type}", h.Rule.Id).Replace("{n}", number.ToString()).Replace("{random}", Alias(key)));
                cursor = h.Start + h.Length;
                if (!result.Counts.ContainsKey(h.Rule.Name)) result.Counts[h.Rule.Name] = 0;
                result.Counts[h.Rule.Name]++;
            }
            b.Append(input, cursor, input.Length - cursor);
            result.Text = b.ToString(); result.Count = merged.Count;
            return result;
        }
        private static bool Word(char c) { return Char.IsLetterOrDigit(c) || c == '_'; }
        private string Alias(string value)
        {
            using (var hmac = new HMACSHA256(salt))
                return BitConverter.ToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value)), 0, 8).Replace("-", "").ToLowerInvariant();
        }
    }

    internal sealed class MainForm : Form
    {
        private readonly List<Rule> rules = Rule.Defaults();
        private Engine engine = new Engine();
        internal readonly TextBox Input = Editor(false), Output = Editor(true);
        private readonly DataGridView grid = new DataGridView();
        private readonly ToolStripStatusLabel status = new ToolStripStatusLabel { Name = "ActivityStatus", Spring = true, TextAlign = ContentAlignment.MiddleLeft, AutoToolTip = true };
        private readonly ToolStripStatusLabel counts = new ToolStripStatusLabel { Name = "OutputCounts", BorderSides = ToolStripStatusLabelBorderSides.Left, Padding = new Padding(8, 0, 0, 0) };
        private readonly StatusStrip statusBar = new StatusStrip { SizingGrip = false, Dock = DockStyle.Bottom };
        private readonly NotifyIcon tray = new NotifyIcon { Text = "Veilmark" };
        private readonly ContextMenuStrip trayMenu = new ContextMenuStrip();
        private readonly Action<string> writeClipboard;
        private bool inTray;
        private readonly Button copy = Button("Copy output"), save = Button("Save output…");
        private readonly CheckBox repeat = new CheckBox { Text = "Match repeated values", Checked = true, AutoSize = true, Margin = new Padding(12, 9, 8, 3) };
        private readonly System.Windows.Forms.Timer debounce = new System.Windows.Forms.Timer { Interval = 250 };
        private readonly System.Windows.Forms.Timer settingsTimer = new System.Windows.Forms.Timer { Interval = 600 };
        private readonly SettingsStore settings;
        private bool settingsDirty, settingsWritable = true, settingsErrorShown;
        private WindowPreferences windows = new WindowPreferences();
        private bool windowReady;
        private SplitContainer textSplit;
        private CancellationTokenSource cancellation;
        private int version;
        private bool ready, loading;
        private readonly ToolTip tips = new ToolTip();
        internal const string Sample = "Name: Alex Example\r\nEmail: alex@example.invalid\r\nAddress: 42 Example Road\r\nPostcode: SW1A 1AA\r\n\r\nDB_PASSWORD=Demo-only-Password!42\r\nAPI_KEY=demo_only_api_key_1234567890\r\nEncryptionKey=demo_only_encryption_key_123456\r\nAuthorization: Bearer demo.only.bearer-token\r\nClientSecret=demo_only_client_secret\r\n\r\nA repeated password: Demo-only-Password!42\r\nOrdinary text stays readable.";
        public MainForm(string settingsPath = null, Action<string> clipboardWriter = null)
        {
            writeClipboard = clipboardWriter ?? (text => Clipboard.SetText(text));
            settings = new SettingsStore(settingsPath ?? SettingsStore.DefaultPath);
            try { Preferences saved = settings.Load(); rules = saved.Rules; repeat.Checked = saved.Repeats; windows = saved.Windows; }
            catch
            {
                settingsWritable = false;
                Shown += delegate { MessageBox.Show(this, "Saved settings could not be read. The encrypted file has been left untouched. Defaults are in use and changes will not be saved. See the README recovery instructions.", "Veilmark settings", MessageBoxButtons.OK, MessageBoxIcon.Warning); };
            }
            Text = "Veilmark — local & private";
            using (Stream iconStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Veilmark.ico"))
                Icon = new Icon(iconStream, 32, 32);
            tray.Icon = Icon;
            trayMenu.Items.Add(new ToolStripMenuItem("Open Veilmark", null, delegate { RestoreFromTray(); }) { Name = "Open" });
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add(new ToolStripMenuItem("Quit", null, delegate { Close(); }) { Name = "Quit" });
            tray.ContextMenuStrip = trayMenu;
            tray.DoubleClick += delegate { RestoreFromTray(); };
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Segoe UI", 10);
            BackColor = Color.FromArgb(243, 246, 250);
            ForeColor = Color.FromArgb(28, 42, 60);
            MinimumSize = new Size(1020, 780); Size = new Size(1380, 960);
            StartPosition = FormStartPosition.CenterScreen;
            if (windows.MainBounds.Width > 0) { StartPosition = FormStartPosition.Manual; Bounds = VisibleBounds(windows.MainBounds, MinimumSize); }
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(18, 10, 18, 10) };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 43));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 43));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 267));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 29));
            Controls.Add(layout);
            statusBar.Items.Add(status); statusBar.Items.Add(counts);
            statusBar.BackColor = Color.FromArgb(226, 233, 242); statusBar.Font = Font;
            Controls.Add(statusBar);
            var heading = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 2, RowCount = 2, Padding = new Padding(0, 0, 0, 6) };
            heading.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 60));
            heading.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            heading.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            heading.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            var brandLogo = new PictureBox { SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(50, 50), Anchor = AnchorStyles.Top | AnchorStyles.Left, Margin = new Padding(0, 0, 10, 0) };
            using (Stream logoStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Veilmark.png"))
            using (Image logo = Image.FromStream(logoStream)) brandLogo.Image = new Bitmap(logo);
            heading.Controls.Add(brandLogo, 0, 0); heading.SetRowSpan(brandLogo, 2);
            heading.Controls.Add(new Label { Text = "Veilmark", Font = new Font("Segoe UI", 21, FontStyle.Bold), AutoSize = true, Margin = Padding.Empty }, 1, 0);
            heading.Controls.Add(new Label { Text = "Local text redaction. Source text is never saved; settings are encrypted.", AutoSize = true, ForeColor = Color.FromArgb(82, 99, 116), Margin = Padding.Empty }, 1, 1);
            layout.Controls.Add(heading, 0, 0);
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
            Add(toolbar, "Paste text", delegate { ClipboardAction(delegate { Input.Paste(); }); });
            Add(toolbar, "Open text file…", delegate { OpenFile(null); });
            Add(toolbar, "Load demo", delegate { if (Input.TextLength == 0 || MessageBox.Show(this, "Replace the current input with synthetic demonstration text?", "Load demo", MessageBoxButtons.YesNo) == DialogResult.Yes) Input.Text = Sample; });
            Add(toolbar, "Clear all text", delegate { ClearText(); });
            Add(toolbar, "New random values", delegate { engine = new Engine(); Schedule(); });
            toolbar.Controls.Add(copy); copy.Click += delegate { CopyOutput(); };
            toolbar.Controls.Add(save); save.Click += delegate { SaveOutput(); };
            layout.Controls.Add(toolbar, 0, 1);
            var split = new SplitContainer { Size = new Size(1300, 400), Dock = DockStyle.Fill, Orientation = Orientation.Vertical, SplitterWidth = 12, BackColor = BackColor, Panel1MinSize = 250, Panel2MinSize = 250 };
            split.Size = new Size(1300, 400); split.SplitterDistance = 640;
            textSplit = split;
            Pane(split.Panel1, "SOURCE TEXT", "Paste, type, or drop plain text / a text file here", Input);
            Pane(split.Panel2, "REDACTED OUTPUT", "Click to copy all output • review before sharing", Output);
            Output.MouseClick += delegate(object sender, MouseEventArgs e) { if (e.Button == MouseButtons.Left) CopyOutput(); };
            tips.SetToolTip(Output, "Click to copy the complete output to the clipboard.");
            layout.Controls.Add(split, 0, 2);
            var options = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 3, 0, 0) };
            options.Controls.Add(new Label { Text = "Redaction rules", AutoSize = true, Font = new Font(Font, FontStyle.Bold), Margin = new Padding(0, 7, 18, 0) });
            Add(options, "Redact all", delegate { SetModes(false); });
            Add(options, "Randomise all", delegate { SetModes(true); });
            Add(options, "Exact matches…", delegate { ExactMatches(); });
            options.Controls.Add(repeat); repeat.CheckedChanged += delegate { SettingsChanged(); Schedule(); };
            layout.Controls.Add(options, 0, 3);
            SetupGrid(); layout.Controls.Add(grid, 0, 4);
            // Include row/header heights and outer margins, rather than squeezing the last row.
            layout.Layout += delegate { FitRulesHeight(layout); };
            grid.RowHeightChanged += delegate { FitRulesHeight(layout); };
            grid.ColumnHeadersHeightChanged += delegate { FitRulesHeight(layout); };
            status.Text = "Ready — paste text to begin.";
            var footer = new Label { Dock = DockStyle.Fill, AutoEllipsis = true, ForeColor = Color.FromArgb(95, 103, 119), Margin = new Padding(3, 5, 3, 0), Text = "Review before sharing. For unlabelled names / addresses, use Exact matches. Templates: {type}, {n}, {random}." };
            layout.Controls.Add(footer, 0, 5);
            tips.SetToolTip(repeat, "Also replace literal repetitions of detected values (4+ characters). Repetitions are case-sensitive and word-bounded.");
            Input.TextChanged += delegate { Schedule(); };
            Input.AllowDrop = true;
            Input.DragEnter += delegate(object sender, DragEventArgs e) { if (e.Data.GetDataPresent(DataFormats.UnicodeText) || e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            Input.DragDrop += delegate(object sender, DragEventArgs e)
            {
                if (e.Data.GetDataPresent(DataFormats.FileDrop)) { string[] files = (string[])e.Data.GetData(DataFormats.FileDrop); if (files.Length == 1) OpenFile(files[0]); else MessageBox.Show(this, "Drop one text file at a time."); }
                else Input.SelectedText = (string)e.Data.GetData(DataFormats.UnicodeText);
            };
            debounce.Tick += async delegate { debounce.Stop(); await ProcessNow(); };
            settingsTimer.Tick += delegate { settingsTimer.Stop(); SavePreferences(true); };
            Shown += delegate
            {
                if (windows.Maximized) WindowState = FormWindowState.Maximized;
                int available = split.ClientSize.Width - split.SplitterWidth;
                split.SplitterDistance = Math.Max(split.Panel1MinSize, Math.Min(available - split.Panel2MinSize, (int)Math.Round(available * windows.SplitRatio)));
                windowReady = true;
            };
            ResizeEnd += delegate { if (windowReady) { CaptureWindowPreferences(); SettingsChanged(); } };
            Resize += delegate
            {
                if (!windowReady) return;
                if (WindowState == FormWindowState.Minimized) MinimiseToTray();
                else { CaptureWindowPreferences(); SettingsChanged(); }
            };
            split.SplitterMoved += delegate { if (windowReady) { CaptureWindowPreferences(); SettingsChanged(); } };
            grid.ColumnWidthChanged += delegate { if (windowReady) SettingsChanged(); };
            FormClosing += delegate(object sender, FormClosingEventArgs e)
            {
                grid.EndEdit(); settingsTimer.Stop();
                if (windowReady) { CaptureWindowPreferences(); settingsDirty = true; }
                if (!SavePreferences(false) && MessageBox.Show(this, "Settings could not be saved. Close without saving these changes?", "Veilmark settings", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) { e.Cancel = true; return; }
                version++; debounce.Stop(); if (cancellation != null) cancellation.Cancel();
            };
            Disposed += delegate { tray.Visible = false; tray.Dispose(); trayMenu.Dispose(); debounce.Dispose(); settingsTimer.Dispose(); tips.Dispose(); brandLogo.Image.Dispose(); Icon.Dispose(); };
            copy.Enabled = save.Enabled = false;
        }
        private static TextBox Editor(bool readOnly)
        {
            return new TextBox { Multiline = true, AcceptsReturn = true, AcceptsTab = true, ScrollBars = ScrollBars.Both, WordWrap = false, ReadOnly = readOnly, Dock = DockStyle.Fill, Font = new Font("Consolas", 11), BackColor = readOnly ? Color.FromArgb(246, 251, 250) : Color.White, BorderStyle = BorderStyle.FixedSingle, MaxLength = 1000000 };
        }
        private void MinimiseToTray()
        {
            if (inTray || IsDisposed) return;
            inTray = true;
            grid.EndEdit(); CaptureWindowPreferences(); SettingsChanged(); SavePreferences(true);
            tray.Visible = true; ShowInTaskbar = false; Hide();
            status.Text = "Minimised to tray — double-click the Veilmark icon to restore.";
        }
        private void RestoreFromTray()
        {
            if (IsDisposed) return;
            bool maximized = windows.Maximized;
            inTray = false; ShowInTaskbar = true;
            WindowState = maximized ? FormWindowState.Maximized : FormWindowState.Normal;
            Show(); Activate(); tray.Visible = false;
            status.Text = "Restored from tray.";
        }
        private void CopyOutput()
        {
            if (!ready || Output.TextLength == 0)
            {
                status.Text = Input.TextLength == 0 || ready ? "Nothing to copy — the output is empty." : "Output is not ready — wait for processing to finish successfully.";
                return;
            }
            try
            {
                writeClipboard(Output.Text);
                status.Text = "Copied " + Output.TextLength.ToString("N0") + " characters to the clipboard.";
            }
            catch { status.Text = "Copy failed — the Windows clipboard is unavailable. Click the output to try again."; }
        }
        private static Button Button(string text) { return new Button { Text = text, AutoSize = true, Height = 31, FlatStyle = FlatStyle.Flat, BackColor = Color.White, Margin = new Padding(0, 0, 8, 0), Padding = new Padding(7, 1, 7, 1) }; }
        private static void Add(Control parent, string text, EventHandler handler) { var b = Button(text); b.Click += handler; parent.Controls.Add(b); }
        private void Pane(Control parent, string title, string subtitle, TextBox editor)
        {
            var pane = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Margin = Padding.Empty };
            pane.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pane.RowStyles.Add(new RowStyle(SizeType.Absolute, 24)); pane.RowStyles.Add(new RowStyle(SizeType.Absolute, 25)); pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            pane.Controls.Add(new Label { Text = title, AutoSize = true, Font = new Font(Font, FontStyle.Bold) }, 0, 0);
            pane.Controls.Add(new Label { Text = subtitle, AutoSize = true, ForeColor = Color.FromArgb(90, 105, 120) }, 0, 1);
            pane.Controls.Add(editor, 0, 2); parent.Controls.Add(pane);
        }
        private void SetupGrid()
        {
            grid.Dock = DockStyle.Fill; grid.AllowUserToAddRows = false; grid.AllowUserToDeleteRows = false;
            grid.AllowUserToResizeRows = false; grid.RowHeadersVisible = false; grid.BackgroundColor = Color.White;
            grid.BorderStyle = BorderStyle.None; grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            grid.ScrollBars = ScrollBars.Horizontal;
            grid.SelectionMode = DataGridViewSelectionMode.CellSelect; grid.MultiSelect = false;
            grid.EnableHeadersVisualStyles = false; grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(226, 233, 242);
            grid.ColumnHeadersDefaultCellStyle.Font = new Font(Font, FontStyle.Bold); grid.ColumnHeadersHeight = 30;
            grid.RowTemplate.Height = 29; grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(246, 248, 251);
            grid.Columns.Add(new DataGridViewCheckBoxColumn { Name = "Enabled", HeaderText = "On", FillWeight = 5, MinimumWidth = 40 });
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Category", HeaderText = "Information", ReadOnly = true, FillWeight = 21, MinimumWidth = 170 });
            grid.Columns.Add(new DataGridViewComboBoxColumn { Name = "Mode", HeaderText = "Mode", DataSource = new[] { "Redact", "Randomise" }, FillWeight = 12, MinimumWidth = 100 });
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Replacement", HeaderText = "Replacement text (Redact)", FillWeight = 28, MinimumWidth = 180 });
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "RandomTemplate", HeaderText = "Template (Randomise)", FillWeight = 27, MinimumWidth = 180 });
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Exact", HeaderText = "Exact", ReadOnly = true, FillWeight = 7, MinimumWidth = 55 });
            grid.Columns[0].AutoSizeMode = DataGridViewAutoSizeColumnMode.None; grid.Columns[0].Width = 48;
            grid.Columns[5].AutoSizeMode = DataGridViewAutoSizeColumnMode.None; grid.Columns[5].Width = 55;
            grid.Columns[1].FillWeight = 22; grid.Columns[2].FillWeight = 12; grid.Columns[3].FillWeight = 33; grid.Columns[4].FillWeight = 33;
            grid.Columns[0].Width = windows.OnWidth; grid.Columns[5].Width = windows.ExactWidth;
            for (int i = 0; i < windows.FillWeights.Length; i++) grid.Columns[i + 1].FillWeight = windows.FillWeights[i];
            grid.Columns[0].HeaderCell.ToolTipText = "Click to deselect all categories. If any are off, click to select all.";
            foreach (DataGridViewColumn column in grid.Columns) column.SortMode = DataGridViewColumnSortMode.NotSortable;
            foreach (Rule r in rules) grid.Rows.Add(r.Enabled, r.Name, r.Randomise ? "Randomise" : "Redact", r.Replacement, r.RandomTemplate, ExactCount(r.Exact));
            grid.CurrentCellDirtyStateChanged += delegate { if (grid.IsCurrentCellDirty) grid.CommitEdit(DataGridViewDataErrorContexts.Commit); };
            grid.CellValueChanged += delegate(object sender, DataGridViewCellEventArgs e)
            {
                if (loading || e.RowIndex < 0) return;
                DataGridViewRow row = grid.Rows[e.RowIndex]; Rule r = rules[e.RowIndex];
                r.Enabled = Convert.ToBoolean(row.Cells[0].Value); r.Randomise = Convert.ToString(row.Cells[2].Value) == "Randomise";
                r.Replacement = Convert.ToString(row.Cells[3].Value); r.RandomTemplate = Convert.ToString(row.Cells[4].Value); SettingsChanged(); Schedule();
            };
            grid.CellDoubleClick += delegate(object sender, DataGridViewCellEventArgs e) { if (e.ColumnIndex == 5 && e.RowIndex >= 0) ExactMatches(e.RowIndex); };
            grid.ColumnHeaderMouseClick += delegate(object sender, DataGridViewCellMouseEventArgs e)
            {
                if (e.ColumnIndex == 0 && e.Button == MouseButtons.Left) ToggleAllCategories();
            };
            grid.DataError += delegate(object sender, DataGridViewDataErrorEventArgs e) { e.ThrowException = false; };
        }
        private void FitRulesHeight(TableLayoutPanel layout)
        {
            int height = grid.ColumnHeadersHeight + grid.Rows.GetRowsHeight(DataGridViewElementStates.Visible) + grid.Margin.Vertical + 2;
            if (grid.Columns.GetColumnsWidth(DataGridViewElementStates.Visible) > grid.ClientSize.Width)
                height += SystemInformation.HorizontalScrollBarHeight;
            if (layout.RowStyles[4].Height != height) layout.RowStyles[4].Height = height;
        }
        private void ToggleAllCategories()
        {
            grid.EndEdit();
            bool enabled = !rules.All(r => r.Enabled);
            loading = true;
            try
            {
                for (int i = 0; i < rules.Count; i++)
                {
                    rules[i].Enabled = enabled;
                    grid.Rows[i].Cells[0].Value = enabled;
                }
            }
            finally { loading = false; }
            SettingsChanged(); Schedule();
        }
        private void SetModes(bool random)
        {
            loading = true;
            for (int i = 0; i < rules.Count; i++) { rules[i].Randomise = random; grid.Rows[i].Cells[2].Value = random ? "Randomise" : "Redact"; }
            loading = false; SettingsChanged(); Schedule();
        }
        private static int ExactCount(string text) { return text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Count(x => x.Trim().Length > 0); }
        internal static Rectangle VisibleBounds(Rectangle saved, Size minimum)
        {
            Rectangle area = Screen.AllScreens.Any(s => s.WorkingArea.IntersectsWith(saved)) ? Screen.FromRectangle(saved).WorkingArea : Screen.PrimaryScreen.WorkingArea;
            int width = Math.Min(area.Width, Math.Max(minimum.Width, saved.Width));
            int height = Math.Min(area.Height, Math.Max(minimum.Height, saved.Height));
            return new Rectangle(Math.Max(area.Left, Math.Min(saved.X, area.Right - width)), Math.Max(area.Top, Math.Min(saved.Y, area.Bottom - height)), width, height);
        }
        private void CaptureWindowPreferences()
        {
            if (!windowReady) return;
            if (WindowState == FormWindowState.Normal) windows.MainBounds = Bounds;
            else if (RestoreBounds.Width > 0) windows.MainBounds = RestoreBounds;
            if (WindowState != FormWindowState.Minimized) windows.Maximized = WindowState == FormWindowState.Maximized;
            int available = textSplit.ClientSize.Width - textSplit.SplitterWidth;
            if (available > 0) windows.SplitRatio = (double)textSplit.SplitterDistance / available;
            windows.OnWidth = grid.Columns[0].Width; windows.ExactWidth = grid.Columns[5].Width;
            for (int i = 0; i < windows.FillWeights.Length; i++) windows.FillWeights[i] = grid.Columns[i + 1].FillWeight;
        }
        private void SettingsChanged()
        {
            if (loading || !settingsWritable) return;
            settingsDirty = true; settingsTimer.Stop(); settingsTimer.Start();
        }
        internal bool SavePreferences(bool showError)
        {
            if (!settingsDirty || !settingsWritable) return true;
            try { CaptureWindowPreferences(); settings.Save(rules, repeat.Checked, windows); settingsDirty = false; settingsErrorShown = false; return true; }
            catch
            {
                if (showError && !settingsErrorShown)
                {
                    settingsErrorShown = true;
                    MessageBox.Show(this, "Settings could not be saved. Your changes are still active in this window. Check that your local application-data folder is writable; changes will be retried on close.", "Veilmark settings", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                return false;
            }
        }
        private void ExactMatches(int selected = -1)
        {
            using (Form form = CreateExactMatchDialog(selected)) form.ShowDialog(this);
        }
        internal Form CreateExactMatchDialog(int selected = -1)
        {
            if (selected < 0) selected = windows.ExactCategory;
            Icon dialogIcon = (Icon)Icon.Clone();
            var form = new Form { Text = "Exact matches — Veilmark", Icon = dialogIcon, AutoScaleMode = AutoScaleMode.Dpi, Size = new Size(710, 580), MinimumSize = new Size(560, 420), StartPosition = FormStartPosition.CenterParent, Font = Font, MinimizeBox = false, MaximizeBox = false };
            if (windows.ExactBounds.Width > 0) { form.StartPosition = FormStartPosition.Manual; form.Bounds = VisibleBounds(windows.ExactBounds, form.MinimumSize); }
            {
                var panel = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 4, ColumnCount = 1, Padding = new Padding(15) };
                panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
                panel.RowStyles.Add(new RowStyle(SizeType.AutoSize)); panel.RowStyles.Add(new RowStyle(SizeType.AutoSize)); panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                panel.Controls.Add(new Label { Text = "One literal value per line. Matches ignore case and respect word boundaries.\nApply saves your lists encrypted for your Windows account.", AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(3, 3, 3, 10) });
                var select = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
                select.Items.AddRange(rules.Select(r => (object)r.Name).ToArray()); panel.Controls.Add(select);
                var editor = Editor(false); editor.WordWrap = true; panel.Controls.Add(editor);
                string[] edits = rules.Select(r => r.Exact).ToArray(); int previous = selected;
                select.SelectedIndexChanged += delegate { if (select.SelectedIndex < 0) return; edits[previous] = editor.Text; previous = select.SelectedIndex; editor.Text = edits[previous]; };
                editor.Text = edits[selected]; select.SelectedIndex = selected;
                var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = false, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 8, 0, 2) };
                var apply = Button("Apply"); apply.DialogResult = DialogResult.OK; actions.Controls.Add(apply);
                var cancel = Button("Cancel"); cancel.DialogResult = DialogResult.Cancel; actions.Controls.Add(cancel); panel.Controls.Add(actions);
                form.Controls.Add(panel); form.AcceptButton = apply; form.CancelButton = cancel;
                form.FormClosing += delegate
                {
                    windows.ExactCategory = select.SelectedIndex; windows.ExactBounds = form.Bounds;
                    SettingsChanged();
                    if (form.DialogResult != DialogResult.OK) { SavePreferences(true); return; }
                    edits[previous] = editor.Text; loading = true;
                    for (int i = 0; i < rules.Count; i++) { rules[i].Exact = edits[i]; grid.Rows[i].Cells[5].Value = ExactCount(edits[i]); }
                    loading = false; SettingsChanged(); SavePreferences(true); Schedule();
                };
                form.Disposed += delegate { dialogIcon.Dispose(); };
            }
            return form;
        }
        private void Schedule()
        {
            if (loading || IsDisposed) return;
            version++; if (cancellation != null) cancellation.Cancel();
            ready = false; copy.Enabled = save.Enabled = false; Output.Clear();
            status.Text = Input.TextLength == 0 ? "Ready — paste text to begin." : "Updating output…";
            counts.Text = ""; counts.ToolTipText = "";
            debounce.Stop(); if (Input.TextLength > 0) debounce.Start();
        }
        internal async Task ProcessNow()
        {
            debounce.Stop();
            int current = version;
            if (cancellation != null) cancellation.Cancel();
            var source = new CancellationTokenSource(); cancellation = source;
            string input = Input.Text;
            List<Rule> snapshot = rules.Select(r => r.Copy()).ToList();
            Engine worker = engine; bool matchRepeated = repeat.Checked;
            try
            {
                Result result = await Task.Run(() => worker.Process(input, snapshot, matchRepeated, source.Token));
                if (IsDisposed || current != version || source.IsCancellationRequested) return;
                Output.Text = result.Text; ready = true; copy.Enabled = save.Enabled = Output.TextLength > 0;
                status.Text = result.Count == 0 ? "No matches found — review the text before copying." : "Output ready — click the right-hand text box to copy.";
                counts.Text = result.Count + " replacement(s) • " + input.Length.ToString("N0") + " source characters";
                counts.ToolTipText = String.Join(", ", result.Counts.Select(p => p.Key + ": " + p.Value));
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                if (IsDisposed || current != version) return;
                ready = false; Output.Clear(); copy.Enabled = save.Enabled = false;
                status.Text = ex is RegexMatchTimeoutException ? "Detection timed out. Output withheld; process a smaller section." : ex is InvalidOperationException ? ex.Message : "Unable to process text. Output withheld; try a smaller section.";
            }
            finally { if (Object.ReferenceEquals(cancellation, source)) cancellation = null; source.Dispose(); }
        }
        private void ClearText()
        {
            Input.Clear(); Input.ClearUndo(); Output.Clear(); Output.ClearUndo();
            engine = new Engine(); status.Text = "Source and output cleared. Saved rules and exact-match lists are retained. Clipboard unchanged.";
        }
        private void ClipboardAction(Action action)
        {
            try { action(); } catch { status.Text = "The Windows clipboard is unavailable. Try again."; }
        }
        private void OpenFile(string path)
        {
            if (path == null)
            {
                using (var dialog = new OpenFileDialog { Filter = "Text files|*.txt;*.log;*.json;*.yaml;*.yml;*.xml;*.csv;*.ini;*.env;*.config;*.md|All files|*.*" })
                { if (dialog.ShowDialog(this) != DialogResult.OK) return; path = dialog.FileName; }
            }
            try
            {
                if (new FileInfo(path).Length > 4000000) { MessageBox.Show(this, "This file is too large. Open a smaller text file (up to 1,000,000 characters)."); return; }
                string text = File.ReadAllText(path, new UTF8Encoding(false, true));
                if (text.Length > 1000000 || text.IndexOf('\0') >= 0) { MessageBox.Show(this, "Use a plain-text file of up to 1,000,000 characters. Binary files are not supported."); return; }
                if (Input.TextLength > 0 && MessageBox.Show(this, "Replace the current source text with this file?", "Open text file", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
                Input.Text = text;
            }
            catch { MessageBox.Show(this, "Could not read the file. Use a readable UTF-8 or BOM-marked Unicode text file."); }
        }
        private void SaveOutput()
        {
            if (!ready) return;
            using (var dialog = new SaveFileDialog { Filter = "Text file|*.txt", FileName = "redacted.txt", OverwritePrompt = true })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                try { File.WriteAllText(dialog.FileName, Output.Text, new UTF8Encoding(false)); status.Text = "Output saved."; }
                catch { status.Text = "Could not save the output — choose a writable folder."; MessageBox.Show(this, "Could not save the output. Choose a writable folder."); }
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            if (args.Length > 0 && args[0] == "--self-test") return Tests.Run(args.Length > 1 ? args[1] : null);
            if (args.Length == 2 && args[0] == "--verify-persistence") return Tests.VerifyPersistence(args[1]);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate { MessageBox.Show("An unexpected error occurred. Close and reopen Veilmark. No diagnostic text has been saved."); };
            Application.Run(new MainForm()); return 0;
        }
    }
    internal static class Tests
    {
        private static int passed;
        private static void Check(bool condition, string name) { if (!condition) throw new Exception(name); passed++; }
        private static Result RunText(string text, List<Rule> rules = null, Engine engine = null, bool repeats = true)
        { return (engine ?? new Engine()).Process(text, rules ?? Rule.Defaults(), repeats, CancellationToken.None); }
        private static IEnumerable<Control> Descendants(Control parent)
        {
            foreach (Control child in parent.Controls) { yield return child; foreach (Control nested in Descendants(child)) yield return nested; }
        }
        private static void CheckLayout(MainForm form, string size)
        {
            Label subtitle = Descendants(form).OfType<Label>().Single(l => l.Text.StartsWith("Local text redaction."));
            Check(subtitle.Height >= subtitle.PreferredHeight && subtitle.Bottom <= subtitle.Parent.ClientSize.Height, "Subtitle fully visible at " + size);
            var grid = Descendants(form).OfType<DataGridView>().Single();
            Rectangle lastRow = grid.GetRowDisplayRectangle(grid.RowCount - 1, true);
            Check(lastRow.Height == grid.Rows[grid.RowCount - 1].Height && lastRow.Bottom <= grid.ClientSize.Height, "All rule rows fully visible at " + size);
            Check(!grid.Controls.OfType<VScrollBar>().Any(s => s.Visible), "No rules vertical scrollbar at " + size);
            var statusBar = Descendants(form).OfType<StatusStrip>().Single();
            Check(statusBar.Visible && statusBar.Bottom <= form.ClientSize.Height && statusBar.Top >= grid.RectangleToScreen(grid.ClientRectangle).Bottom - form.PointToScreen(Point.Empty).Y, "Status bar visible below content at " + size);
        }
        private static void ClickOutput(MainForm form, MouseButtons button = MouseButtons.Left)
        {
            typeof(Control).GetMethod("OnMouseClick", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(form.Output, new object[] { new MouseEventArgs(button, 1, 20, 20, 0) });
        }
        private static string StatusText(MainForm form) { return Descendants(form).OfType<StatusStrip>().Single().Items["ActivityStatus"].Text; }
        private static NotifyIcon TrayIcon(MainForm form) { return (NotifyIcon)typeof(MainForm).GetField("tray", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(form); }
        private static bool WaitFor(Func<bool> condition, int timeoutMilliseconds = 3000)
        {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
            do
            {
                Application.DoEvents();
                if (condition()) return true;
                Thread.Sleep(20);
            }
            while (DateTime.UtcNow < deadline);
            Application.DoEvents();
            return condition();
        }
        private static void TrayTests(MainForm form)
        {
            Rectangle originalBounds = form.Bounds;
            string originalInput = form.Input.Text, originalOutput = form.Output.Text;
            NotifyIcon tray = TrayIcon(form);
            form.WindowState = FormWindowState.Minimized;
            Check(WaitFor(() => !form.Visible && !form.ShowInTaskbar && tray.Visible), "Minimise hides window and shows tray icon");
            Check(form.Input.Text == originalInput && form.Output.Text == originalOutput, "Minimise preserves current text");
            ((ToolStripMenuItem)tray.ContextMenuStrip.Items["Open"]).PerformClick();
            Check(WaitFor(() => form.Visible && form.ShowInTaskbar && form.WindowState == FormWindowState.Normal && !tray.Visible), "Tray Open restores normal window");
            form.WindowState = FormWindowState.Maximized; WaitFor(() => form.WindowState == FormWindowState.Maximized);
            form.WindowState = FormWindowState.Minimized;
            Check(WaitFor(() => !form.Visible && tray.Visible), "Maximized window minimises to tray");
            typeof(NotifyIcon).GetMethod("OnDoubleClick", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(tray, new object[] { EventArgs.Empty });
            Check(WaitFor(() => form.Visible && form.WindowState == FormWindowState.Maximized && !tray.Visible), "Tray double-click restores maximized window");
            form.WindowState = FormWindowState.Normal; form.Bounds = originalBounds; Application.DoEvents();
        }
        private static void ClickOnHeader(DataGridView grid)
        {
            typeof(DataGridView).GetMethod("OnColumnHeaderMouseClick", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(grid,
                new object[] { new DataGridViewCellMouseEventArgs(0, -1, 5, 5, new MouseEventArgs(MouseButtons.Left, 1, 5, 5, 0)) });
        }
        private static void CheckDialogLayout(Form dialog, string label)
        {
            foreach (Button button in Descendants(dialog).OfType<Button>())
            {
                Rectangle buttonArea = button.RectangleToScreen(button.ClientRectangle);
                bool visible = true;
                for (Control parent = button.Parent; parent != null; parent = parent.Parent)
                    visible = visible && parent.RectangleToScreen(parent.ClientRectangle).Contains(buttonArea);
                Check(visible && button.Height >= button.PreferredSize.Height, button.Text + " fully visible at " + label);
            }
        }
        private static void ExactDialogTests(MainForm parent, string folder, string settingsPath)
        {
            using (Form dialog = parent.CreateExactMatchDialog(5))
            {
                Exception failure = null;
                dialog.Shown += delegate
                {
                    try
                    {
                        using (var a = new MemoryStream()) using (var b = new MemoryStream())
                        { dialog.Icon.Save(a); parent.Icon.Save(b); Check(a.ToArray().SequenceEqual(b.ToArray()), "Exact dialog uses Veilmark icon"); }
                        CheckDialogLayout(dialog, "default dialog size");
                        using (var bitmap = new Bitmap(dialog.Width, dialog.Height)) { dialog.DrawToBitmap(bitmap, new Rectangle(Point.Empty, dialog.Size)); bitmap.Save(Path.Combine(folder, "exact-matches.png")); }
                        dialog.Size = dialog.MinimumSize; dialog.PerformLayout();
                        CheckDialogLayout(dialog, "minimum dialog size");
                        using (var bitmap = new Bitmap(dialog.Width, dialog.Height)) { dialog.DrawToBitmap(bitmap, new Rectangle(Point.Empty, dialog.Size)); bitmap.Save(Path.Combine(folder, "exact-matches-minimum.png")); }
                        dialog.Size = new Size(650, 480);
                        var editor = Descendants(dialog).OfType<TextBox>().Single();
                        var select = Descendants(dialog).OfType<ComboBox>().Single();
                        editor.Text = "Morgan Synthetic\r\nUnicode 示例";
                        select.SelectedIndex = 0; editor.Text = "synthetic_saved_exact_secret";
                        select.SelectedIndex = 5;
                        Check(editor.Text.Contains("Morgan Synthetic"), "Exact list survives category switch");
                        Descendants(dialog).OfType<Button>().Single(b => b.Text == "Apply").PerformClick();
                    }
                    catch (Exception ex) { failure = ex; dialog.DialogResult = DialogResult.Cancel; dialog.Close(); }
                };
                dialog.ShowDialog(parent);
                if (failure != null) throw failure;
            }
            Check(new SettingsStore(settingsPath).Load().Rules[0].Exact == "synthetic_saved_exact_secret", "Apply persists current and other category lists");
            using (Form dialog = parent.CreateExactMatchDialog(0))
            {
                dialog.Shown += delegate
                {
                    Descendants(dialog).OfType<TextBox>().Single().Text = "discard_synthetic_edit";
                    Descendants(dialog).OfType<ComboBox>().Single().SelectedIndex = 6;
                    Descendants(dialog).OfType<Button>().Single(b => b.Text == "Cancel").PerformClick();
                };
                dialog.ShowDialog(parent);
            }
            Check(new SettingsStore(settingsPath).Load().Rules[0].Exact == "synthetic_saved_exact_secret", "Cancel leaves saved exact lists intact");
            Check(new SettingsStore(settingsPath).Load().Windows.ExactCategory == 6 && new SettingsStore(settingsPath).Load().Windows.ExactBounds.Size == new Size(650, 480), "Exact category and dialog size persist independently of cancelled list edits");
            Descendants(parent).OfType<Button>().Single(b => b.Text == "Clear all text").PerformClick();
            using (Form dialog = parent.CreateExactMatchDialog(0))
                Check(Descendants(dialog).OfType<TextBox>().Single().Text == "synthetic_saved_exact_secret", "Clear text preserves exact-match lists");
        }
        private static void SettingsTests(string folder)
        {
            string path = Path.Combine(folder, "store-" + Guid.NewGuid().ToString("N"), "settings.dat");
            var store = new SettingsStore(path);
            var rules = Rule.Defaults();
            Check(store.Load().Rules.All(r => r.Enabled), "Missing settings uses defaults");
            rules[0].Exact = "synthetic_only_private_fixture_123";
            rules[0].Replacement = "replacement_示例"; rules[0].Enabled = false; rules[0].Randomise = true;
            rules[0].RandomTemplate = "saved-{random}";
            store.Save(rules, false);
            Preferences loaded = store.Load();
            Check(loaded.Rules[0].Exact == rules[0].Exact && loaded.Rules[0].Replacement == rules[0].Replacement, "Encrypted settings round trip including Unicode");
            Check(!loaded.Repeats && !loaded.Rules[0].Enabled && loaded.Rules[0].Randomise && loaded.Rules[0].RandomTemplate == "saved-{random}", "All preference types round trip");
            var layout = new WindowPreferences { MainBounds = new Rectangle(30, 40, 1200, 850), Maximized = true, ExactBounds = new Rectangle(70, 80, 650, 480), ExactCategory = 6, SplitRatio = 0.42, OnWidth = 65, ExactWidth = 70, FillWeights = new float[] { 20, 15, 30, 35 } };
            store.Save(rules, false, layout);
            WindowPreferences savedLayout = store.Load().Windows;
            Check(savedLayout.MainBounds == layout.MainBounds && savedLayout.Maximized && savedLayout.ExactBounds == layout.ExactBounds && savedLayout.ExactCategory == 6 && savedLayout.SplitRatio == 0.42 && savedLayout.OnWidth == 65 && savedLayout.ExactWidth == 70 && savedLayout.FillWeights.SequenceEqual(layout.FillWeights), "All window preferences round trip");
            byte[] first = File.ReadAllBytes(path);
            Check(!Encoding.UTF8.GetString(first).Contains(rules[0].Exact) && !Encoding.Unicode.GetString(first).Contains(rules[0].Exact), "Settings file contains no plaintext fixture");
            rules[0].Exact = "second_synthetic_fixture"; store.Save(rules, true);
            Check(store.Load().Rules[0].Exact == rules[0].Exact && store.Load().Repeats, "Atomic save replaces existing settings");
            byte[] valid = File.ReadAllBytes(path);
            rules[0].Exact = new string('x', 1000001); bool rejected = false;
            try { store.Save(rules, true); } catch (InvalidDataException) { rejected = true; }
            Check(rejected && valid.SequenceEqual(File.ReadAllBytes(path)), "Failed validation preserves existing encrypted settings");
            Check(Directory.GetFiles(Path.GetDirectoryName(path), "*.tmp").Length == 0, "No temporary settings left after save");
            rules[0].Exact = "legacy_synthetic_secret";
            using (var memory = new MemoryStream())
            {
                using (var writer = new BinaryWriter(memory, Encoding.UTF8, true))
                {
                    writer.Write("Veilmark.Settings.1"); writer.Write(false); writer.Write(rules.Count);
                    foreach (Rule rule in rules) { writer.Write(rule.Id); writer.Write(rule.Enabled); writer.Write(rule.Randomise); writer.Write(rule.Replacement); writer.Write(rule.RandomTemplate); writer.Write(rule.Exact); }
                }
                File.WriteAllBytes(path, ProtectedData.Protect(memory.ToArray(), null, DataProtectionScope.CurrentUser));
            }
            Preferences legacy = store.Load();
            Check(legacy.Rules[0].Exact == "legacy_synthetic_secret" && !legacy.Repeats && legacy.Windows.MainBounds.IsEmpty, "Version 1.2.0 settings load without losing existing preferences");
            store.Save(legacy.Rules, legacy.Repeats, legacy.Windows);
            Check(store.Load().Rules[0].Exact == "legacy_synthetic_secret", "Legacy settings migrate to new format");
            Rectangle relocated = MainForm.VisibleBounds(new Rectangle(-99999, -99999, 1150, 820), new Size(1020, 780));
            Check(Screen.AllScreens.Any(s => s.WorkingArea.Contains(relocated)), "Disconnected display bounds return to a visible screen");
            File.WriteAllBytes(path, new byte[] { 1, 2, 3, 4 }); bool corrupt = false;
            try { store.Load(); } catch (CryptographicException) { corrupt = true; }
            Check(corrupt && File.ReadAllBytes(path).SequenceEqual(new byte[] { 1, 2, 3, 4 }), "Corrupt settings detected without overwriting");
            File.Delete(path); Directory.Delete(Path.GetDirectoryName(path));
        }
        public static int VerifyPersistence(string path)
        {
            try
            {
                using (var form = new MainForm(path))
                {
                    var grid = Descendants(form).OfType<DataGridView>().Single();
                    Preferences stored = new SettingsStore(path).Load();
                    return !Convert.ToBoolean(grid.Rows[0].Cells[0].Value) && Convert.ToString(grid.Rows[0].Cells[2].Value) == "Randomise" && Convert.ToString(grid.Rows[0].Cells[3].Value) == "immediate_close_edit" && Convert.ToString(grid.Rows[0].Cells[4].Value) == "saved-ui-{random}" && !Descendants(form).OfType<CheckBox>().Single().Checked && stored.Rules[0].Exact == "synthetic_saved_exact_secret" && stored.Windows.ExactCategory == 6 && stored.Windows.Maximized && form.Input.TextLength == 0 && form.Output.TextLength == 0 ? 0 : 1;
                }
            }
            catch { return 1; }
        }
        public static int Run(string folder)
        {
            try
            {
                EngineTests();
                if (folder != null)
                {
                    Directory.CreateDirectory(folder);
                    SettingsTests(folder);
                    string testSettingsPath = Path.Combine(folder, "ui-settings-" + Guid.NewGuid().ToString("N"), "settings.dat");
                    var clipboardWrites = new List<string>(); bool clipboardUnavailable = false;
                    using (var form = new MainForm(testSettingsPath, text => { if (clipboardUnavailable) throw new InvalidOperationException(); clipboardWrites.Add(text); }))
                    {
                        Exception failure = null;
                        form.Shown += async delegate
                        {
                            try
                            {
                                form.Input.Text = MainForm.Sample; await form.ProcessNow();
                                Check(form.Output.Text.Contains("[REDACTED_PASSWORD]"), "UI renders engine output");
                                Check(!form.Output.Text.Contains("Demo-only-Password"), "UI synthetic secret removed");
                                Check(form.Output.ReadOnly, "Output is read-only");
                                form.Output.Select(0, 3); ClickOutput(form);
                                Check(clipboardWrites.Count == 1 && clipboardWrites[0] == form.Output.Text, "Output click copies full output, not selection");
                                Check(StatusText(form) == "Copied " + form.Output.TextLength.ToString("N0") + " characters to the clipboard.", "Output click confirms copy in status bar");
                                ClickOutput(form, MouseButtons.Right);
                                Check(clipboardWrites.Count == 1, "Right-click does not trigger automatic copy");
                                Descendants(form).OfType<Button>().Single(b => b.Text == "Copy output").PerformClick();
                                Check(clipboardWrites.Count == 2 && clipboardWrites[1] == form.Output.Text, "Copy button uses same full-output path");
                                clipboardUnavailable = true; ClickOutput(form);
                                Check(clipboardWrites.Count == 2 && StatusText(form).StartsWith("Copy failed"), "Clipboard failure reported without exposing content");
                                clipboardUnavailable = false; ClickOutput(form);
                                CheckLayout(form, "default size");
                                using (var bitmap = new Bitmap(form.Width, form.Height)) { form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, form.Size)); bitmap.Save(Path.Combine(folder, "preview.png")); }
                                form.Size = form.MinimumSize; form.PerformLayout();
                                CheckLayout(form, "minimum size");
                                using (var bitmap = new Bitmap(form.Width, form.Height)) { form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, form.Size)); bitmap.Save(Path.Combine(folder, "preview-minimum.png")); }
                                TrayTests(form);
                                int beforePendingClick = clipboardWrites.Count;
                                form.Input.Text = "password=copy_guard_synthetic_secret"; ClickOutput(form);
                                Check(clipboardWrites.Count == beforePendingClick && StatusText(form).StartsWith("Output is not ready"), "Click cannot copy stale output while processing");
                                form.Input.Text = "password=synthetic_ui_secret"; await form.ProcessNow();
                                var categoryGrid = Descendants(form).OfType<DataGridView>().Single();
                                string settingsBefore = String.Join("|", categoryGrid.Rows.Cast<DataGridViewRow>().SelectMany(r => r.Cells.Cast<DataGridViewCell>().Skip(1).Select(c => Convert.ToString(c.Value))));
                                ClickOnHeader(categoryGrid); await form.ProcessNow();
                                Check(categoryGrid.Rows.Cast<DataGridViewRow>().All(r => !Convert.ToBoolean(r.Cells[0].Value)) && form.Output.Text == form.Input.Text, "On header deselects all and refreshes output");
                                ClickOnHeader(categoryGrid); await form.ProcessNow();
                                Check(categoryGrid.Rows.Cast<DataGridViewRow>().All(r => Convert.ToBoolean(r.Cells[0].Value)) && !form.Output.Text.Contains("synthetic_ui_secret"), "On header selects all and refreshes output");
                                categoryGrid.Rows[3].Cells[0].Value = false;
                                ClickOnHeader(categoryGrid); await form.ProcessNow();
                                Check(categoryGrid.Rows.Cast<DataGridViewRow>().All(r => Convert.ToBoolean(r.Cells[0].Value)), "On header selects all from mixed state");
                                Check(settingsBefore == String.Join("|", categoryGrid.Rows.Cast<DataGridViewRow>().SelectMany(r => r.Cells.Cast<DataGridViewCell>().Skip(1).Select(c => Convert.ToString(c.Value)))), "On header preserves other settings");
                                categoryGrid.Rows[0].Cells[0].Value = false; await form.ProcessNow();
                                Check(form.Output.Text.Contains("synthetic_ui_secret"), "UI category checkbox changes output");
                                categoryGrid.Rows[0].Cells[0].Value = true;
                                categoryGrid.Rows[0].Cells[3].Value = "<MASKED>"; await form.ProcessNow();
                                Check(form.Output.Text == "password=<MASKED>", "UI replacement editing changes output");
                                Descendants(form).OfType<Button>().Single(b => b.Text == "Randomise all").PerformClick(); await form.ProcessNow();
                                Check(form.Output.Text != "password=<MASKED>" && !form.Output.Text.Contains("synthetic_ui_secret"), "UI randomise action");
                                categoryGrid.Rows[0].Cells[4].Value = "alias-{random}"; await form.ProcessNow();
                                Check(form.Output.Text.StartsWith("password=alias-"), "UI random template editing");
                                string alias = form.Output.Text;
                                Descendants(form).OfType<Button>().Single(b => b.Text == "New random values").PerformClick(); await form.ProcessNow();
                                Check(form.Output.Text != alias, "UI new random values action");
                                Descendants(form).OfType<Button>().Single(b => b.Text == "Redact all").PerformClick();
                                categoryGrid.Rows[0].Cells[3].Value = "[REDACTED_PASSWORD]";
                                form.Input.Text = "password=old_synthetic_value";
                                Task first = form.ProcessNow();
                                form.Input.Text = "password=new_synthetic_value";
                                await form.ProcessNow(); await first;
                                Check(!form.Output.Text.Contains("synthetic_value") && form.Output.Text == "password=[REDACTED_PASSWORD]", "Latest edit wins");
                                form.Input.Clear(); Check(form.Output.Text.Length == 0, "Clearing source invalidates output");
                                int beforeEmptyClick = clipboardWrites.Count; ClickOutput(form);
                                Check(clipboardWrites.Count == beforeEmptyClick && StatusText(form).StartsWith("Nothing to copy"), "Empty output leaves clipboard unchanged and reports status");
                                Check(!Descendants(form).OfType<Button>().Single(b => b.Text == "Copy output").Enabled, "Copy disabled for invalidated output");
                                ExactDialogTests(form, folder, testSettingsPath);
                                categoryGrid.Rows[0].Cells[0].Value = false;
                                categoryGrid.Rows[0].Cells[2].Value = "Randomise";
                                categoryGrid.Rows[0].Cells[3].Value = "saved_ui_replacement";
                                categoryGrid.Rows[0].Cells[4].Value = "saved-ui-{random}";
                                Descendants(form).OfType<CheckBox>().Single().Checked = false;
                                form.Input.Text = "SOURCE_MUST_NEVER_BE_SAVED_123456";
                                await Task.Delay(850);
                                Preferences saved = new SettingsStore(testSettingsPath).Load();
                                Check(!saved.Rules[0].Enabled && saved.Rules[0].Randomise && saved.Rules[0].Replacement == "saved_ui_replacement" && !saved.Repeats, "Settings automatically save without closing app");
                                byte[] decrypted = ProtectedData.Unprotect(File.ReadAllBytes(testSettingsPath), null, DataProtectionScope.CurrentUser);
                                try { Check(!Encoding.UTF8.GetString(decrypted).Contains("SOURCE_MUST_NEVER_BE_SAVED_123456"), "Source and output excluded from settings payload"); }
                                finally { Array.Clear(decrypted, 0, decrypted.Length); }
                                form.Bounds = MainForm.VisibleBounds(new Rectangle(30, 40, 1150, 830), form.MinimumSize);
                                var split = Descendants(form).OfType<SplitContainer>().Single();
                                split.SplitterDistance = (int)((split.Width - split.SplitterWidth) * 0.43);
                                categoryGrid.Columns[0].Width = 65; categoryGrid.Columns[5].Width = 72;
                                categoryGrid.Columns[1].Width = 240;
                                form.WindowState = FormWindowState.Maximized;
                                categoryGrid.CurrentCell = categoryGrid.Rows[0].Cells[3]; categoryGrid.BeginEdit(true);
                                ((TextBox)categoryGrid.EditingControl).Text = "immediate_close_edit";
                            }
                            catch (Exception ex) { failure = ex; }
                            finally { form.Close(); }
                        };
                        Application.Run(form);
                        if (failure != null) throw failure;
                    }
                    using (var reopened = new MainForm(testSettingsPath))
                    {
                        var grid = Descendants(reopened).OfType<DataGridView>().Single();
                        Check(!Convert.ToBoolean(grid.Rows[0].Cells[0].Value) && Convert.ToString(grid.Rows[0].Cells[2].Value) == "Randomise" && Convert.ToString(grid.Rows[0].Cells[3].Value) == "immediate_close_edit" && Convert.ToString(grid.Rows[0].Cells[4].Value) == "saved-ui-{random}", "Closing immediately commits active cell and restores settings");
                        Check(!Descendants(reopened).OfType<CheckBox>().Single().Checked && Convert.ToInt32(grid.Rows[0].Cells[5].Value) == 1 && Convert.ToInt32(grid.Rows[5].Cells[5].Value) == 2, "New app instance restores repeat option and exact counts");
                        Check(reopened.Input.TextLength == 0 && reopened.Output.TextLength == 0, "New app instance never restores source or output");
                        Preferences stored = new SettingsStore(testSettingsPath).Load();
                        reopened.Show(); Application.DoEvents();
                        Check(reopened.WindowState == FormWindowState.Maximized && reopened.RestoreBounds == stored.Windows.MainBounds, "Main window bounds and maximized state restored: state=" + reopened.WindowState + ", actual=" + reopened.RestoreBounds + ", stored=" + stored.Windows.MainBounds + ", max=" + stored.Windows.Maximized);
                        var split = Descendants(reopened).OfType<SplitContainer>().Single();
                        Check(Math.Abs((double)split.SplitterDistance / (split.Width - split.SplitterWidth) - stored.Windows.SplitRatio) < 0.002, "Text panel divider restored");
                        Check(grid.Columns[0].Width == 65 && grid.Columns[5].Width == 72 && Enumerable.Range(0, 4).All(i => Math.Abs(grid.Columns[i + 1].FillWeight - stored.Windows.FillWeights[i]) < 0.1), "Rule column widths restored");
                        using (Form dialog = reopened.CreateExactMatchDialog())
                            Check(dialog.Size == stored.Windows.ExactBounds.Size && Descendants(dialog).OfType<ComboBox>().Single().SelectedIndex == 6, "Exact dialog layout and category restored");
                        NotifyIcon notify = TrayIcon(reopened);
                        reopened.WindowState = FormWindowState.Minimized; Application.DoEvents();
                        Check(notify.Visible && !reopened.Visible, "Quit test begins minimized in tray");
                        ((ToolStripMenuItem)notify.ContextMenuStrip.Items["Quit"]).PerformClick();
                        Check(WaitFor(() => reopened.IsDisposed && !notify.Visible), "Tray Quit closes app and removes tray icon");
                    }
                    var probe = new System.Diagnostics.ProcessStartInfo(Application.ExecutablePath, "--verify-persistence \"" + testSettingsPath + "\"") { UseShellExecute = false, CreateNoWindow = true, WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden };
                    using (var child = System.Diagnostics.Process.Start(probe))
                    {
                        bool completed = child.WaitForExit(15000);
                        if (!completed) child.Kill();
                        Check(completed && child.ExitCode == 0, "Separate process restores persisted selections after close");
                    }
                    File.Delete(testSettingsPath); Directory.Delete(Path.GetDirectoryName(testSettingsPath));
                    File.WriteAllText(Path.Combine(folder, "test-results.txt"), "PASS: " + passed + " synthetic checks. No real credentials used.\r\nEngine checks, output UI, stale-result protection, and window renders completed.\r\n");
                }
                return 0;
            }
            catch (Exception ex)
            {
                if (folder != null) File.WriteAllText(Path.Combine(folder, "test-results.txt"), "FAIL (synthetic self-test only): " + ex.ToString() + "\r\n");
                return 1;
            }
        }
        private static void EngineTests()
        {
            string[] cases = {
                "password=synthetic_Secret91", "DB_PASSWORD=synthetic_Secret91", "{\"password\":\"synthetic_Secret91\"}",
                "password: 'synthetic_Secret91'", "--password synthetic_Secret91", "postgres://demo:synthetic_Secret91@localhost/db",
                "encryption_key=synthetic_Secret91", "EncryptionKey: synthetic_Secret91", "apiKey=synthetic_Secret91", "X-API-Key: synthetic_Secret91",
                "Authorization: Bearer synthetic_Secret91", "access_token=synthetic_Secret91", "client_secret=synthetic_Secret91", "Username=synthetic_Secret91",
                "{\"name\":\"synthetic_Secret91\"}", "Address: synthetic_Secret91", "Cookie: session=synthetic_Secret91", "AccountKey=synthetic_Secret91"
            };
            for (int i = 0; i < cases.Length; i++) Check(!RunText(cases[i]).Text.Contains("synthetic_Secret91"), "Credential / label pattern " + i);
            Check(RunText("password=\"space secret \\\"quoted\\\" value\"").Text == "password=\"[REDACTED_PASSWORD]\"", "Escaped quoted value");
            Check(RunText("<password>synthetic_xml_secret</password>").Text == "<password>[REDACTED_PASSWORD]</password>", "XML credential element");
            Check(RunText("password: |\n  synthetic_yaml_secret\n  second_line\npublic: visible").Text == "password: [REDACTED_PASSWORD]\npublic: visible", "YAML multiline credential");
            Check(RunText("config:\n  api_key: >-\n    synthetic_key\n  public: visible").Text == "config:\n  api_key: [REDACTED_API_KEY]\n  public: visible", "Indented YAML multiline key");
            Check(RunText("x a.person+tag@example.invalid y").Text == "x [REDACTED_EMAIL] y", "Email boundaries");
            Check(RunText("Call at 42 Example Road tomorrow.").Text.Contains("[REDACTED_ADDRESS]"), "Street heuristic");
            Check(!RunText("Name: Alex Example\r\nNext line is public").Text.Contains("Alex Example"), "Full name label");
            Check(RunText("password=secret_synthetic\r\nCopy secret_synthetic").Text == "password=[REDACTED_PASSWORD]\r\nCopy [REDACTED_PASSWORD]", "Repeated value");
            Check(RunText("password=secret_synthetic\nCopy secret_synthetic", null, null, false).Text.EndsWith("Copy secret_synthetic"), "Repeat switch");
            Check(RunText("-----BEGIN RSA PRIVATE KEY-----\nSYNTHETICBLOCK\n-----END RSA PRIVATE KEY-----").Text == "[REDACTED_ENCRYPTION_KEY]", "Multiline PEM");
            Check(RunText("-----BEGIN PGP PRIVATE KEY BLOCK-----\nSYNTHETICBLOCK\n-----END PGP PRIVATE KEY BLOCK-----").Text == "[REDACTED_ENCRYPTION_KEY]", "Multiline PGP");
            Check(RunText("-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC_PARTIAL_BLOCK").Text == "[REDACTED_ENCRYPTION_KEY]", "Incomplete private key withheld to end of input");
            Check(RunText("ghp_abcdefghijklmnopqrstuvwxyz123456").Text == "[REDACTED_API_KEY]", "Standalone provider token");
            Check(RunText("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c3ludGhldGlj").Text == "[REDACTED_BEARER_TOKEN]", "Standalone JWT");
            Check(RunText("Public note\r\nColour: blue\r\nCount: 12").Text == "Public note\r\nColour: blue\r\nCount: 12", "Unrelated content unchanged");
            var rules = Rule.Defaults(); rules.ForEach(r => r.Enabled = false);
            Check(RunText(MainForm.Sample, rules).Text == MainForm.Sample, "All category switches off");
            rules = Rule.Defaults(); rules[0].Enabled = false;
            Check(RunText("password=synthetic_Secret91", rules).Text.Contains("synthetic_Secret91"), "Password switch independently off");
            rules = Rule.Defaults(); rules[3].Enabled = false;
            Check(RunText("access_token=synthetic_Secret91", rules).Text.Contains("synthetic_Secret91"), "Bearer switch independently off");
            rules = Rule.Defaults(); rules[2].Enabled = false;
            Check(RunText("api_token=synthetic_Secret91", rules).Text.Contains("synthetic_Secret91"), "API switch independently off");
            for (int i = 0; i < 8; i++)
            {
                rules = Rule.Defaults(); rules.ForEach(r => r.Enabled = false); rules[i].Enabled = true; rules[i].Exact = "UniqueSyntheticValue";
                Check(RunText("UniqueSyntheticValue", rules).Text == rules[i].Replacement, "Independent category " + i);
            }
            rules = Rule.Defaults(); rules[5].Exact = "Alex Example\nAnn";
            Check(RunText("alex example met Ann and Anna", rules).Text == "[REDACTED_NAME] met [REDACTED_NAME] and Anna", "Exact lists case and word boundaries");
            rules[0].Replacement = "<hidden>";
            Check(RunText("password=synthetic_Secret91", rules).Text == "password=<hidden>", "Custom replacement");
            rules[0].Replacement = "";
            Check(RunText("password=synthetic_Secret91", rules).Text == "password=", "Empty replacement deletes value");
            rules = Rule.Defaults(); rules[0].Randomise = true; rules[0].RandomTemplate = "{type}-{random}-{n}";
            var engine = new Engine(); string input = "password=synthetic_Secret91\npassword=synthetic_Secret91";
            string output = RunText(input, rules, engine).Text;
            Check(output.Split('\n')[0] == output.Split('\n')[1], "Same value same alias");
            Check(output == RunText(input, rules, engine).Text, "Aliases stable during session");
            Check(output != RunText(input, rules, new Engine()).Text, "Fresh randomisation changes aliases");
            Check(!output.Contains("synthetic_Secret91") && !output.Contains("{random}"), "Random alias has no source value");
            Check(!RunText("password=user@example.invalid").Text.Contains("example.invalid"), "Overlap union prevents partial exposure");
            Check(RunText("").Text == "", "Empty input");
            Check(RunText("名字: 公開\npassword=秘密123").Text == "名字: 公開\npassword=[REDACTED_PASSWORD]", "Unicode source");
            bool limited = false; try { RunText(new string('x', 1000001)); } catch (InvalidOperationException) { limited = true; }
            Check(limited, "Input size bound");
            var cts = new CancellationTokenSource(); cts.Cancel(); bool cancelled = false;
            try { new Engine().Process(input, Rule.Defaults(), true, cts.Token); } catch (OperationCanceledException) { cancelled = true; }
            Check(cancelled, "Cancellation");
        }
    }
}
