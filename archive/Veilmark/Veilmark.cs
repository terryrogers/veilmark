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
[assembly: AssemblyVersion("1.1.0.0")]
[assembly: AssemblyFileVersion("1.1.0.0")]

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
        private readonly Label status = new Label();
        private readonly Button copy = Button("Copy output"), save = Button("Save output…");
        private readonly CheckBox repeat = new CheckBox { Text = "Match repeated values", Checked = true, AutoSize = true, Margin = new Padding(12, 9, 8, 3) };
        private readonly System.Windows.Forms.Timer debounce = new System.Windows.Forms.Timer { Interval = 250 };
        private CancellationTokenSource cancellation;
        private int version;
        private bool ready, loading;
        private readonly ToolTip tips = new ToolTip();
        internal const string Sample = "Name: Alex Example\r\nEmail: alex@example.invalid\r\nAddress: 42 Example Road\r\nPostcode: SW1A 1AA\r\n\r\nDB_PASSWORD=Demo-only-Password!42\r\nAPI_KEY=demo_only_api_key_1234567890\r\nEncryptionKey=demo_only_encryption_key_123456\r\nAuthorization: Bearer demo.only.bearer-token\r\nClientSecret=demo_only_client_secret\r\n\r\nA repeated password: Demo-only-Password!42\r\nOrdinary text stays readable.";
        public MainForm()
        {
            Text = "Veilmark — local & private";
            using (Stream iconStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Veilmark.ico"))
                Icon = new Icon(iconStream, 32, 32);
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Segoe UI", 10);
            BackColor = Color.FromArgb(243, 246, 250);
            ForeColor = Color.FromArgb(28, 42, 60);
            MinimumSize = new Size(1020, 780); Size = new Size(1380, 960);
            StartPosition = FormStartPosition.CenterScreen;
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(18, 10, 18, 10) };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 43));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 43));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 267));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 51));
            Controls.Add(layout);
            var heading = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2 };
            heading.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 60));
            heading.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            var brandLogo = new PictureBox { SizeMode = PictureBoxSizeMode.Zoom, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 10, 3) };
            using (Stream logoStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Veilmark.png"))
            using (Image logo = Image.FromStream(logoStream)) brandLogo.Image = new Bitmap(logo);
            heading.Controls.Add(brandLogo, 0, 0); heading.SetRowSpan(brandLogo, 2);
            heading.Controls.Add(new Label { Text = "Veilmark", Font = new Font("Segoe UI", 21, FontStyle.Bold), AutoSize = true, Margin = Padding.Empty }, 1, 0);
            heading.Controls.Add(new Label { Text = "Local text redaction. No uploads, telemetry or automatic text storage.", AutoSize = true, ForeColor = Color.FromArgb(82, 99, 116), Margin = Padding.Empty }, 1, 1);
            layout.Controls.Add(heading, 0, 0);
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
            Add(toolbar, "Paste text", delegate { ClipboardAction(delegate { Input.Paste(); }); });
            Add(toolbar, "Open text file…", delegate { OpenFile(null); });
            Add(toolbar, "Load demo", delegate { if (Input.TextLength == 0 || MessageBox.Show(this, "Replace the current input with synthetic demonstration text?", "Load demo", MessageBoxButtons.YesNo) == DialogResult.Yes) Input.Text = Sample; });
            Add(toolbar, "Clear all text", delegate { ClearText(); });
            Add(toolbar, "New random values", delegate { engine = new Engine(); Schedule(); });
            toolbar.Controls.Add(copy); copy.Click += delegate { if (ready) ClipboardAction(delegate { Clipboard.SetText(Output.Text); }); };
            toolbar.Controls.Add(save); save.Click += delegate { SaveOutput(); };
            layout.Controls.Add(toolbar, 0, 1);
            var split = new SplitContainer { Size = new Size(1300, 400), Dock = DockStyle.Fill, Orientation = Orientation.Vertical, SplitterWidth = 12, BackColor = BackColor, Panel1MinSize = 250, Panel2MinSize = 250 };
            split.Size = new Size(1300, 400); split.SplitterDistance = 640;
            Pane(split.Panel1, "SOURCE TEXT", "Paste, type, or drop plain text / a text file here", Input);
            Pane(split.Panel2, "REDACTED OUTPUT", "Updates automatically • review before sharing", Output);
            layout.Controls.Add(split, 0, 2);
            var options = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 3, 0, 0) };
            options.Controls.Add(new Label { Text = "Redaction rules", AutoSize = true, Font = new Font(Font, FontStyle.Bold), Margin = new Padding(0, 7, 18, 0) });
            Add(options, "Redact all", delegate { SetModes(false); });
            Add(options, "Randomise all", delegate { SetModes(true); });
            Add(options, "Exact matches…", delegate { ExactMatches(); });
            options.Controls.Add(repeat); repeat.CheckedChanged += delegate { Schedule(); };
            layout.Controls.Add(options, 0, 3);
            SetupGrid(); layout.Controls.Add(grid, 0, 4);
            var footer = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            footer.RowStyles.Add(new RowStyle(SizeType.Absolute, 24)); footer.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            status.Dock = DockStyle.Fill; status.AutoEllipsis = true; status.Text = "Ready — paste text to begin.";
            footer.Controls.Add(status);
            footer.Controls.Add(new Label { Dock = DockStyle.Fill, AutoEllipsis = true, ForeColor = Color.FromArgb(95, 103, 119), Text = "Review before sharing. For unlabelled names / addresses, use Exact matches. Templates: {type}, {n}, {random}." });
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
            FormClosing += delegate { version++; debounce.Stop(); if (cancellation != null) cancellation.Cancel(); };
            FormClosed += delegate { debounce.Dispose(); tips.Dispose(); brandLogo.Image.Dispose(); Icon.Dispose(); };
            copy.Enabled = save.Enabled = false;
        }
        private static TextBox Editor(bool readOnly)
        {
            return new TextBox { Multiline = true, AcceptsReturn = true, AcceptsTab = true, ScrollBars = ScrollBars.Both, WordWrap = false, ReadOnly = readOnly, Dock = DockStyle.Fill, Font = new Font("Consolas", 11), BackColor = readOnly ? Color.FromArgb(246, 251, 250) : Color.White, BorderStyle = BorderStyle.FixedSingle, MaxLength = 1000000 };
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
            foreach (DataGridViewColumn column in grid.Columns) column.SortMode = DataGridViewColumnSortMode.NotSortable;
            foreach (Rule r in rules) grid.Rows.Add(r.Enabled, r.Name, "Redact", r.Replacement, r.RandomTemplate, "0");
            grid.CurrentCellDirtyStateChanged += delegate { if (grid.IsCurrentCellDirty) grid.CommitEdit(DataGridViewDataErrorContexts.Commit); };
            grid.CellValueChanged += delegate(object sender, DataGridViewCellEventArgs e)
            {
                if (loading || e.RowIndex < 0) return;
                DataGridViewRow row = grid.Rows[e.RowIndex]; Rule r = rules[e.RowIndex];
                r.Enabled = Convert.ToBoolean(row.Cells[0].Value); r.Randomise = Convert.ToString(row.Cells[2].Value) == "Randomise";
                r.Replacement = Convert.ToString(row.Cells[3].Value); r.RandomTemplate = Convert.ToString(row.Cells[4].Value); Schedule();
            };
            grid.CellDoubleClick += delegate(object sender, DataGridViewCellEventArgs e) { if (e.ColumnIndex == 5 && e.RowIndex >= 0) ExactMatches(e.RowIndex); };
            grid.DataError += delegate(object sender, DataGridViewDataErrorEventArgs e) { e.ThrowException = false; };
        }
        private void SetModes(bool random)
        {
            loading = true;
            for (int i = 0; i < rules.Count; i++) { rules[i].Randomise = random; grid.Rows[i].Cells[2].Value = random ? "Randomise" : "Redact"; }
            loading = false; Schedule();
        }
        private void ExactMatches(int selected = 0)
        {
            using (var form = new Form { Text = "Exact matches — kept only for this session", Size = new Size(710, 580), MinimumSize = new Size(560, 420), StartPosition = FormStartPosition.CenterParent, Font = Font, MinimizeBox = false, MaximizeBox = false })
            {
                var panel = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 4, ColumnCount = 1, Padding = new Padding(15) };
                panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
                panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 47)); panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 36)); panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
                panel.Controls.Add(new Label { Text = "One literal value per line. Matches ignore case and respect word boundaries.\nAdd full names / full addresses here to catch them in unlabelled text.", Dock = DockStyle.Fill });
                var select = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
                select.Items.AddRange(rules.Select(r => (object)r.Name).ToArray()); panel.Controls.Add(select);
                var editor = Editor(false); editor.WordWrap = true; panel.Controls.Add(editor);
                string[] edits = rules.Select(r => r.Exact).ToArray(); int previous = selected;
                select.SelectedIndexChanged += delegate { if (select.SelectedIndex < 0) return; edits[previous] = editor.Text; previous = select.SelectedIndex; editor.Text = edits[previous]; };
                editor.Text = edits[selected]; select.SelectedIndex = selected;
                var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 6, 0, 0) };
                var apply = Button("Apply"); apply.DialogResult = DialogResult.OK; actions.Controls.Add(apply);
                var cancel = Button("Cancel"); cancel.DialogResult = DialogResult.Cancel; actions.Controls.Add(cancel); panel.Controls.Add(actions);
                form.Controls.Add(panel); form.AcceptButton = apply; form.CancelButton = cancel;
                if (form.ShowDialog(this) == DialogResult.OK)
                {
                    edits[previous] = editor.Text; loading = true;
                    for (int i = 0; i < rules.Count; i++) { rules[i].Exact = edits[i]; grid.Rows[i].Cells[5].Value = edits[i].Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Count(x => x.Trim().Length > 0); }
                    loading = false; Schedule();
                }
            }
        }
        private void Schedule()
        {
            if (loading || IsDisposed) return;
            version++; if (cancellation != null) cancellation.Cancel();
            ready = false; copy.Enabled = save.Enabled = false; Output.Clear();
            status.Text = Input.TextLength == 0 ? "Ready — paste text to begin." : "Updating output…";
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
                status.Text = result.Count + " replacement(s) • " + input.Length.ToString("N0") + " characters" + (result.Count == 0 ? " • No matches found; review the text." : " • " + String.Join(", ", result.Counts.Select(p => p.Key + ": " + p.Value)));
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
            foreach (Rule r in rules) r.Exact = "";
            loading = true; foreach (DataGridViewRow row in grid.Rows) row.Cells[5].Value = "0"; loading = false;
            engine = new Engine(); status.Text = "Text and exact-match lists cleared. The Windows clipboard is unchanged.";
        }
        private void ClipboardAction(Action action)
        {
            try { action(); } catch { MessageBox.Show(this, "The Windows clipboard is unavailable. Try again.", "Clipboard"); }
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
                try { File.WriteAllText(dialog.FileName, Output.Text, new UTF8Encoding(false)); }
                catch { MessageBox.Show(this, "Could not save the output. Choose a writable folder."); }
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
        public static int Run(string folder)
        {
            try
            {
                EngineTests();
                if (folder != null)
                {
                    Directory.CreateDirectory(folder);
                    using (var form = new MainForm())
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
                                using (var bitmap = new Bitmap(form.Width, form.Height)) { form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, form.Size)); bitmap.Save(Path.Combine(folder, "preview.png")); }
                                form.Size = form.MinimumSize; form.PerformLayout();
                                using (var bitmap = new Bitmap(form.Width, form.Height)) { form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, form.Size)); bitmap.Save(Path.Combine(folder, "preview-minimum.png")); }
                                form.Input.Text = "password=synthetic_ui_secret"; await form.ProcessNow();
                                var categoryGrid = Descendants(form).OfType<DataGridView>().Single();
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
                                Check(!Descendants(form).OfType<Button>().Single(b => b.Text == "Copy output").Enabled, "Copy disabled for invalidated output");
                            }
                            catch (Exception ex) { failure = ex; }
                            finally { form.Close(); }
                        };
                        Application.Run(form);
                        if (failure != null) throw failure;
                    }
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
