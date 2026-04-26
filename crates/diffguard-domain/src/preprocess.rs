     1|use std::fmt;
     2|use std::str::FromStr;
     3|
     4|/// Supported programming languages for preprocessing.
     5|///
     6|/// Each language has specific comment and string syntax that the preprocessor
     7|/// uses to correctly mask comments and strings.
     8|#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
     9|pub enum Language {
    10|    Rust,
    11|    Python,
    12|    JavaScript,
    13|    TypeScript,
    14|    Go,
    15|    Ruby,
    16|    C,
    17|    Cpp,
    18|    CSharp,
    19|    Java,
    20|    Kotlin,
    21|    Shell,
    22|    Swift,
    23|    Scala,
    24|    Sql,
    25|    Xml,
    26|    Php,
    27|    Yaml,
    28|    Toml,
    29|    Json,
    30|    #[default]
    31|    Unknown,
    32|}
    33|
    34|impl FromStr for Language {
    35|    type Err = std::convert::Infallible;
    36|
    37|    /// Parse a language identifier string into a Language enum.
    38|    ///
    39|    /// The matching is case-insensitive. Unknown languages return `Language::Unknown`.
    40|    fn from_str(s: &str) -> Result<Self, Self::Err> {
    41|        Ok(match s.to_ascii_lowercase().as_str() {
    42|            "rust" => Language::Rust,
    43|            "python" => Language::Python,
    44|            "javascript" => Language::JavaScript,
    45|            "typescript" => Language::TypeScript,
    46|            "go" => Language::Go,
    47|            "ruby" => Language::Ruby,
    48|            "c" => Language::C,
    49|            "cpp" => Language::Cpp,
    50|            "csharp" => Language::CSharp,
    51|            "java" => Language::Java,
    52|            "kotlin" => Language::Kotlin,
    53|            "shell" | "bash" | "sh" | "zsh" | "ksh" | "fish" => Language::Shell,
    54|            "swift" => Language::Swift,
    55|            "scala" => Language::Scala,
    56|            "sql" => Language::Sql,
    57|            "xml" | "html" | "xhtml" | "svg" | "xsl" | "xslt" => Language::Xml,
    58|            "php" => Language::Php,
    59|            "yaml" | "yml" => Language::Yaml,
    60|            "toml" => Language::Toml,
    61|            "json" | "jsonc" | "json5" => Language::Json,
    62|            _ => Language::Unknown,
    63|        })
    64|    }
    65|}
    66|
    67|impl Language {
    68|    /// Returns the comment syntax for this language.
    69|    pub fn comment_syntax(self) -> CommentSyntax {
    70|        match self {
    71|            Language::Python | Language::Ruby | Language::Shell => CommentSyntax::Hash,
    72|            // Rust, Swift, and Scala support nested block comments
    73|            Language::Rust | Language::Swift | Language::Scala => CommentSyntax::CStyleNested,
    74|            // SQL uses -- for line comments
    75|            Language::Sql => CommentSyntax::Sql,
    76|            // XML/HTML uses <!-- --> block comments only
    77|            Language::Xml => CommentSyntax::Xml,
    78|            // PHP uses //, #, and /* */
    79|            Language::Php => CommentSyntax::Php,
    80|            // YAML/TOML use # comments
    81|            Language::Yaml | Language::Toml => CommentSyntax::Hash,
    82|            // JSON supports comments in jsonc/json5 dialects (handled by wildcard)
    83|            _ => CommentSyntax::CStyle,
    84|        }
    85|    }
    86|
    87|    /// Returns the string syntax for this language.
    88|    pub fn string_syntax(self) -> StringSyntax {
    89|        match self {
    90|            Language::Rust => StringSyntax::Rust,
    91|            Language::Python => StringSyntax::Python,
    92|            // Ruby uses single quotes for strings (not char literals like C)
    93|            Language::JavaScript | Language::TypeScript | Language::Ruby => {
    94|                StringSyntax::JavaScript
    95|            }
    96|            Language::Go => StringSyntax::Go,
    97|            Language::Shell => StringSyntax::Shell,
    98|            // Swift and Scala support triple-quoted strings like Python
    99|            Language::Swift | Language::Scala => StringSyntax::SwiftScala,
   100|            // SQL uses single quotes for strings
   101|            Language::Sql => StringSyntax::Sql,
   102|            // XML uses both single and double quotes for attribute values
   103|            Language::Xml => StringSyntax::Xml,
   104|            // PHP uses both single and double quotes
   105|            Language::Php => StringSyntax::Php,
   106|            // YAML/TOML/JSON strings are C-style-like in this best-effort model
   107|            Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
   108|            // All other languages (C, C++, Java, etc.) use C-style strings
   109|            _ => StringSyntax::CStyle,
   110|        }
   111|    }
   112|}
   113|
   114|/// Comment syntax variants for different programming languages.
   115|#[derive(Debug, Clone, Copy, PartialEq, Eq)]
   116|pub enum CommentSyntax {
   117|    /// C-style comments: `//` line comments and `/* */` block comments
   118|    CStyle,
   119|    /// C-style comments with nesting support (Rust, Swift, Scala): `//` and `/* */` with nesting
   120|    CStyleNested,
   121|    /// Hash comments only: `#` line comments (Python, Ruby)
   122|    Hash,
   123|    /// SQL comments: `--` line comments and `/* */` block comments
   124|    Sql,
   125|    /// XML/HTML comments: `<!-- -->` block comments only
   126|    Xml,
   127|    /// PHP comments: `//`, `#` line comments and `/* */` block comments
   128|    Php,
   129|}
   130|
   131|/// String syntax variants for different programming languages.
   132|#[derive(Debug, Clone, Copy, PartialEq, Eq)]
   133|pub enum StringSyntax {
   134|    /// C-style strings: `"..."` with backslash escapes
   135|    CStyle,
   136|    /// Rust strings: `"..."`, `r#"..."#`, `b"..."`
   137|    Rust,
   138|    /// Python strings: `"..."`, `'...'`, `"""..."""`, `'''...'''`
   139|    Python,
   140|    /// JavaScript strings: `"..."`, `'...'`, `` `...` `` (template literals)
   141|    JavaScript,
   142|    /// Go strings: `"..."`, `` `...` `` (raw strings)
   143|    Go,
   144|    /// Shell strings: `'...'` (literal, no escapes), `"..."` (with escapes), `$'...'` (ANSI-C)
   145|    Shell,
   146|    /// Swift/Scala strings: `"..."`, `"""..."""` multi-line strings
   147|    SwiftScala,
   148|    /// SQL strings: `'...'` single quotes only
   149|    Sql,
   150|    /// XML/HTML strings: `"..."` and `'...'` for attribute values
   151|    Xml,
   152|    /// PHP strings: `'...'` (literal) and `"..."` (with escapes)
   153|    Php,
   154|}
   155|
   156|/// Preprocessing options.
   157|///
   158|/// `mask_*` controls whether the corresponding token class is replaced with spaces.
   159|///
   160|/// Regardless of masking, the preprocessor may still *track* strings when masking
   161|/// comments, so that comment markers inside strings do not start a comment.
   162|#[derive(Debug, Clone, Copy, PartialEq, Eq)]
   163|pub struct PreprocessOptions {
   164|    pub mask_comments: bool,
   165|    pub mask_strings: bool,
   166|}
   167|
   168|impl PreprocessOptions {
   169|    pub fn none() -> Self {
   170|        Self {
   171|            mask_comments: false,
   172|            mask_strings: false,
   173|        }
   174|    }
   175|
   176|    pub fn comments_only() -> Self {
   177|        Self {
   178|            mask_comments: true,
   179|            mask_strings: false,
   180|        }
   181|    }
   182|
   183|    pub fn strings_only() -> Self {
   184|        Self {
   185|            mask_comments: false,
   186|            mask_strings: true,
   187|        }
   188|    }
   189|
   190|    pub fn comments_and_strings() -> Self {
   191|        Self {
   192|            mask_comments: true,
   193|            mask_strings: true,
   194|        }
   195|    }
   196|
   197|    fn track_strings(self) -> bool {
   198|        self.mask_strings || self.mask_comments
   199|    }
   200|}
   201|
   202|#[derive(Clone, Copy, PartialEq, Eq)]
   203|enum Mode {
   204|    Normal,
   205|    LineComment,
   206|    BlockComment {
   207|        depth: u32,
   208|    },
   209|    NormalString {
   210|        escaped: bool,
   211|        quote: u8,
   212|    },
   213|    RawString {
   214|        hashes: usize,
   215|    },
   216|    Char {
   217|        escaped: bool,
   218|    },
   219|    TemplateLiteral {
   220|        escaped: bool,
   221|    },
   222|    TripleQuotedString {
   223|        escaped: bool,
   224|        quote: u8,
   225|    },
   226|    /// Shell literal string: '...' - no escapes at all
   227|    ShellLiteralString,
   228|    /// Shell ANSI-C string: $'...' - with escape sequences
   229|    ShellAnsiCString {
   230|        escaped: bool,
   231|    },
   232|    /// XML/HTML block comment: <!-- ... -->
   233|    XmlComment,
   234|}
   235|
   236|impl fmt::Debug for Mode {
   237|    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
   238|        match self {
   239|            Mode::Normal => write!(f, "Normal"),
   240|            Mode::LineComment => write!(f, "LineComment"),
   241|            Mode::BlockComment { depth } => write!(f, "BlockComment(depth={depth})"),
   242|            Mode::NormalString { escaped, quote } => {
   243|                write!(f, "NormalString(escaped={escaped}, quote={quote})")
   244|            }
   245|            Mode::RawString { hashes } => write!(f, "RawString(hashes={hashes})"),
   246|            Mode::Char { escaped } => write!(f, "Char(escaped={escaped})"),
   247|            Mode::TemplateLiteral { escaped } => write!(f, "TemplateLiteral(escaped={escaped})"),
   248|            Mode::TripleQuotedString { escaped, quote } => {
   249|                write!(f, "TripleQuotedString(escaped={escaped}, quote={quote})")
   250|            }
   251|            Mode::ShellLiteralString => write!(f, "ShellLiteralString"),
   252|            Mode::ShellAnsiCString { escaped } => {
   253|                write!(f, "ShellAnsiCString(escaped={escaped})")
   254|            }
   255|            Mode::XmlComment => write!(f, "XmlComment"),
   256|        }
   257|    }
   258|}
   259|
   260|/// A stateful preprocessor, intended to be run on sequential lines of the *same file*.
   261|///
   262|/// The state tracks multi-line comments/strings best-effort. If the diff begins inside an
   263|/// existing comment/string, the preprocessor cannot infer that.
   264|#[derive(Debug, Clone)]
   265|pub struct Preprocessor {
   266|    opts: PreprocessOptions,
   267|    mode: Mode,
   268|    lang: Language,
   269|}
   270|
   271|impl Preprocessor {
   272|    pub fn new(opts: PreprocessOptions) -> Self {
   273|        Self {
   274|            opts,
   275|            mode: Mode::Normal,
   276|            lang: Language::Unknown,
   277|        }
   278|    }
   279|
   280|    /// Create a new preprocessor with language-specific syntax support.
   281|    pub fn with_language(opts: PreprocessOptions, lang: Language) -> Self {
   282|        Self {
   283|            opts,
   284|            mode: Mode::Normal,
   285|            lang,
   286|        }
   287|    }
   288|
   289|    /// Set the language for this preprocessor and reset state.
   290|    pub fn set_language(&mut self, lang: Language) {
   291|        self.lang = lang;
   292|        self.reset();
   293|    }
   294|
   295|    pub fn reset(&mut self) {
   296|        self.mode = Mode::Normal;
   297|    }
   298|
   299|    /// Returns a sanitized line where masked segments are replaced with spaces.
   300|    ///
   301|    /// The output is the same length in bytes as the input.
   302|    #[cfg_attr(mutants, mutants::skip)]
   303|    #[allow(clippy::collapsible_if)]
   304|    pub fn sanitize_line(&mut self, line: &str) -> String {
   305|        let mut out: Vec<u8> = line.as_bytes().to_vec();
   306|        let bytes = line.as_bytes();
   307|        let len = bytes.len();
   308|
   309|        let comment_syntax = self.lang.comment_syntax();
   310|        let string_syntax = self.lang.string_syntax();
   311|
   312|        let mut i = 0;
   313|
   314|        while i < len {
   315|            match self.mode {
   316|                Mode::Normal => {
   317|                    // String detection (language-specific)
   318|                    if self.opts.track_strings() {
   319|                        // Rust raw string start detection: r#"..."# or br#"..."#
   320|                        if string_syntax == StringSyntax::Rust {
   321|                            if let Some((_, end_quote_i, hashes)) =
   322|                                detect_raw_string_start(bytes, i)
   323|                            {
   324|                                if self.opts.mask_strings {
   325|                                    mask_range(&mut out, i, end_quote_i + 1);
   326|                                }
   327|                                self.mode = Mode::RawString { hashes };
   328|                                i = end_quote_i + 1;
   329|                                continue;
   330|                            }
   331|
   332|                            // Byte string: b"..."
   333|                            if bytes[i] == b'b' && i + 1 < len && bytes[i + 1] == b'"' {
   334|                                if self.opts.mask_strings {
   335|                                    mask_range(&mut out, i, i + 2);
   336|                                }
   337|                                self.mode = Mode::NormalString {
   338|                                    escaped: false,
   339|                                    quote: b'"',
   340|                                };
   341|                                i += 2;
   342|                                continue;
   343|                            }
   344|                        }
   345|
   346|                        // Triple-quoted strings: """...""" or '''...''' (Python)
   347|                        // Swift/Scala only use """...""" (not single-quote triple)
   348|                        if string_syntax == StringSyntax::Python
   349|                            || string_syntax == StringSyntax::SwiftScala
   350|                        {
   351|                            if let Some((quote, end_i)) = detect_triple_quote_start(bytes, i) {
   352|                                // Swift/Scala only support double-quote triple strings
   353|                                if string_syntax == StringSyntax::SwiftScala && quote != b'"' {
   354|                                    // Fall through to normal string handling
   355|                                } else {
   356|                                    if self.opts.mask_strings {
   357|                                        mask_range(&mut out, i, end_i);
   358|                                    }
   359|                                    self.mode = Mode::TripleQuotedString {
   360|                                        escaped: false,
   361|                                        quote,
   362|                                    };
   363|                                    i = end_i;
   364|                                    continue;
   365|                                }
   366|                            }
   367|                        }
   368|
   369|                        // JavaScript/TypeScript template literals: `...`
   370|                        if string_syntax == StringSyntax::JavaScript && bytes[i] == b'`' {
   371|                            if self.opts.mask_strings {
   372|                                out[i] = b' ';
   373|                            }
   374|                            self.mode = Mode::TemplateLiteral { escaped: false };
   375|                            i += 1;
   376|                            continue;
   377|                        }
   378|
   379|                        // Go raw strings: `...`
   380|                        if string_syntax == StringSyntax::Go && bytes[i] == b'`' {
   381|                            if self.opts.mask_strings {
   382|                                out[i] = b' ';
   383|                            }
   384|                            // Go raw strings don't support escapes, use RawString with 0 hashes
   385|                            self.mode = Mode::RawString { hashes: 0 };
   386|                            i += 1;
   387|                            continue;
   388|                        }
   389|
   390|                        // Shell ANSI-C quoting: $'...'
   391|                        if string_syntax == StringSyntax::Shell
   392|                            && bytes[i] == b'$'
   393|                            && i + 1 < len
   394|                            && bytes[i + 1] == b'\''
   395|                        {
   396|                            if self.opts.mask_strings {
   397|                                mask_range(&mut out, i, i + 2);
   398|                            }
   399|                            self.mode = Mode::ShellAnsiCString { escaped: false };
   400|                            i += 2;
   401|                            continue;
   402|                        }
   403|
   404|                        // Shell single-quoted literal strings: '...' (no escapes!)
   405|                        if string_syntax == StringSyntax::Shell && bytes[i] == b'\'' {
   406|                            if self.opts.mask_strings {
   407|                                out[i] = b' ';
   408|                            }
   409|                            self.mode = Mode::ShellLiteralString;
   410|                            i += 1;
   411|                            continue;
   412|                        }
   413|
   414|                        // SQL strings: '...' (single quotes with '' escape)
   415|                        if string_syntax == StringSyntax::Sql && bytes[i] == b'\'' {
   416|                            if self.opts.mask_strings {
   417|                                out[i] = b' ';
   418|                            }
   419|                            self.mode = Mode::NormalString {
   420|                                escaped: false,
   421|                                quote: b'\'',
   422|                            };
   423|                            i += 1;
   424|                            continue;
   425|                        }
   426|
   427|                        // XML/HTML attribute strings: both "..." and '...'
   428|                        if string_syntax == StringSyntax::Xml
   429|                            && (bytes[i] == b'"' || bytes[i] == b'\'')
   430|                        {
   431|                            let quote = bytes[i];
   432|                            if self.opts.mask_strings {
   433|                                out[i] = b' ';
   434|                            }
   435|                            // XML strings don't have escape sequences
   436|                            self.mode = Mode::NormalString {
   437|                                escaped: false,
   438|                                quote,
   439|                            };
   440|                            i += 1;
   441|                            continue;
   442|                        }
   443|
   444|                        // PHP strings: '...' (literal, minimal escapes) and "..." (with escapes)
   445|                        if string_syntax == StringSyntax::Php
   446|                            && (bytes[i] == b'"' || bytes[i] == b'\'')
   447|                        {
   448|                            let quote = bytes[i];
   449|                            if self.opts.mask_strings {
   450|                                out[i] = b' ';
   451|                            }
   452|                            self.mode = Mode::NormalString {
   453|                                escaped: false,
   454|                                quote,
   455|                            };
   456|                            i += 1;
   457|                            continue;
   458|                        }
   459|
   460|                        // Normal double-quoted string: "..."
   461|                        // Note: SQL only uses single quotes for strings, so skip this for SQL
   462|                        if bytes[i] == b'"' && string_syntax != StringSyntax::Sql {
   463|                            if self.opts.mask_strings {
   464|                                out[i] = b' ';
   465|                            }
   466|                            self.mode = Mode::NormalString {
   467|                                escaped: false,
   468|                                quote: b'"',
   469|                            };
   470|                            i += 1;
   471|                            continue;
   472|                        }
   473|
   474|                        // Single-quoted strings for Python, JavaScript, Ruby
   475|                        if (string_syntax == StringSyntax::Python
   476|                            || string_syntax == StringSyntax::JavaScript
   477|                            || string_syntax == StringSyntax::CStyle)
   478|                            && bytes[i] == b'\''
   479|                        {
   480|                            // For C-style languages, single quote is a char literal
   481|                            if string_syntax == StringSyntax::CStyle {
   482|                                if self.opts.mask_strings {
   483|                                    out[i] = b' ';
   484|                                }
   485|                                self.mode = Mode::Char { escaped: false };
   486|                                i += 1;
   487|                                continue;
   488|                            }
   489|                            // For Python/JavaScript, single quote is a string
   490|                            if self.opts.mask_strings {
   491|                                out[i] = b' ';
   492|                            }
   493|                            self.mode = Mode::NormalString {
   494|                                escaped: false,
   495|                                quote: b'\'',
   496|                            };
   497|                            i += 1;
   498|                            continue;
   499|                        }
   500|
   501|