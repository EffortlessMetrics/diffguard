use std::fmt;
use std::str::FromStr;

/// Supported programming languages for preprocessing.
///
/// Each language has specific comment and string syntax that the preprocessor
/// uses to correctly mask comments and strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Ruby,
    C,
    Cpp,
    CSharp,
    Java,
    Kotlin,
    Shell,
    Swift,
    Scala,
    Sql,
    Xml,
    Php,
    #[default]
    Unknown,
}

impl FromStr for Language {
    type Err = std::convert::Infallible;

    /// Parse a language identifier string into a Language enum.
    ///
    /// The matching is case-insensitive. Unknown languages return `Language::Unknown`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "rust" => Language::Rust,
            "python" => Language::Python,
            "javascript" => Language::JavaScript,
            "typescript" => Language::TypeScript,
            "go" => Language::Go,
            "ruby" => Language::Ruby,
            "c" => Language::C,
            "cpp" => Language::Cpp,
            "csharp" => Language::CSharp,
            "java" => Language::Java,
            "kotlin" => Language::Kotlin,
            "shell" | "bash" | "sh" | "zsh" | "ksh" | "fish" => Language::Shell,
            "swift" => Language::Swift,
            "scala" => Language::Scala,
            "sql" => Language::Sql,
            "xml" | "html" | "xhtml" | "svg" | "xsl" | "xslt" => Language::Xml,
            "php" => Language::Php,
            _ => Language::Unknown,
        })
    }
}

impl Language {
    /// Returns the comment syntax for this language.
    pub fn comment_syntax(self) -> CommentSyntax {
        match self {
            Language::Python | Language::Ruby | Language::Shell => CommentSyntax::Hash,
            // Rust, Swift, and Scala support nested block comments
            Language::Rust | Language::Swift | Language::Scala => CommentSyntax::CStyleNested,
            // SQL uses -- for line comments
            Language::Sql => CommentSyntax::Sql,
            // XML/HTML uses <!-- --> block comments only
            Language::Xml => CommentSyntax::Xml,
            // PHP uses //, #, and /* */
            Language::Php => CommentSyntax::Php,
            _ => CommentSyntax::CStyle,
        }
    }

    /// Returns the string syntax for this language.
    pub fn string_syntax(self) -> StringSyntax {
        match self {
            Language::Rust => StringSyntax::Rust,
            Language::Python => StringSyntax::Python,
            // Ruby uses single quotes for strings (not char literals like C)
            Language::JavaScript | Language::TypeScript | Language::Ruby => {
                StringSyntax::JavaScript
            }
            Language::Go => StringSyntax::Go,
            Language::Shell => StringSyntax::Shell,
            // Swift and Scala support triple-quoted strings like Python
            Language::Swift | Language::Scala => StringSyntax::SwiftScala,
            // SQL uses single quotes for strings
            Language::Sql => StringSyntax::Sql,
            // XML uses both single and double quotes for attribute values
            Language::Xml => StringSyntax::Xml,
            // PHP uses both single and double quotes
            Language::Php => StringSyntax::Php,
            _ => StringSyntax::CStyle,
        }
    }
}

/// Comment syntax variants for different programming languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentSyntax {
    /// C-style comments: `//` line comments and `/* */` block comments
    CStyle,
    /// C-style comments with nesting support (Rust, Swift, Scala): `//` and `/* */` with nesting
    CStyleNested,
    /// Hash comments only: `#` line comments (Python, Ruby)
    Hash,
    /// SQL comments: `--` line comments and `/* */` block comments
    Sql,
    /// XML/HTML comments: `<!-- -->` block comments only
    Xml,
    /// PHP comments: `//`, `#` line comments and `/* */` block comments
    Php,
}

/// String syntax variants for different programming languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringSyntax {
    /// C-style strings: `"..."` with backslash escapes
    CStyle,
    /// Rust strings: `"..."`, `r#"..."#`, `b"..."`
    Rust,
    /// Python strings: `"..."`, `'...'`, `"""..."""`, `'''...'''`
    Python,
    /// JavaScript strings: `"..."`, `'...'`, `` `...` `` (template literals)
    JavaScript,
    /// Go strings: `"..."`, `` `...` `` (raw strings)
    Go,
    /// Shell strings: `'...'` (literal, no escapes), `"..."` (with escapes), `$'...'` (ANSI-C)
    Shell,
    /// Swift/Scala strings: `"..."`, `"""..."""` multi-line strings
    SwiftScala,
    /// SQL strings: `'...'` single quotes only
    Sql,
    /// XML/HTML strings: `"..."` and `'...'` for attribute values
    Xml,
    /// PHP strings: `'...'` (literal) and `"..."` (with escapes)
    Php,
}

/// Preprocessing options.
///
/// `mask_*` controls whether the corresponding token class is replaced with spaces.
///
/// Regardless of masking, the preprocessor may still *track* strings when masking
/// comments, so that comment markers inside strings do not start a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreprocessOptions {
    pub mask_comments: bool,
    pub mask_strings: bool,
}

impl PreprocessOptions {
    pub fn none() -> Self {
        Self {
            mask_comments: false,
            mask_strings: false,
        }
    }

    pub fn comments_only() -> Self {
        Self {
            mask_comments: true,
            mask_strings: false,
        }
    }

    pub fn strings_only() -> Self {
        Self {
            mask_comments: false,
            mask_strings: true,
        }
    }

    pub fn comments_and_strings() -> Self {
        Self {
            mask_comments: true,
            mask_strings: true,
        }
    }

    fn track_strings(self) -> bool {
        self.mask_strings || self.mask_comments
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    LineComment,
    BlockComment {
        depth: u32,
    },
    NormalString {
        escaped: bool,
        quote: u8,
    },
    RawString {
        hashes: usize,
    },
    Char {
        escaped: bool,
    },
    TemplateLiteral {
        escaped: bool,
    },
    TripleQuotedString {
        escaped: bool,
        quote: u8,
    },
    /// Shell literal string: '...' - no escapes at all
    ShellLiteralString,
    /// Shell ANSI-C string: $'...' - with escape sequences
    ShellAnsiCString {
        escaped: bool,
    },
    /// XML/HTML block comment: <!-- ... -->
    XmlComment,
}

impl fmt::Debug for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Normal => write!(f, "Normal"),
            Mode::LineComment => write!(f, "LineComment"),
            Mode::BlockComment { depth } => write!(f, "BlockComment(depth={depth})"),
            Mode::NormalString { escaped, quote } => {
                write!(f, "NormalString(escaped={escaped}, quote={quote})")
            }
            Mode::RawString { hashes } => write!(f, "RawString(hashes={hashes})"),
            Mode::Char { escaped } => write!(f, "Char(escaped={escaped})"),
            Mode::TemplateLiteral { escaped } => write!(f, "TemplateLiteral(escaped={escaped})"),
            Mode::TripleQuotedString { escaped, quote } => {
                write!(f, "TripleQuotedString(escaped={escaped}, quote={quote})")
            }
            Mode::ShellLiteralString => write!(f, "ShellLiteralString"),
            Mode::ShellAnsiCString { escaped } => {
                write!(f, "ShellAnsiCString(escaped={escaped})")
            }
            Mode::XmlComment => write!(f, "XmlComment"),
        }
    }
}

/// A stateful preprocessor, intended to be run on sequential lines of the *same file*.
///
/// The state tracks multi-line comments/strings best-effort. If the diff begins inside an
/// existing comment/string, the preprocessor cannot infer that.
#[derive(Debug, Clone)]
pub struct Preprocessor {
    opts: PreprocessOptions,
    mode: Mode,
    lang: Language,
}

impl Preprocessor {
    pub fn new(opts: PreprocessOptions) -> Self {
        Self {
            opts,
            mode: Mode::Normal,
            lang: Language::Unknown,
        }
    }

    /// Create a new preprocessor with language-specific syntax support.
    pub fn with_language(opts: PreprocessOptions, lang: Language) -> Self {
        Self {
            opts,
            mode: Mode::Normal,
            lang,
        }
    }

    /// Set the language for this preprocessor and reset state.
    pub fn set_language(&mut self, lang: Language) {
        self.lang = lang;
        self.reset();
    }

    pub fn reset(&mut self) {
        self.mode = Mode::Normal;
    }

    /// Returns a sanitized line where masked segments are replaced with spaces.
    ///
    /// The output is the same length in bytes as the input.
    #[cfg_attr(mutants, mutants::skip)]
    pub fn sanitize_line(&mut self, line: &str) -> String {
        let mut out: Vec<u8> = line.as_bytes().to_vec();
        let bytes = line.as_bytes();
        let len = bytes.len();

        let comment_syntax = self.lang.comment_syntax();
        let string_syntax = self.lang.string_syntax();

        let mut i = 0;

        while i < len {
            match self.mode {
                Mode::Normal => {
                    // String detection (language-specific)
                    if self.opts.track_strings() {
                        // Rust raw string start detection: r#"..."# or br#"..."#
                        if string_syntax == StringSyntax::Rust {
                            if let Some((start_i, end_quote_i, hashes)) =
                                detect_raw_string_start(bytes, i)
                            {
                                if start_i == i {
                                    if self.opts.mask_strings {
                                        mask_range(&mut out, start_i, end_quote_i + 1);
                                    }
                                    self.mode = Mode::RawString { hashes };
                                    i = end_quote_i + 1;
                                    continue;
                                }
                            }

                            // Byte string: b"..."
                            if bytes[i] == b'b' && i + 1 < len && bytes[i + 1] == b'"' {
                                if self.opts.mask_strings {
                                    mask_range(&mut out, i, i + 2);
                                }
                                self.mode = Mode::NormalString {
                                    escaped: false,
                                    quote: b'"',
                                };
                                i += 2;
                                continue;
                            }
                        }

                        // Triple-quoted strings: """...""" or '''...''' (Python)
                        // Swift/Scala only use """...""" (not single-quote triple)
                        if string_syntax == StringSyntax::Python
                            || string_syntax == StringSyntax::SwiftScala
                        {
                            if let Some((quote, end_i)) = detect_triple_quote_start(bytes, i) {
                                // Swift/Scala only support double-quote triple strings
                                if string_syntax == StringSyntax::SwiftScala && quote != b'"' {
                                    // Fall through to normal string handling
                                } else {
                                    if self.opts.mask_strings {
                                        mask_range(&mut out, i, end_i);
                                    }
                                    self.mode = Mode::TripleQuotedString {
                                        escaped: false,
                                        quote,
                                    };
                                    i = end_i;
                                    continue;
                                }
                            }
                        }

                        // JavaScript/TypeScript template literals: `...`
                        if string_syntax == StringSyntax::JavaScript && bytes[i] == b'`' {
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            self.mode = Mode::TemplateLiteral { escaped: false };
                            i += 1;
                            continue;
                        }

                        // Go raw strings: `...`
                        if string_syntax == StringSyntax::Go && bytes[i] == b'`' {
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            // Go raw strings don't support escapes, use RawString with 0 hashes
                            self.mode = Mode::RawString { hashes: 0 };
                            i += 1;
                            continue;
                        }

                        // Shell ANSI-C quoting: $'...'
                        if string_syntax == StringSyntax::Shell
                            && bytes[i] == b'$'
                            && i + 1 < len
                            && bytes[i + 1] == b'\''
                        {
                            if self.opts.mask_strings {
                                mask_range(&mut out, i, i + 2);
                            }
                            self.mode = Mode::ShellAnsiCString { escaped: false };
                            i += 2;
                            continue;
                        }

                        // Shell single-quoted literal strings: '...' (no escapes!)
                        if string_syntax == StringSyntax::Shell && bytes[i] == b'\'' {
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            self.mode = Mode::ShellLiteralString;
                            i += 1;
                            continue;
                        }

                        // SQL strings: '...' (single quotes with '' escape)
                        if string_syntax == StringSyntax::Sql && bytes[i] == b'\'' {
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            self.mode = Mode::NormalString {
                                escaped: false,
                                quote: b'\'',
                            };
                            i += 1;
                            continue;
                        }

                        // XML/HTML attribute strings: both "..." and '...'
                        if string_syntax == StringSyntax::Xml
                            && (bytes[i] == b'"' || bytes[i] == b'\'')
                        {
                            let quote = bytes[i];
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            // XML strings don't have escape sequences
                            self.mode = Mode::NormalString {
                                escaped: false,
                                quote,
                            };
                            i += 1;
                            continue;
                        }

                        // PHP strings: '...' (literal, minimal escapes) and "..." (with escapes)
                        if string_syntax == StringSyntax::Php
                            && (bytes[i] == b'"' || bytes[i] == b'\'')
                        {
                            let quote = bytes[i];
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            self.mode = Mode::NormalString {
                                escaped: false,
                                quote,
                            };
                            i += 1;
                            continue;
                        }

                        // Swift/Scala double-quoted strings (not triple-quoted)
                        if string_syntax == StringSyntax::SwiftScala && bytes[i] == b'"' {
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            self.mode = Mode::NormalString {
                                escaped: false,
                                quote: b'"',
                            };
                            i += 1;
                            continue;
                        }

                        // Normal double-quoted string: "..."
                        // Note: SQL only uses single quotes for strings, so skip this for SQL
                        if bytes[i] == b'"' && string_syntax != StringSyntax::Sql {
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            self.mode = Mode::NormalString {
                                escaped: false,
                                quote: b'"',
                            };
                            i += 1;
                            continue;
                        }

                        // Single-quoted strings for Python, JavaScript, Ruby
                        if (string_syntax == StringSyntax::Python
                            || string_syntax == StringSyntax::JavaScript
                            || string_syntax == StringSyntax::CStyle)
                            && bytes[i] == b'\''
                        {
                            // For C-style languages, single quote is a char literal
                            if string_syntax == StringSyntax::CStyle {
                                if self.opts.mask_strings {
                                    out[i] = b' ';
                                }
                                self.mode = Mode::Char { escaped: false };
                                i += 1;
                                continue;
                            }
                            // For Python/JavaScript, single quote is a string
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            self.mode = Mode::NormalString {
                                escaped: false,
                                quote: b'\'',
                            };
                            i += 1;
                            continue;
                        }

                        // Rust char literal: '...'
                        if string_syntax == StringSyntax::Rust && bytes[i] == b'\'' {
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            self.mode = Mode::Char { escaped: false };
                            i += 1;
                            continue;
                        }
                    }

                    // Comment detection (language-specific)
                    if self.opts.mask_comments {
                        // Hash comments for Python/Ruby/Shell
                        if comment_syntax == CommentSyntax::Hash && bytes[i] == b'#' {
                            mask_range(&mut out, i, len);
                            self.mode = Mode::LineComment;
                            break;
                        }

                        // PHP comments: // and # for line comments, /* */ for block
                        if comment_syntax == CommentSyntax::Php {
                            if bytes[i] == b'#' {
                                mask_range(&mut out, i, len);
                                self.mode = Mode::LineComment;
                                break;
                            }
                            if bytes[i] == b'/' && i + 1 < len {
                                let n = bytes[i + 1];
                                if n == b'/' {
                                    mask_range(&mut out, i, len);
                                    self.mode = Mode::LineComment;
                                    break;
                                }
                                if n == b'*' {
                                    mask_range(&mut out, i, i + 2);
                                    self.mode = Mode::BlockComment { depth: 1 };
                                    i += 2;
                                    continue;
                                }
                            }
                        }

                        // SQL comments: -- for line comments, /* */ for block
                        if comment_syntax == CommentSyntax::Sql {
                            // -- line comment
                            if bytes[i] == b'-' && i + 1 < len && bytes[i + 1] == b'-' {
                                mask_range(&mut out, i, len);
                                self.mode = Mode::LineComment;
                                break;
                            }
                            // /* */ block comment
                            if bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
                                mask_range(&mut out, i, i + 2);
                                self.mode = Mode::BlockComment { depth: 1 };
                                i += 2;
                                continue;
                            }
                        }

                        // XML/HTML comments: <!-- -->
                        if comment_syntax == CommentSyntax::Xml
                            && bytes[i] == b'<'
                            && i + 3 < len
                            && bytes[i + 1] == b'!'
                            && bytes[i + 2] == b'-'
                            && bytes[i + 3] == b'-'
                        {
                            mask_range(&mut out, i, i + 4);
                            self.mode = Mode::XmlComment;
                            i += 4;
                            continue;
                        }

                        // C-style comments: // and /* */
                        if (comment_syntax == CommentSyntax::CStyle
                            || comment_syntax == CommentSyntax::CStyleNested)
                            && bytes[i] == b'/'
                            && i + 1 < len
                        {
                            let n = bytes[i + 1];
                            if n == b'/' {
                                // line comment until EOL
                                mask_range(&mut out, i, len);
                                self.mode = Mode::LineComment;
                                break;
                            }
                            if n == b'*' {
                                // block comment
                                mask_range(&mut out, i, i + 2);
                                self.mode = Mode::BlockComment { depth: 1 };
                                i += 2;
                                continue;
                            }
                        }
                    }

                    i += 1;
                }

                Mode::LineComment => {
                    // End-of-line resets line comments.
                    self.mode = Mode::Normal;
                    break;
                }

                Mode::BlockComment { depth } => {
                    // Everything is masked in a block comment.
                    if self.opts.mask_comments {
                        out[i] = b' ';
                    }

                    // Nested block comments are possible in Rust.
                    let supports_nesting = comment_syntax == CommentSyntax::CStyleNested;
                    if supports_nesting && bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
                        if self.opts.mask_comments {
                            out[i + 1] = b' ';
                        }
                        self.mode = Mode::BlockComment { depth: depth + 1 };
                        i += 2;
                        continue;
                    }

                    if bytes[i] == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                        if self.opts.mask_comments {
                            out[i + 1] = b' ';
                        }
                        if depth == 1 {
                            self.mode = Mode::Normal;
                        } else {
                            self.mode = Mode::BlockComment { depth: depth - 1 };
                        }
                        i += 2;
                        continue;
                    }

                    i += 1;
                }

                Mode::NormalString { escaped, quote } => {
                    if self.opts.mask_strings {
                        out[i] = b' ';
                    }

                    if escaped {
                        self.mode = Mode::NormalString {
                            escaped: false,
                            quote,
                        };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'\\' {
                        self.mode = Mode::NormalString {
                            escaped: true,
                            quote,
                        };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == quote {
                        // End of string
                        self.mode = Mode::Normal;
                        i += 1;
                        continue;
                    }

                    i += 1;
                }

                Mode::Char { escaped } => {
                    if self.opts.mask_strings {
                        out[i] = b' ';
                    }

                    if escaped {
                        self.mode = Mode::Char { escaped: false };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'\\' {
                        self.mode = Mode::Char { escaped: true };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'\'' {
                        self.mode = Mode::Normal;
                        i += 1;
                        continue;
                    }

                    i += 1;
                }

                Mode::RawString { hashes } => {
                    if self.opts.mask_strings {
                        out[i] = b' ';
                    }

                    // For Go raw strings (hashes == 0), look for closing backtick
                    if hashes == 0 && string_syntax == StringSyntax::Go {
                        if bytes[i] == b'`' {
                            self.mode = Mode::Normal;
                            i += 1;
                            continue;
                        }
                        i += 1;
                        continue;
                    }

                    // For Rust raw strings, look for end delimiter: "###
                    if bytes[i] == b'"' {
                        let mut ok = true;
                        for j in 0..hashes {
                            if i + 1 + j >= len || bytes[i + 1 + j] != b'#' {
                                ok = false;
                                break;
                            }
                        }

                        if ok {
                            if self.opts.mask_strings {
                                mask_range(&mut out, i, (i + 1 + hashes).min(len));
                            }
                            self.mode = Mode::Normal;
                            i = (i + 1 + hashes).min(len);
                            continue;
                        }
                    }

                    i += 1;
                }

                Mode::TemplateLiteral { escaped } => {
                    if self.opts.mask_strings {
                        out[i] = b' ';
                    }

                    if escaped {
                        self.mode = Mode::TemplateLiteral { escaped: false };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'\\' {
                        self.mode = Mode::TemplateLiteral { escaped: true };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'`' {
                        // End of template literal
                        self.mode = Mode::Normal;
                        i += 1;
                        continue;
                    }

                    i += 1;
                }

                Mode::TripleQuotedString { escaped, quote } => {
                    if self.opts.mask_strings {
                        out[i] = b' ';
                    }

                    if escaped {
                        self.mode = Mode::TripleQuotedString {
                            escaped: false,
                            quote,
                        };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'\\' {
                        self.mode = Mode::TripleQuotedString {
                            escaped: true,
                            quote,
                        };
                        i += 1;
                        continue;
                    }

                    // Check for closing triple quote
                    if bytes[i] == quote
                        && i + 2 < len
                        && bytes[i + 1] == quote
                        && bytes[i + 2] == quote
                    {
                        if self.opts.mask_strings {
                            mask_range(&mut out, i, i + 3);
                        }
                        self.mode = Mode::Normal;
                        i += 3;
                        continue;
                    }

                    i += 1;
                }

                Mode::ShellLiteralString => {
                    // Shell single-quoted strings: NO escapes at all!
                    // The only way out is a closing single quote.
                    if self.opts.mask_strings {
                        out[i] = b' ';
                    }

                    if bytes[i] == b'\'' {
                        // End of literal string
                        self.mode = Mode::Normal;
                        i += 1;
                        continue;
                    }

                    i += 1;
                }

                Mode::ShellAnsiCString { escaped } => {
                    // Shell ANSI-C strings: $'...' with escape sequences
                    if self.opts.mask_strings {
                        out[i] = b' ';
                    }

                    if escaped {
                        self.mode = Mode::ShellAnsiCString { escaped: false };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'\\' {
                        self.mode = Mode::ShellAnsiCString { escaped: true };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'\'' {
                        // End of ANSI-C string
                        self.mode = Mode::Normal;
                        i += 1;
                        continue;
                    }

                    i += 1;
                }

                Mode::XmlComment => {
                    // XML/HTML comments: <!-- ... -->
                    // Everything inside is masked until we see -->
                    if self.opts.mask_comments {
                        out[i] = b' ';
                    }

                    // Check for closing -->
                    if bytes[i] == b'-'
                        && i + 2 < len
                        && bytes[i + 1] == b'-'
                        && bytes[i + 2] == b'>'
                    {
                        if self.opts.mask_comments {
                            out[i + 1] = b' ';
                            out[i + 2] = b' ';
                        }
                        self.mode = Mode::Normal;
                        i += 3;
                        continue;
                    }

                    i += 1;
                }
            }
        }

        // Line comments end at EOL.
        if matches!(self.mode, Mode::LineComment) {
            self.mode = Mode::Normal;
        }

        String::from_utf8(out).unwrap_or_else(|_| line.to_string())
    }
}

fn mask_range(out: &mut [u8], start: usize, end: usize) {
    let end = end.min(out.len());
    for b in &mut out[start..end] {
        *b = b' ';
    }
}

/// Detect a triple-quoted string start (Python): """...""" or '''...'''
///
/// Returns (quote_char, end_index) where end_index is the position after the opening triple quote.
fn detect_triple_quote_start(bytes: &[u8], i: usize) -> Option<(u8, usize)> {
    let len = bytes.len();
    if i + 2 >= len {
        return None;
    }

    let quote = bytes[i];
    if (quote == b'"' || quote == b'\'') && bytes[i + 1] == quote && bytes[i + 2] == quote {
        Some((quote, i + 3))
    } else {
        None
    }
}

/// Detect a raw string start (Rust): r#"..."# or br#"..."#.
///
/// Returns (start_index, quote_index, hash_count) where quote_index points to the opening `"`.
fn detect_raw_string_start(bytes: &[u8], i: usize) -> Option<(usize, usize, usize)> {
    let len = bytes.len();

    // Either r... or br...
    let (start, r_i) = if bytes.get(i) == Some(&b'r') {
        (i, i)
    } else if bytes.get(i) == Some(&b'b') && bytes.get(i + 1) == Some(&b'r') {
        (i, i + 1)
    } else {
        return None;
    };

    let j = r_i + 1;
    let hashes = bytes
        .get(j..len)
        .unwrap_or(&[])
        .iter()
        .take_while(|&&b| b == b'#')
        .count();
    let j = j + hashes;

    if j < len && bytes[j] == b'"' {
        Some((start, j, hashes))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Language enum tests ====================

    #[test]
    fn preprocess_options_track_strings_reflects_masks() {
        assert!(!PreprocessOptions::none().track_strings());
        assert!(PreprocessOptions::comments_only().track_strings());
        assert!(PreprocessOptions::strings_only().track_strings());
        assert!(PreprocessOptions::comments_and_strings().track_strings());
    }

    #[test]
    fn mode_debug_format_includes_variant() {
        assert_eq!(format!("{:?}", Mode::Normal), "Normal");
        assert_eq!(format!("{:?}", Mode::LineComment), "LineComment");
        assert_eq!(
            format!("{:?}", Mode::BlockComment { depth: 2 }),
            "BlockComment(depth=2)"
        );
        assert_eq!(
            format!(
                "{:?}",
                Mode::NormalString {
                    escaped: true,
                    quote: b'\"'
                }
            ),
            "NormalString(escaped=true, quote=34)"
        );
    }

    #[test]
    fn detect_triple_quote_start_detects_quotes() {
        assert_eq!(detect_triple_quote_start(b"\"\"\"rest", 0), Some((b'"', 3)));
        assert_eq!(detect_triple_quote_start(b"'''abc", 0), Some((b'\'', 3)));
        assert_eq!(detect_triple_quote_start(b"x\"\"y", 1), None);
        assert_eq!(detect_triple_quote_start(b"\"x\"", 0), None);
        assert_eq!(detect_triple_quote_start(b"''", 0), None);
        assert_eq!(detect_triple_quote_start(b"x'''y", 0), None);
    }

    #[test]
    fn detect_raw_string_start_detects_rust_raw_strings() {
        assert_eq!(detect_raw_string_start(b"r\"rest", 0), Some((0, 1, 0)));
        assert_eq!(detect_raw_string_start(b"br\"rest", 0), Some((0, 2, 0)));
        assert_eq!(detect_raw_string_start(b"r#\"rest", 0), Some((0, 2, 1)));
        assert_eq!(detect_raw_string_start(b"br##\"rest", 0), Some((0, 4, 2)));
        assert_eq!(detect_raw_string_start(b"b\"\"rest", 0), None);
        assert_eq!(detect_raw_string_start(b"b\"rest", 0), None);
        assert_eq!(detect_raw_string_start(b"x\"rest", 0), None);
        assert_eq!(detect_raw_string_start(b"r###", 0), None);
    }

    #[test]
    fn language_from_str_known_languages() {
        assert_eq!("rust".parse::<Language>().unwrap(), Language::Rust);
        assert_eq!("python".parse::<Language>().unwrap(), Language::Python);
        assert_eq!(
            "javascript".parse::<Language>().unwrap(),
            Language::JavaScript
        );
        assert_eq!(
            "typescript".parse::<Language>().unwrap(),
            Language::TypeScript
        );
        assert_eq!("go".parse::<Language>().unwrap(), Language::Go);
        assert_eq!("ruby".parse::<Language>().unwrap(), Language::Ruby);
        assert_eq!("c".parse::<Language>().unwrap(), Language::C);
        assert_eq!("cpp".parse::<Language>().unwrap(), Language::Cpp);
        assert_eq!("csharp".parse::<Language>().unwrap(), Language::CSharp);
        assert_eq!("java".parse::<Language>().unwrap(), Language::Java);
        assert_eq!("kotlin".parse::<Language>().unwrap(), Language::Kotlin);
    }

    #[test]
    fn language_from_str_case_insensitive() {
        assert_eq!("RUST".parse::<Language>().unwrap(), Language::Rust);
        assert_eq!("Python".parse::<Language>().unwrap(), Language::Python);
        assert_eq!(
            "JavaScript".parse::<Language>().unwrap(),
            Language::JavaScript
        );
        assert_eq!(
            "TypeScript".parse::<Language>().unwrap(),
            Language::TypeScript
        );
        assert_eq!("GO".parse::<Language>().unwrap(), Language::Go);
        assert_eq!("RUBY".parse::<Language>().unwrap(), Language::Ruby);
        assert_eq!("C".parse::<Language>().unwrap(), Language::C);
        assert_eq!("CPP".parse::<Language>().unwrap(), Language::Cpp);
        assert_eq!("CSharp".parse::<Language>().unwrap(), Language::CSharp);
        assert_eq!("JAVA".parse::<Language>().unwrap(), Language::Java);
        assert_eq!("KOTLIN".parse::<Language>().unwrap(), Language::Kotlin);
    }

    #[test]
    fn language_from_str_unknown() {
        assert_eq!("unknown".parse::<Language>().unwrap(), Language::Unknown);
        assert_eq!("".parse::<Language>().unwrap(), Language::Unknown);
        assert_eq!("fortran".parse::<Language>().unwrap(), Language::Unknown);
        assert_eq!("cobol".parse::<Language>().unwrap(), Language::Unknown);
    }

    #[test]
    fn language_default_is_unknown() {
        assert_eq!(Language::default(), Language::Unknown);
    }

    // ==================== CommentSyntax tests ====================

    #[test]
    fn comment_syntax_hash_languages() {
        assert_eq!(Language::Python.comment_syntax(), CommentSyntax::Hash);
        assert_eq!(Language::Ruby.comment_syntax(), CommentSyntax::Hash);
    }

    #[test]
    fn comment_syntax_cstyle_nested_languages() {
        assert_eq!(Language::Rust.comment_syntax(), CommentSyntax::CStyleNested);
    }

    #[test]
    fn comment_syntax_cstyle_languages() {
        assert_eq!(Language::JavaScript.comment_syntax(), CommentSyntax::CStyle);
        assert_eq!(Language::TypeScript.comment_syntax(), CommentSyntax::CStyle);
        assert_eq!(Language::Go.comment_syntax(), CommentSyntax::CStyle);
        assert_eq!(Language::C.comment_syntax(), CommentSyntax::CStyle);
        assert_eq!(Language::Cpp.comment_syntax(), CommentSyntax::CStyle);
        assert_eq!(Language::CSharp.comment_syntax(), CommentSyntax::CStyle);
        assert_eq!(Language::Java.comment_syntax(), CommentSyntax::CStyle);
        assert_eq!(Language::Kotlin.comment_syntax(), CommentSyntax::CStyle);
        assert_eq!(Language::Unknown.comment_syntax(), CommentSyntax::CStyle);
    }

    // ==================== StringSyntax tests ====================

    #[test]
    fn string_syntax_rust() {
        assert_eq!(Language::Rust.string_syntax(), StringSyntax::Rust);
    }

    #[test]
    fn string_syntax_python() {
        assert_eq!(Language::Python.string_syntax(), StringSyntax::Python);
    }

    #[test]
    fn string_syntax_javascript() {
        assert_eq!(
            Language::JavaScript.string_syntax(),
            StringSyntax::JavaScript
        );
        assert_eq!(
            Language::TypeScript.string_syntax(),
            StringSyntax::JavaScript
        );
    }

    #[test]
    fn string_syntax_go() {
        assert_eq!(Language::Go.string_syntax(), StringSyntax::Go);
    }

    #[test]
    fn string_syntax_cstyle_languages() {
        assert_eq!(Language::C.string_syntax(), StringSyntax::CStyle);
        assert_eq!(Language::Cpp.string_syntax(), StringSyntax::CStyle);
        assert_eq!(Language::CSharp.string_syntax(), StringSyntax::CStyle);
        assert_eq!(Language::Java.string_syntax(), StringSyntax::CStyle);
        assert_eq!(Language::Kotlin.string_syntax(), StringSyntax::CStyle);
        assert_eq!(Language::Unknown.string_syntax(), StringSyntax::CStyle);
    }

    #[test]
    fn string_syntax_ruby() {
        // Ruby uses JavaScript-style string syntax (single quotes are strings, not char literals)
        assert_eq!(Language::Ruby.string_syntax(), StringSyntax::JavaScript);
    }

    // ==================== Preprocessor constructor tests ====================

    #[test]
    fn preprocessor_with_language() {
        let p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Python);
        assert_eq!(p.lang, Language::Python);
    }

    #[test]
    fn preprocessor_set_language() {
        let mut p = Preprocessor::new(PreprocessOptions::comments_only());
        assert_eq!(p.lang, Language::Unknown);
        p.set_language(Language::Python);
        assert_eq!(p.lang, Language::Python);
    }

    // ==================== Preprocessor tests (default/unknown language) ====================

    #[test]
    fn masks_line_comments_when_enabled() {
        let mut p = Preprocessor::new(PreprocessOptions::comments_only());
        let s = p.sanitize_line("let x = 1; // .unwrap() should be ignored");
        assert!(s.contains("let x = 1;"));
        assert!(!s.contains("unwrap"));
    }

    #[test]
    fn does_not_mask_line_comments_when_disabled() {
        let mut p = Preprocessor::new(PreprocessOptions::none());
        let s = p.sanitize_line("// .unwrap() should be visible");
        assert!(s.contains("unwrap"));
    }

    #[test]
    fn masks_strings_when_enabled() {
        let mut p = Preprocessor::new(PreprocessOptions::strings_only());
        let s = p.sanitize_line("let s = \".unwrap()\";");
        assert!(!s.contains("unwrap"));
        assert!(s.contains("let s ="));
    }

    #[test]
    fn does_not_start_comment_inside_string() {
        let mut p = Preprocessor::new(PreprocessOptions::comments_only());
        let s = p.sanitize_line("let s = \"// not a comment\"; // real comment");
        assert!(s.contains("// not a comment"));
        assert!(!s.contains("real comment"));
    }

    #[test]
    fn masks_raw_string() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Rust);
        let s = p.sanitize_line("let s = r#\".unwrap()\"#;");
        assert!(!s.contains("unwrap"));
    }

    // ==================== Python-specific tests ====================

    #[test]
    fn python_masks_hash_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Python);
        let s = p.sanitize_line("x = 1  # this is a comment with print()");
        assert!(s.contains("x = 1"));
        assert!(!s.contains("print"));
        assert!(!s.contains("comment"));
    }

    #[test]
    fn python_does_not_mask_hash_in_string() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Python);
        let s = p.sanitize_line("x = \"# not a comment\"  # real comment");
        assert!(s.contains("# not a comment"));
        assert!(!s.contains("real comment"));
    }

    #[test]
    fn python_masks_single_quoted_strings() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);
        let s = p.sanitize_line("x = 'print() inside string'");
        assert!(s.contains("x ="));
        assert!(!s.contains("print"));
    }

    #[test]
    fn python_masks_double_quoted_strings() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);
        let s = p.sanitize_line("x = \"print() inside string\"");
        assert!(s.contains("x ="));
        assert!(!s.contains("print"));
    }

    #[test]
    fn python_masks_triple_double_quoted_strings() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);
        let s = p.sanitize_line("x = \"\"\"print() inside triple string\"\"\"");
        assert!(s.contains("x ="));
        assert!(!s.contains("print"));
    }

    #[test]
    fn python_masks_triple_single_quoted_strings() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);
        let s = p.sanitize_line("x = '''print() inside triple string'''");
        assert!(s.contains("x ="));
        assert!(!s.contains("print"));
    }

    #[test]
    fn python_triple_quoted_string_multiline() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);
        // First line starts the triple-quoted string
        let s1 = p.sanitize_line("x = \"\"\"start of");
        assert!(s1.contains("x ="));
        assert!(!s1.contains("start"));

        // Second line is inside the string
        let s2 = p.sanitize_line("print() in middle");
        assert!(!s2.contains("print"));

        // Third line ends the string
        let s3 = p.sanitize_line("end of string\"\"\" + y");
        assert!(!s3.contains("end of string"));
        assert!(s3.contains("+ y"));
    }

    // ==================== JavaScript/TypeScript-specific tests ====================

    #[test]
    fn javascript_masks_line_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);
        let s = p.sanitize_line("let x = 1; // console.log here");
        assert!(s.contains("let x = 1;"));
        assert!(!s.contains("console"));
    }

    #[test]
    fn javascript_masks_block_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);
        let s = p.sanitize_line("let x = /* console.log */ 1;");
        assert!(s.contains("let x ="));
        assert!(s.contains("1;"));
        assert!(!s.contains("console"));
    }

    #[test]
    fn javascript_masks_single_quoted_strings() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);
        let s = p.sanitize_line("let x = 'console.log inside';");
        assert!(s.contains("let x ="));
        assert!(!s.contains("console"));
    }

    #[test]
    fn javascript_masks_double_quoted_strings() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);
        let s = p.sanitize_line("let x = \"console.log inside\";");
        assert!(s.contains("let x ="));
        assert!(!s.contains("console"));
    }

    #[test]
    fn javascript_masks_template_literals() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);
        let s = p.sanitize_line("let x = `console.log inside template`;");
        assert!(s.contains("let x ="));
        assert!(!s.contains("console"));
    }

    #[test]
    fn javascript_template_literal_multiline() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);
        // First line starts the template literal
        let s1 = p.sanitize_line("let x = `start of");
        assert!(s1.contains("let x ="));
        assert!(!s1.contains("start"));

        // Second line is inside the template literal
        let s2 = p.sanitize_line("console.log in middle");
        assert!(!s2.contains("console"));

        // Third line ends the template literal
        let s3 = p.sanitize_line("end of template` + y;");
        assert!(!s3.contains("end of template"));
        assert!(s3.contains("+ y;"));
    }

    #[test]
    fn typescript_masks_template_literals() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::TypeScript);
        let s = p.sanitize_line("let x = `console.log inside template`;");
        assert!(s.contains("let x ="));
        assert!(!s.contains("console"));
    }

    // ==================== Go-specific tests ====================

    #[test]
    fn go_masks_line_comments() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Go);
        let s = p.sanitize_line("x := 1 // fmt.Println here");
        assert!(s.contains("x := 1"));
        assert!(!s.contains("fmt"));
    }

    #[test]
    fn go_masks_block_comments() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Go);
        let s = p.sanitize_line("x := /* fmt.Println */ 1");
        assert!(s.contains("x :="));
        assert!(s.contains("1"));
        assert!(!s.contains("fmt"));
    }

    #[test]
    fn go_masks_double_quoted_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Go);
        let s = p.sanitize_line("x := \"fmt.Println inside\"");
        assert!(s.contains("x :="));
        assert!(!s.contains("fmt"));
    }

    #[test]
    fn go_masks_backtick_raw_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Go);
        let s = p.sanitize_line("x := `fmt.Println inside raw string`");
        assert!(s.contains("x :="));
        assert!(!s.contains("fmt"));
    }

    #[test]
    fn go_backtick_raw_string_multiline() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Go);
        // First line starts the raw string
        let s1 = p.sanitize_line("x := `start of");
        assert!(s1.contains("x :="));
        assert!(!s1.contains("start"));

        // Second line is inside the raw string
        let s2 = p.sanitize_line("fmt.Println in middle");
        assert!(!s2.contains("fmt"));

        // Third line ends the raw string
        let s3 = p.sanitize_line("end of raw` + y");
        assert!(!s3.contains("end of raw"));
        assert!(s3.contains("+ y"));
    }

    // ==================== Ruby-specific tests ====================

    #[test]
    fn ruby_masks_hash_comments() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Ruby);
        let s = p.sanitize_line("x = 1  # this is a comment with puts");
        assert!(s.contains("x = 1"));
        assert!(!s.contains("puts"));
        assert!(!s.contains("comment"));
    }

    #[test]
    fn ruby_does_not_mask_hash_in_string() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Ruby);
        let s = p.sanitize_line("x = \"# not a comment\"  # real comment");
        assert!(s.contains("# not a comment"));
        assert!(!s.contains("real comment"));
    }

    #[test]
    fn ruby_masks_single_quoted_strings() {
        // Ruby uses single quotes for strings (not char literals like C/Rust)
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Ruby);
        let s = p.sanitize_line("puts 'hello world'");
        assert!(s.contains("puts"));
        // The content inside the single quotes should be masked
        assert!(!s.contains("hello"));
        assert!(!s.contains("world"));
    }

    #[test]
    fn ruby_masks_double_quoted_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Ruby);
        let s = p.sanitize_line("puts \"hello world\"");
        assert!(s.contains("puts"));
        assert!(!s.contains("hello"));
        assert!(!s.contains("world"));
    }

    // ==================== Unknown/fallback language tests ====================

    #[test]
    fn unknown_language_uses_cstyle_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Unknown);
        let s = p.sanitize_line("x = 1; // this is a comment");
        assert!(s.contains("x = 1;"));
        assert!(!s.contains("comment"));
    }

    #[test]
    fn unknown_language_uses_cstyle_block_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Unknown);
        let s = p.sanitize_line("x = /* comment */ 1;");
        assert!(s.contains("x ="));
        assert!(s.contains("1;"));
        assert!(!s.contains("comment"));
    }

    #[test]
    fn unknown_language_does_not_mask_hash_as_comment() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Unknown);
        let s = p.sanitize_line("x = 1  # this is NOT a comment");
        // Hash should NOT be treated as a comment for unknown languages
        assert!(s.contains("# this is NOT a comment"));
    }

    // ==================== Line length preservation tests ====================

    #[test]
    fn preserves_line_length_python_hash_comment() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Python);
        let line = "x = 1  # comment";
        let s = p.sanitize_line(line);
        assert_eq!(s.len(), line.len());
    }

    #[test]
    fn preserves_line_length_javascript_template_literal() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);
        let line = "let x = `template`;";
        let s = p.sanitize_line(line);
        assert_eq!(s.len(), line.len());
    }

    #[test]
    fn preserves_line_length_go_raw_string() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Go);
        let line = "x := `raw string`";
        let s = p.sanitize_line(line);
        assert_eq!(s.len(), line.len());
    }

    #[test]
    fn preserves_line_length_python_triple_quoted() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);
        let line = "x = \"\"\"triple\"\"\"";
        let s = p.sanitize_line(line);
        assert_eq!(s.len(), line.len());
    }

    // ==================== Multi-line block comment tests (Requirement 9.3) ====================

    #[test]
    fn multiline_block_comment_cstyle() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);

        // First line starts the block comment
        let s1 = p.sanitize_line("let x = 1; /* start of comment");
        assert!(s1.contains("let x = 1;"));
        assert!(!s1.contains("start of comment"));

        // Second line is entirely inside the block comment
        let s2 = p.sanitize_line("console.log('hidden') in middle");
        assert!(!s2.contains("console"));
        assert!(!s2.contains("hidden"));

        // Third line ends the block comment
        let s3 = p.sanitize_line("end of comment */ let y = 2;");
        assert!(!s3.contains("end of comment"));
        assert!(s3.contains("let y = 2;"));
    }

    #[test]
    fn multiline_block_comment_rust_nested() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

        // First line starts a nested block comment
        let s1 = p.sanitize_line("let x = 1; /* outer /* inner");
        assert!(s1.contains("let x = 1;"));
        assert!(!s1.contains("outer"));
        assert!(!s1.contains("inner"));

        // Second line is inside nested comment
        let s2 = p.sanitize_line("still in comment");
        assert!(!s2.contains("still"));

        // Third line closes inner comment but still in outer
        let s3 = p.sanitize_line("inner closed */ still outer");
        assert!(!s3.contains("inner closed"));
        assert!(!s3.contains("still outer"));

        // Fourth line closes outer comment
        let s4 = p.sanitize_line("outer closed */ let y = 2;");
        assert!(!s4.contains("outer closed"));
        assert!(s4.contains("let y = 2;"));
    }

    #[test]
    fn multiline_block_comment_go() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Go);

        // First line starts the block comment
        let s1 = p.sanitize_line("x := 1 /* start");
        assert!(s1.contains("x := 1"));
        assert!(!s1.contains("start"));

        // Second line is inside the block comment
        let s2 = p.sanitize_line("fmt.Println hidden");
        assert!(!s2.contains("fmt"));
        assert!(!s2.contains("hidden"));

        // Third line ends the block comment
        let s3 = p.sanitize_line("end */ y := 2");
        assert!(!s3.contains("end"));
        assert!(s3.contains("y := 2"));
    }

    #[test]
    fn multiline_block_comment_java() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Java);

        // First line starts the block comment
        let s1 = p.sanitize_line("int x = 1; /* javadoc style");
        assert!(s1.contains("int x = 1;"));
        assert!(!s1.contains("javadoc"));

        // Second line is inside the block comment
        let s2 = p.sanitize_line(" * System.out.println hidden");
        assert!(!s2.contains("System"));
        assert!(!s2.contains("hidden"));

        // Third line ends the block comment
        let s3 = p.sanitize_line(" */ int y = 2;");
        assert!(s3.contains("int y = 2;"));
    }

    #[test]
    fn multiline_block_comment_preserves_line_length() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);

        let line1 = "let x = 1; /* start";
        let s1 = p.sanitize_line(line1);
        assert_eq!(s1.len(), line1.len());

        let line2 = "middle of comment";
        let s2 = p.sanitize_line(line2);
        assert_eq!(s2.len(), line2.len());

        let line3 = "end */ let y = 2;";
        let s3 = p.sanitize_line(line3);
        assert_eq!(s3.len(), line3.len());
    }

    // ==================== Multi-line string tests (Requirement 9.3) ====================

    #[test]
    fn multiline_string_with_escaped_newline() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);

        // First line starts a string with escaped newline at end
        let s1 = p.sanitize_line("let x = \"start\\");
        assert!(s1.contains("let x ="));
        // The string content should be masked
        assert!(!s1.contains("start"));

        // Second line continues the string (escaped newline means string continues)
        let s2 = p.sanitize_line("console.log hidden\"");
        // After the escaped backslash, we're still in the string
        // The string ends with the closing quote
        assert!(!s2.contains("console"));
    }

    #[test]
    fn multiline_rust_raw_string() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

        // First line starts a raw string
        let s1 = p.sanitize_line("let x = r#\"start of raw");
        assert!(s1.contains("let x ="));
        assert!(!s1.contains("start"));

        // Second line is inside the raw string
        let s2 = p.sanitize_line("unwrap() hidden in raw string");
        assert!(!s2.contains("unwrap"));

        // Third line ends the raw string
        let s3 = p.sanitize_line("end of raw\"# + y;");
        assert!(!s3.contains("end of raw"));
        assert!(s3.contains("+ y;"));
    }

    #[test]
    fn multiline_rust_raw_string_with_hashes() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

        // First line starts a raw string with multiple hashes
        let s1 = p.sanitize_line("let x = r##\"start");
        assert!(s1.contains("let x ="));
        assert!(!s1.contains("start"));

        // Second line has a fake ending that shouldn't close the string
        let s2 = p.sanitize_line("fake end\"# still inside");
        assert!(!s2.contains("fake"));
        assert!(!s2.contains("still inside"));

        // Third line has the real ending with correct number of hashes
        let s3 = p.sanitize_line("real end\"## + y;");
        assert!(!s3.contains("real end"));
        assert!(s3.contains("+ y;"));
    }

    #[test]
    fn multiline_python_triple_quoted_with_embedded_quotes() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);

        // First line starts a triple-quoted string
        let s1 = p.sanitize_line("x = \"\"\"start with \"embedded\" quote");
        assert!(s1.contains("x ="));
        assert!(!s1.contains("start"));
        assert!(!s1.contains("embedded"));

        // Second line has more embedded quotes
        let s2 = p.sanitize_line("more \"quotes\" and 'single' too");
        assert!(!s2.contains("quotes"));
        assert!(!s2.contains("single"));

        // Third line ends the triple-quoted string
        let s3 = p.sanitize_line("end\"\"\" + y");
        assert!(!s3.contains("end"));
        assert!(s3.contains("+ y"));
    }

    #[test]
    fn multiline_javascript_template_literal_with_expressions() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);

        // First line starts a template literal
        let s1 = p.sanitize_line("let x = `start ${expr}");
        assert!(s1.contains("let x ="));
        assert!(!s1.contains("start"));

        // Second line is inside the template literal
        let s2 = p.sanitize_line("console.log in template");
        assert!(!s2.contains("console"));

        // Third line ends the template literal
        let s3 = p.sanitize_line("end` + y;");
        assert!(!s3.contains("end"));
        assert!(s3.contains("+ y;"));
    }

    // ==================== State reset tests (Requirement 9.3) ====================

    #[test]
    fn reset_clears_block_comment_state() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);

        // Start a block comment
        let s1 = p.sanitize_line("let x = 1; /* start comment");
        assert!(!s1.contains("start comment"));

        // Verify we're in block comment mode
        let s2 = p.sanitize_line("still in comment");
        assert!(!s2.contains("still"));

        // Reset the preprocessor
        p.reset();

        // After reset, the same line should NOT be treated as inside a comment
        let s3 = p.sanitize_line("not in comment anymore");
        assert!(s3.contains("not in comment anymore"));
    }

    #[test]
    fn reset_clears_string_state() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);

        // Start a triple-quoted string
        let s1 = p.sanitize_line("x = \"\"\"start of string");
        assert!(!s1.contains("start"));

        // Verify we're in string mode
        let s2 = p.sanitize_line("still in string");
        assert!(!s2.contains("still"));

        // Reset the preprocessor
        p.reset();

        // After reset, the same line should NOT be treated as inside a string
        let s3 = p.sanitize_line("not in string anymore");
        assert!(s3.contains("not in string anymore"));
    }

    #[test]
    fn reset_clears_template_literal_state() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);

        // Start a template literal
        let s1 = p.sanitize_line("let x = `start of template");
        assert!(!s1.contains("start"));

        // Verify we're in template literal mode
        let s2 = p.sanitize_line("still in template");
        assert!(!s2.contains("still"));

        // Reset the preprocessor
        p.reset();

        // After reset, the same line should NOT be treated as inside a template literal
        let s3 = p.sanitize_line("not in template anymore");
        assert!(s3.contains("not in template anymore"));
    }

    #[test]
    fn reset_clears_raw_string_state() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Go);

        // Start a raw string
        let s1 = p.sanitize_line("x := `start of raw");
        assert!(!s1.contains("start"));

        // Verify we're in raw string mode
        let s2 = p.sanitize_line("still in raw");
        assert!(!s2.contains("still"));

        // Reset the preprocessor
        p.reset();

        // After reset, the same line should NOT be treated as inside a raw string
        let s3 = p.sanitize_line("not in raw anymore");
        assert!(s3.contains("not in raw anymore"));
    }

    #[test]
    fn set_language_resets_state() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);

        // Start a block comment
        let s1 = p.sanitize_line("let x = 1; /* start comment");
        assert!(!s1.contains("start comment"));

        // Verify we're in block comment mode
        let s2 = p.sanitize_line("still in comment");
        assert!(!s2.contains("still"));

        // Change language (which should reset state)
        p.set_language(Language::Python);

        // After set_language, the state should be reset
        let s3 = p.sanitize_line("not in comment anymore");
        assert!(s3.contains("not in comment anymore"));
    }

    #[test]
    fn set_language_changes_syntax_and_resets() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);

        // Start a block comment in JavaScript
        let s1 = p.sanitize_line("let x = 1; /* start");
        assert!(!s1.contains("start"));

        // Change to Python (which uses hash comments)
        p.set_language(Language::Python);

        // Now hash should be treated as comment, not /* */
        let s2 = p.sanitize_line("x = 1  # python comment");
        assert!(s2.contains("x = 1"));
        assert!(!s2.contains("python comment"));

        // And /* should NOT be treated as comment start in Python
        let s3 = p.sanitize_line("x = 1 /* not a comment */");
        assert!(s3.contains("/* not a comment */"));
    }

    #[test]
    fn state_reset_between_files_simulation() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Rust);

        // Process "file 1" - start a block comment
        let f1_l1 = p.sanitize_line("// File 1");
        assert!(!f1_l1.contains("File 1"));

        let f1_l2 = p.sanitize_line("let x = 1; /* unclosed comment");
        assert!(!f1_l2.contains("unclosed"));

        // Simulate switching to "file 2" by resetting
        p.reset();

        // Process "file 2" - should start fresh
        let f2_l1 = p.sanitize_line("// File 2");
        assert!(!f2_l1.contains("File 2"));

        let f2_l2 = p.sanitize_line("let y = 2; // normal code");
        assert!(f2_l2.contains("let y = 2;"));
        assert!(!f2_l2.contains("normal code"));
    }

    #[test]
    fn state_reset_between_files_with_language_change() {
        let mut p = Preprocessor::with_language(
            PreprocessOptions::comments_and_strings(),
            Language::Python,
        );

        // Process Python file - start a triple-quoted string
        let py_l1 = p.sanitize_line("x = \"\"\"unclosed");
        assert!(!py_l1.contains("unclosed"));

        // Simulate switching to JavaScript file
        p.set_language(Language::JavaScript);

        // Process JavaScript file - should start fresh with JS syntax
        let js_l1 = p.sanitize_line("let x = `template`;");
        assert!(js_l1.contains("let x ="));
        assert!(!js_l1.contains("template"));

        // Verify template literal works correctly
        let js_l2 = p.sanitize_line("let y = 2; // comment");
        assert!(js_l2.contains("let y = 2;"));
        assert!(!js_l2.contains("comment"));
    }

    #[test]
    fn nested_rust_block_comment_state_tracking() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

        // Start nested block comments
        let s1 = p.sanitize_line("/* level 1 /* level 2");
        assert!(!s1.contains("level 1"));
        assert!(!s1.contains("level 2"));

        // Close one level
        let s2 = p.sanitize_line("close level 2 */ still level 1");
        assert!(!s2.contains("close level 2"));
        assert!(!s2.contains("still level 1"));

        // Close final level
        let s3 = p.sanitize_line("close level 1 */ visible code");
        assert!(!s3.contains("close level 1"));
        assert!(s3.contains("visible code"));
    }

    // ==================== Shell/Bash-specific tests ====================

    #[test]
    fn shell_language_from_str() {
        assert_eq!("shell".parse::<Language>().unwrap(), Language::Shell);
        assert_eq!("bash".parse::<Language>().unwrap(), Language::Shell);
        assert_eq!("sh".parse::<Language>().unwrap(), Language::Shell);
        assert_eq!("zsh".parse::<Language>().unwrap(), Language::Shell);
        assert_eq!("ksh".parse::<Language>().unwrap(), Language::Shell);
        assert_eq!("fish".parse::<Language>().unwrap(), Language::Shell);
    }

    #[test]
    fn shell_comment_syntax() {
        assert_eq!(Language::Shell.comment_syntax(), CommentSyntax::Hash);
    }

    #[test]
    fn shell_string_syntax() {
        assert_eq!(Language::Shell.string_syntax(), StringSyntax::Shell);
    }

    #[test]
    fn shell_masks_hash_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Shell);
        let s = p.sanitize_line("echo hello  # this is a comment");
        assert!(s.contains("echo hello"));
        assert!(!s.contains("this is a comment"));
    }

    #[test]
    fn shell_does_not_mask_hash_in_string() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Shell);
        let s = p.sanitize_line("echo \"# not a comment\"  # real comment");
        assert!(s.contains("# not a comment"));
        assert!(!s.contains("real comment"));
    }

    #[test]
    fn shell_single_quoted_string_no_escapes() {
        // Shell single quotes are literal - backslash has NO special meaning
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);
        let s = p.sanitize_line("echo 'hello\\nworld'");
        assert!(s.contains("echo"));
        assert!(!s.contains("hello"));
        assert!(!s.contains("world"));
        // Verify the backslash is masked too
        assert!(!s.contains("\\n"));
    }

    #[test]
    fn shell_single_quoted_cannot_contain_single_quote() {
        // In shell, you cannot escape a single quote inside single quotes
        // 'hello' is a complete string, then world' is the next token
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);
        let s = p.sanitize_line("echo 'hello' world");
        assert!(s.contains("echo"));
        assert!(!s.contains("hello"));
        assert!(s.contains("world")); // world is outside the string
    }

    #[test]
    fn shell_double_quoted_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);
        let s = p.sanitize_line("echo \"hello world\"");
        assert!(s.contains("echo"));
        assert!(!s.contains("hello"));
        assert!(!s.contains("world"));
    }

    #[test]
    fn shell_double_quoted_with_escapes() {
        // Shell double quotes support backslash escapes
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);
        let s = p.sanitize_line("echo \"say \\\"hello\\\"\"");
        assert!(s.contains("echo"));
        assert!(!s.contains("say"));
        assert!(!s.contains("hello"));
    }

    #[test]
    fn shell_ansi_c_quoting() {
        // Shell ANSI-C quoting: $'...'
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);
        let s = p.sanitize_line("echo $'hello\\nworld'");
        assert!(s.contains("echo"));
        assert!(!s.contains("hello"));
        assert!(!s.contains("world"));
    }

    #[test]
    fn shell_ansi_c_quoting_with_escapes() {
        // ANSI-C quoting supports escapes like \t, \n, \'
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);
        let s = p.sanitize_line("echo $'tab\\there'");
        assert!(s.contains("echo"));
        assert!(!s.contains("tab"));
        assert!(!s.contains("here"));
    }

    #[test]
    fn shell_ansi_c_escaped_single_quote() {
        // Unlike regular single quotes, $' allows \' to escape a quote
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);
        let s = p.sanitize_line("echo $'it\\'s ok'");
        assert!(s.contains("echo"));
        assert!(!s.contains("it"));
        assert!(!s.contains("ok"));
    }

    #[test]
    fn shell_preserves_line_length() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Shell);
        let line = "echo 'hello' # comment";
        let s = p.sanitize_line(line);
        assert_eq!(s.len(), line.len());
    }

    #[test]
    fn shell_multiline_double_quoted_string() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);

        // First line starts a double-quoted string with escaped newline
        let s1 = p.sanitize_line("echo \"start\\");
        assert!(s1.contains("echo"));
        assert!(!s1.contains("start"));

        // Second line continues the string
        let s2 = p.sanitize_line("middle\" end");
        // After escaped backslash, we're still in the string until closing quote
        assert!(s2.contains("end"));
    }

    #[test]
    fn shell_hash_not_comment_in_string() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Shell);
        let s = p.sanitize_line("grep '#include' file.c  # search for includes");
        assert!(!s.contains("#include")); // masked (in string)
        assert!(!s.contains("search")); // masked (in comment)
        assert!(s.contains("grep"));
        assert!(s.contains("file.c"));
    }

    #[test]
    fn shell_complex_mixed_quotes() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Shell);
        // Mix of single, double, and $' quoting
        let s = p.sanitize_line("echo 'single' \"double\" $'ansi' # comment");
        assert!(s.contains("echo"));
        assert!(!s.contains("single"));
        assert!(!s.contains("double"));
        assert!(!s.contains("ansi"));
        assert!(!s.contains("comment"));
    }

    // ==================== Swift-specific tests ====================

    #[test]
    fn swift_language_from_str() {
        assert_eq!("swift".parse::<Language>().unwrap(), Language::Swift);
        assert_eq!("Swift".parse::<Language>().unwrap(), Language::Swift);
        assert_eq!("SWIFT".parse::<Language>().unwrap(), Language::Swift);
    }

    #[test]
    fn swift_comment_syntax() {
        assert_eq!(
            Language::Swift.comment_syntax(),
            CommentSyntax::CStyleNested
        );
    }

    #[test]
    fn swift_string_syntax() {
        assert_eq!(Language::Swift.string_syntax(), StringSyntax::SwiftScala);
    }

    #[test]
    fn swift_masks_line_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Swift);
        let s = p.sanitize_line("let x = 1 // print() here");
        assert!(s.contains("let x = 1"));
        assert!(!s.contains("print"));
    }

    #[test]
    fn swift_masks_block_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Swift);
        let s = p.sanitize_line("let x = /* print() */ 1");
        assert!(s.contains("let x ="));
        assert!(s.contains("1"));
        assert!(!s.contains("print"));
    }

    #[test]
    fn swift_nested_block_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Swift);
        // Swift supports nested block comments like Rust
        let s1 = p.sanitize_line("let x = 1 /* outer /* inner");
        assert!(s1.contains("let x = 1"));
        assert!(!s1.contains("outer"));
        assert!(!s1.contains("inner"));

        // Still in nested comment
        let s2 = p.sanitize_line("still inside");
        assert!(!s2.contains("still"));

        // Close inner
        let s3 = p.sanitize_line("close inner */ still outer");
        assert!(!s3.contains("close inner"));
        assert!(!s3.contains("still outer"));

        // Close outer
        let s4 = p.sanitize_line("close outer */ let y = 2");
        assert!(!s4.contains("close outer"));
        assert!(s4.contains("let y = 2"));
    }

    #[test]
    fn swift_masks_double_quoted_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Swift);
        let s = p.sanitize_line("let x = \"print() inside\"");
        assert!(s.contains("let x ="));
        assert!(!s.contains("print"));
    }

    #[test]
    fn swift_masks_triple_quoted_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Swift);
        let s = p.sanitize_line("let x = \"\"\"print() inside\"\"\"");
        assert!(s.contains("let x ="));
        assert!(!s.contains("print"));
    }

    #[test]
    fn swift_triple_quoted_string_multiline() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Swift);
        // First line starts the triple-quoted string
        let s1 = p.sanitize_line("let x = \"\"\"start of");
        assert!(s1.contains("let x ="));
        assert!(!s1.contains("start"));

        // Second line is inside the string
        let s2 = p.sanitize_line("print() in middle");
        assert!(!s2.contains("print"));

        // Third line ends the string
        let s3 = p.sanitize_line("end of string\"\"\" + y");
        assert!(!s3.contains("end of string"));
        assert!(s3.contains("+ y"));
    }

    #[test]
    fn swift_preserves_line_length() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Swift);
        let line = "let x = \"hello\" // comment";
        let s = p.sanitize_line(line);
        assert_eq!(s.len(), line.len());
    }

    // ==================== Scala-specific tests ====================

    #[test]
    fn scala_language_from_str() {
        assert_eq!("scala".parse::<Language>().unwrap(), Language::Scala);
        assert_eq!("Scala".parse::<Language>().unwrap(), Language::Scala);
        assert_eq!("SCALA".parse::<Language>().unwrap(), Language::Scala);
    }

    #[test]
    fn scala_comment_syntax() {
        assert_eq!(
            Language::Scala.comment_syntax(),
            CommentSyntax::CStyleNested
        );
    }

    #[test]
    fn scala_string_syntax() {
        assert_eq!(Language::Scala.string_syntax(), StringSyntax::SwiftScala);
    }

    #[test]
    fn scala_masks_line_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Scala);
        let s = p.sanitize_line("val x = 1 // println() here");
        assert!(s.contains("val x = 1"));
        assert!(!s.contains("println"));
    }

    #[test]
    fn scala_masks_block_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Scala);
        let s = p.sanitize_line("val x = /* println() */ 1");
        assert!(s.contains("val x ="));
        assert!(s.contains("1"));
        assert!(!s.contains("println"));
    }

    #[test]
    fn scala_nested_block_comments() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Scala);
        // Scala supports nested block comments
        let s1 = p.sanitize_line("val x = 1 /* outer /* inner");
        assert!(s1.contains("val x = 1"));
        assert!(!s1.contains("outer"));

        let s2 = p.sanitize_line("still inside");
        assert!(!s2.contains("still"));

        let s3 = p.sanitize_line("inner */ still outer");
        assert!(!s3.contains("inner"));

        let s4 = p.sanitize_line("outer */ val y = 2");
        assert!(s4.contains("val y = 2"));
    }

    #[test]
    fn scala_masks_double_quoted_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Scala);
        let s = p.sanitize_line("val x = \"println() inside\"");
        assert!(s.contains("val x ="));
        assert!(!s.contains("println"));
    }

    #[test]
    fn scala_masks_triple_quoted_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Scala);
        let s = p.sanitize_line("val x = \"\"\"println() inside\"\"\"");
        assert!(s.contains("val x ="));
        assert!(!s.contains("println"));
    }

    #[test]
    fn scala_triple_quoted_string_multiline() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Scala);
        let s1 = p.sanitize_line("val x = \"\"\"start of");
        assert!(s1.contains("val x ="));
        assert!(!s1.contains("start"));

        let s2 = p.sanitize_line("println() in middle");
        assert!(!s2.contains("println"));

        let s3 = p.sanitize_line("end of string\"\"\" + y");
        assert!(!s3.contains("end of string"));
        assert!(s3.contains("+ y"));
    }

    #[test]
    fn scala_preserves_line_length() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Scala);
        let line = "val x = \"hello\" // comment";
        let s = p.sanitize_line(line);
        assert_eq!(s.len(), line.len());
    }

    // ==================== SQL-specific tests ====================

    #[test]
    fn sql_language_from_str() {
        assert_eq!("sql".parse::<Language>().unwrap(), Language::Sql);
        assert_eq!("SQL".parse::<Language>().unwrap(), Language::Sql);
        assert_eq!("Sql".parse::<Language>().unwrap(), Language::Sql);
    }

    #[test]
    fn sql_comment_syntax() {
        assert_eq!(Language::Sql.comment_syntax(), CommentSyntax::Sql);
    }

    #[test]
    fn sql_string_syntax() {
        assert_eq!(Language::Sql.string_syntax(), StringSyntax::Sql);
    }

    #[test]
    fn sql_masks_double_dash_comments() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Sql);
        let s = p.sanitize_line("SELECT * FROM users -- secret query");
        assert!(s.contains("SELECT * FROM users"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn sql_masks_block_comments() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Sql);
        let s = p.sanitize_line("SELECT /* hidden */ * FROM users");
        assert!(s.contains("SELECT"));
        assert!(s.contains("* FROM users"));
        assert!(!s.contains("hidden"));
    }

    #[test]
    fn sql_multiline_block_comment() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Sql);
        let s1 = p.sanitize_line("SELECT * /* start comment");
        assert!(s1.contains("SELECT *"));
        assert!(!s1.contains("start"));

        let s2 = p.sanitize_line("hidden query");
        assert!(!s2.contains("hidden"));

        let s3 = p.sanitize_line("end comment */ FROM users");
        assert!(!s3.contains("end comment"));
        assert!(s3.contains("FROM users"));
    }

    #[test]
    fn sql_masks_single_quoted_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Sql);
        let s = p.sanitize_line("SELECT * FROM users WHERE name = 'secret_password'");
        assert!(s.contains("SELECT * FROM users WHERE name ="));
        assert!(!s.contains("secret_password"));
    }

    #[test]
    fn sql_does_not_mask_double_quoted_as_string() {
        // In SQL, double quotes are for identifiers, not strings
        // But for simplicity, we don't handle them specially
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Sql);
        let s = p.sanitize_line("SELECT \"column\" FROM users");
        // SQL string syntax only uses single quotes, so double quotes pass through
        assert!(s.contains("SELECT"));
        assert!(s.contains("column")); // Not masked because SQL uses single quotes
    }

    #[test]
    fn sql_single_dash_not_comment() {
        // A single dash should not start a comment in SQL
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Sql);
        let s = p.sanitize_line("SELECT a - b FROM table");
        assert!(s.contains("SELECT a - b FROM table"));
    }

    #[test]
    fn sql_preserves_line_length() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Sql);
        let line = "SELECT 'hello' -- comment";
        let s = p.sanitize_line(line);
        assert_eq!(s.len(), line.len());
    }

    #[test]
    fn sql_does_not_mask_hash_in_string() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Sql);
        let s = p.sanitize_line("SELECT * WHERE name = '-- not a comment' -- real comment");
        assert!(s.contains("-- not a comment"));
        assert!(!s.contains("real comment"));
    }

    // ==================== XML/HTML-specific tests ====================

    #[test]
    fn xml_language_from_str() {
        assert_eq!("xml".parse::<Language>().unwrap(), Language::Xml);
        assert_eq!("html".parse::<Language>().unwrap(), Language::Xml);
        assert_eq!("xhtml".parse::<Language>().unwrap(), Language::Xml);
        assert_eq!("svg".parse::<Language>().unwrap(), Language::Xml);
        assert_eq!("xsl".parse::<Language>().unwrap(), Language::Xml);
        assert_eq!("xslt".parse::<Language>().unwrap(), Language::Xml);
    }

    #[test]
    fn xml_comment_syntax() {
        assert_eq!(Language::Xml.comment_syntax(), CommentSyntax::Xml);
    }

    #[test]
    fn xml_string_syntax() {
        assert_eq!(Language::Xml.string_syntax(), StringSyntax::Xml);
    }

    #[test]
    fn xml_masks_comments() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Xml);
        let s = p.sanitize_line("<div><!-- secret comment --></div>");
        assert!(s.contains("<div>"));
        assert!(s.contains("</div>"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn xml_multiline_comment() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Xml);
        let s1 = p.sanitize_line("<div><!-- start comment");
        assert!(s1.contains("<div>"));
        assert!(!s1.contains("start"));

        let s2 = p.sanitize_line("hidden content");
        assert!(!s2.contains("hidden"));

        let s3 = p.sanitize_line("end comment --></div>");
        assert!(!s3.contains("end comment"));
        assert!(s3.contains("</div>"));
    }

    #[test]
    fn xml_masks_double_quoted_attributes() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Xml);
        let s = p.sanitize_line("<input type=\"password\" value=\"secret\">");
        assert!(s.contains("<input type="));
        assert!(s.contains("value="));
        assert!(!s.contains("password"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn xml_masks_single_quoted_attributes() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Xml);
        let s = p.sanitize_line("<input type='password' value='secret'>");
        assert!(s.contains("<input type="));
        assert!(s.contains("value="));
        assert!(!s.contains("password"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn xml_mixed_quotes() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Xml);
        let s = p.sanitize_line("<div class=\"myclass\" id='myid'>");
        assert!(s.contains("<div class="));
        assert!(s.contains("id="));
        assert!(!s.contains("myclass"));
        assert!(!s.contains("myid"));
    }

    #[test]
    fn xml_preserves_line_length() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Xml);
        let line = "<div class=\"test\"><!-- comment --></div>";
        let s = p.sanitize_line(line);
        assert_eq!(s.len(), line.len());
    }

    #[test]
    fn xml_comment_delimiter_not_in_string() {
        // When masking only comments, strings should preserve their content
        // The <!-- inside the string should NOT be treated as a comment start
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Xml);
        let s = p.sanitize_line("<div data-comment=\"<!-- not a comment -->\"><!-- real --></div>");
        // The string content is preserved because we're only masking comments
        assert!(s.contains("<!-- not a comment -->"));
        // The real comment is masked
        assert!(!s.contains("real"));
    }

    // ==================== PHP-specific tests ====================

    #[test]
    fn php_language_from_str() {
        assert_eq!("php".parse::<Language>().unwrap(), Language::Php);
        assert_eq!("PHP".parse::<Language>().unwrap(), Language::Php);
        assert_eq!("Php".parse::<Language>().unwrap(), Language::Php);
    }

    #[test]
    fn php_comment_syntax() {
        assert_eq!(Language::Php.comment_syntax(), CommentSyntax::Php);
    }

    #[test]
    fn php_string_syntax() {
        assert_eq!(Language::Php.string_syntax(), StringSyntax::Php);
    }

    #[test]
    fn php_masks_double_slash_comments() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Php);
        let s = p.sanitize_line("$x = 1; // echo secret");
        assert!(s.contains("$x = 1;"));
        assert!(!s.contains("echo"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn php_masks_hash_comments() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Php);
        let s = p.sanitize_line("$x = 1; # echo secret");
        assert!(s.contains("$x = 1;"));
        assert!(!s.contains("echo"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn php_masks_block_comments() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Php);
        let s = p.sanitize_line("$x = /* echo secret */ 1;");
        assert!(s.contains("$x ="));
        assert!(s.contains("1;"));
        assert!(!s.contains("echo"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn php_multiline_block_comment() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Php);
        let s1 = p.sanitize_line("$x = 1; /* start comment");
        assert!(s1.contains("$x = 1;"));
        assert!(!s1.contains("start"));

        let s2 = p.sanitize_line("hidden code");
        assert!(!s2.contains("hidden"));

        let s3 = p.sanitize_line("end comment */ $y = 2;");
        assert!(!s3.contains("end comment"));
        assert!(s3.contains("$y = 2;"));
    }

    #[test]
    fn php_masks_double_quoted_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Php);
        let s = p.sanitize_line("$x = \"echo secret\";");
        assert!(s.contains("$x ="));
        assert!(!s.contains("echo"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn php_masks_single_quoted_strings() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Php);
        let s = p.sanitize_line("$x = 'echo secret';");
        assert!(s.contains("$x ="));
        assert!(!s.contains("echo"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn php_string_with_escapes() {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Php);
        let s = p.sanitize_line("$x = \"say \\\"hello\\\"\";");
        assert!(s.contains("$x ="));
        assert!(!s.contains("say"));
        assert!(!s.contains("hello"));
    }

    #[test]
    fn php_hash_not_comment_in_string() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Php);
        let s = p.sanitize_line("$x = \"# not a comment\"; # real comment");
        assert!(s.contains("# not a comment"));
        assert!(!s.contains("real comment"));
    }

    #[test]
    fn php_slash_not_comment_in_string() {
        let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Php);
        let s = p.sanitize_line("$x = \"// not a comment\"; // real comment");
        assert!(s.contains("// not a comment"));
        assert!(!s.contains("real comment"));
    }

    #[test]
    fn php_preserves_line_length() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Php);
        let line = "$x = 'hello'; // comment";
        let s = p.sanitize_line(line);
        assert_eq!(s.len(), line.len());
    }

    #[test]
    fn php_mixed_comments_and_strings() {
        let mut p =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Php);
        let s = p.sanitize_line("echo 'single' . \"double\"; // comment # more");
        assert!(s.contains("echo"));
        assert!(s.contains("."));
        assert!(!s.contains("single"));
        assert!(!s.contains("double"));
        assert!(!s.contains("comment"));
        assert!(!s.contains("more"));
    }
}
