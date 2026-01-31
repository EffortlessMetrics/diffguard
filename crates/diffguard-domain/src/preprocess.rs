use std::fmt;

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
    #[default]
    Unknown,
}

impl Language {
    /// Parse a language identifier string into a Language enum.
    ///
    /// The matching is case-insensitive.
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
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
            _ => Language::Unknown,
        }
    }

    /// Returns the comment syntax for this language.
    pub fn comment_syntax(self) -> CommentSyntax {
        match self {
            Language::Python | Language::Ruby => CommentSyntax::Hash,
            Language::Rust => CommentSyntax::CStyleNested,
            _ => CommentSyntax::CStyle,
        }
    }

    /// Returns the string syntax for this language.
    pub fn string_syntax(self) -> StringSyntax {
        match self {
            Language::Rust => StringSyntax::Rust,
            Language::Python => StringSyntax::Python,
            Language::JavaScript | Language::TypeScript => StringSyntax::JavaScript,
            Language::Go => StringSyntax::Go,
            _ => StringSyntax::CStyle,
        }
    }
}

/// Comment syntax variants for different programming languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentSyntax {
    /// C-style comments: `//` line comments and `/* */` block comments
    CStyle,
    /// C-style comments with nesting support (Rust): `//` and `/* */` with nesting
    CStyleNested,
    /// Hash comments only: `#` line comments (Python, Ruby)
    Hash,
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
    BlockComment { depth: u32 },
    NormalString { escaped: bool },
    RawString { hashes: usize },
    Char { escaped: bool },
}

impl fmt::Debug for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Normal => write!(f, "Normal"),
            Mode::LineComment => write!(f, "LineComment"),
            Mode::BlockComment { depth } => write!(f, "BlockComment(depth={depth})"),
            Mode::NormalString { escaped } => write!(f, "NormalString(escaped={escaped})"),
            Mode::RawString { hashes } => write!(f, "RawString(hashes={hashes})"),
            Mode::Char { escaped } => write!(f, "Char(escaped={escaped})"),
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
}

impl Preprocessor {
    pub fn new(opts: PreprocessOptions) -> Self {
        Self {
            opts,
            mode: Mode::Normal,
        }
    }

    pub fn reset(&mut self) {
        self.mode = Mode::Normal;
    }

    /// Returns a sanitized line where masked segments are replaced with spaces.
    ///
    /// The output is the same length in bytes as the input.
    pub fn sanitize_line(&mut self, line: &str) -> String {
        let mut out: Vec<u8> = line.as_bytes().to_vec();
        let bytes = line.as_bytes();
        let len = bytes.len();

        let mut i = 0;

        while i < len {
            match self.mode {
                Mode::Normal => {
                    // Raw string start detection.
                    if self.opts.track_strings() {
                        if let Some((start_i, end_quote_i, hashes)) =
                            detect_raw_string_start(bytes, i)
                        {
                            // If this raw string start begins earlier than `i` (because of a `b` prefix),
                            // handle it only when we are at the start.
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
                            self.mode = Mode::NormalString { escaped: false };
                            i += 2;
                            continue;
                        }

                        // Normal string: "..."
                        if bytes[i] == b'"' {
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            self.mode = Mode::NormalString { escaped: false };
                            i += 1;
                            continue;
                        }

                        // Char literal
                        if bytes[i] == b'\'' {
                            if self.opts.mask_strings {
                                out[i] = b' ';
                            }
                            self.mode = Mode::Char { escaped: false };
                            i += 1;
                            continue;
                        }
                    }

                    // Comments detection.
                    if self.opts.mask_comments && bytes[i] == b'/' && i + 1 < len {
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
                    if self.opts.mask_comments
                        && bytes[i] == b'/'
                        && i + 1 < len
                        && bytes[i + 1] == b'*'
                    {
                        if self.opts.mask_comments {
                            out[i + 1] = b' ';
                        }
                        self.mode = Mode::BlockComment { depth: depth + 1 };
                        i += 2;
                        continue;
                    }

                    if self.opts.mask_comments
                        && bytes[i] == b'*'
                        && i + 1 < len
                        && bytes[i + 1] == b'/'
                    {
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

                Mode::NormalString { escaped } => {
                    if self.opts.mask_strings {
                        out[i] = b' ';
                    }

                    if escaped {
                        self.mode = Mode::NormalString { escaped: false };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'\\' {
                        self.mode = Mode::NormalString { escaped: true };
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'"' {
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

                    // Look for end delimiter: "###
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

    let mut j = r_i + 1;
    let mut hashes = 0usize;
    while j < len && bytes[j] == b'#' {
        hashes += 1;
        j += 1;
    }

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
    fn language_from_str_known_languages() {
        assert_eq!(Language::from_str("rust"), Language::Rust);
        assert_eq!(Language::from_str("python"), Language::Python);
        assert_eq!(Language::from_str("javascript"), Language::JavaScript);
        assert_eq!(Language::from_str("typescript"), Language::TypeScript);
        assert_eq!(Language::from_str("go"), Language::Go);
        assert_eq!(Language::from_str("ruby"), Language::Ruby);
        assert_eq!(Language::from_str("c"), Language::C);
        assert_eq!(Language::from_str("cpp"), Language::Cpp);
        assert_eq!(Language::from_str("csharp"), Language::CSharp);
        assert_eq!(Language::from_str("java"), Language::Java);
        assert_eq!(Language::from_str("kotlin"), Language::Kotlin);
    }

    #[test]
    fn language_from_str_case_insensitive() {
        assert_eq!(Language::from_str("RUST"), Language::Rust);
        assert_eq!(Language::from_str("Python"), Language::Python);
        assert_eq!(Language::from_str("JavaScript"), Language::JavaScript);
        assert_eq!(Language::from_str("TypeScript"), Language::TypeScript);
        assert_eq!(Language::from_str("GO"), Language::Go);
        assert_eq!(Language::from_str("RUBY"), Language::Ruby);
        assert_eq!(Language::from_str("C"), Language::C);
        assert_eq!(Language::from_str("CPP"), Language::Cpp);
        assert_eq!(Language::from_str("CSharp"), Language::CSharp);
        assert_eq!(Language::from_str("JAVA"), Language::Java);
        assert_eq!(Language::from_str("KOTLIN"), Language::Kotlin);
    }

    #[test]
    fn language_from_str_unknown() {
        assert_eq!(Language::from_str("unknown"), Language::Unknown);
        assert_eq!(Language::from_str(""), Language::Unknown);
        assert_eq!(Language::from_str("fortran"), Language::Unknown);
        assert_eq!(Language::from_str("cobol"), Language::Unknown);
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
        assert_eq!(Language::Ruby.string_syntax(), StringSyntax::CStyle);
        assert_eq!(Language::Unknown.string_syntax(), StringSyntax::CStyle);
    }

    // ==================== Preprocessor tests ====================

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
        let mut p = Preprocessor::new(PreprocessOptions::comments_and_strings());
        let s = p.sanitize_line("let s = r#\".unwrap()\"#;");
        assert!(!s.contains("unwrap"));
    }
}
