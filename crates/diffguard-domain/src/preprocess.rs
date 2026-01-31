use std::fmt;

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
                    if self.opts.mask_comments && bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
                        if self.opts.mask_comments {
                            out[i + 1] = b' ';
                        }
                        self.mode = Mode::BlockComment { depth: depth + 1 };
                        i += 2;
                        continue;
                    }

                    if self.opts.mask_comments && bytes[i] == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
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
