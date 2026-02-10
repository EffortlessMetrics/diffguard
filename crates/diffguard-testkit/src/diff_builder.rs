//! Unified diff builders for constructing test diffs.
//!
//! This module provides a fluent API for building valid unified diff strings.
//! The builders ensure that generated diffs are well-formed according to the
//! unified diff format.
//!
//! # Bounds
//!
//! To keep tests fast, the following bounds are enforced:
//! - Max files per diff: 5
//! - Max hunks per file: 5
//! - Max lines per hunk: 20
//! - Max line length: 200 bytes
//!
//! # Example
//!
//! ```rust
//! use diffguard_testkit::diff_builder::DiffBuilder;
//!
//! let diff = DiffBuilder::new()
//!     .file("src/lib.rs")
//!         .hunk(1, 1, 1, 2)
//!             .context("fn existing() {}")
//!             .add_line("fn new_function() {}")
//!             .done()
//!         .done()
//!     .build();
//!
//! assert!(diff.contains("+fn new_function() {}"));
//! ```

use crate::arb::{MAX_FILES, MAX_HUNKS_PER_FILE, MAX_LINE_LENGTH, MAX_LINES_PER_HUNK};

/// A builder for constructing unified diff strings.
#[derive(Debug, Clone, Default)]
pub struct DiffBuilder {
    files: Vec<FileBuilder>,
}

impl DiffBuilder {
    /// Create a new empty diff builder.
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Add a file to the diff and return a file builder.
    ///
    /// # Panics
    ///
    /// Panics if MAX_FILES would be exceeded.
    pub fn file(self, path: &str) -> FileBuilderInProgress {
        assert!(
            self.files.len() < MAX_FILES,
            "Cannot add more than {} files to a diff",
            MAX_FILES
        );
        FileBuilderInProgress {
            diff_builder: self,
            file_builder: FileBuilder::new(path),
        }
    }

    /// Add a pre-built file to the diff.
    pub fn add_file(mut self, file: FileBuilder) -> Self {
        assert!(
            self.files.len() < MAX_FILES,
            "Cannot add more than {} files to a diff",
            MAX_FILES
        );
        self.files.push(file);
        self
    }

    /// Build the complete diff string.
    pub fn build(self) -> String {
        self.files
            .iter()
            .map(|f| f.build())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Build with a specific scope for testing.
    pub fn build_for_scope(self, _scope: diffguard_types::Scope) -> String {
        self.build()
    }
}

/// Helper struct for building a file within a diff.
#[derive(Debug)]
pub struct FileBuilderInProgress {
    diff_builder: DiffBuilder,
    file_builder: FileBuilder,
}

impl FileBuilderInProgress {
    /// Add a hunk to the file.
    pub fn hunk(
        self,
        old_start: u32,
        old_count: u32,
        new_start: u32,
        new_count: u32,
    ) -> HunkBuilderInProgress {
        HunkBuilderInProgress {
            file_in_progress: self,
            hunk_builder: HunkBuilder::new(old_start, old_count, new_start, new_count),
        }
    }

    /// Mark as a binary file.
    pub fn binary(mut self) -> Self {
        self.file_builder = self.file_builder.binary();
        self
    }

    /// Mark as a deleted file.
    pub fn deleted(mut self) -> Self {
        self.file_builder = self.file_builder.deleted();
        self
    }

    /// Mark as a new file.
    pub fn new_file(mut self) -> Self {
        self.file_builder = self.file_builder.new_file();
        self
    }

    /// Mark as a mode-only change.
    pub fn mode_change(mut self, old_mode: &str, new_mode: &str) -> Self {
        self.file_builder = self.file_builder.mode_change(old_mode, new_mode);
        self
    }

    /// Mark as a rename.
    pub fn rename_from(mut self, old_path: &str) -> Self {
        self.file_builder = self.file_builder.rename_from(old_path);
        self
    }

    /// Finish this file and return to the diff builder.
    pub fn done(mut self) -> DiffBuilder {
        self.diff_builder.files.push(self.file_builder);
        self.diff_builder
    }
}

/// Helper struct for building a hunk within a file.
#[derive(Debug)]
pub struct HunkBuilderInProgress {
    file_in_progress: FileBuilderInProgress,
    hunk_builder: HunkBuilder,
}

impl HunkBuilderInProgress {
    /// Add a context line (unchanged).
    pub fn context(mut self, content: &str) -> Self {
        self.hunk_builder = self.hunk_builder.context(content);
        self
    }

    /// Add an added line.
    pub fn add_line(mut self, content: &str) -> Self {
        self.hunk_builder = self.hunk_builder.add_line(content);
        self
    }

    /// Add a removed line.
    pub fn remove(mut self, content: &str) -> Self {
        self.hunk_builder = self.hunk_builder.remove(content);
        self
    }

    /// Finish this hunk and return to the file builder.
    pub fn done(mut self) -> FileBuilderInProgress {
        self.file_in_progress.file_builder = self
            .file_in_progress
            .file_builder
            .add_hunk(self.hunk_builder);
        self.file_in_progress
    }
}

/// A builder for a single file in a diff.
#[derive(Debug, Clone)]
pub struct FileBuilder {
    path: String,
    old_path: Option<String>,
    hunks: Vec<HunkBuilder>,
    is_binary: bool,
    is_deleted: bool,
    is_new_file: bool,
    old_mode: Option<String>,
    new_mode: Option<String>,
}

impl FileBuilder {
    /// Create a new file builder with the given path.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            old_path: None,
            hunks: Vec::new(),
            is_binary: false,
            is_deleted: false,
            is_new_file: false,
            old_mode: None,
            new_mode: None,
        }
    }

    /// Mark this file as binary.
    pub fn binary(mut self) -> Self {
        self.is_binary = true;
        self
    }

    /// Mark this file as deleted.
    pub fn deleted(mut self) -> Self {
        self.is_deleted = true;
        self
    }

    /// Mark this file as new.
    pub fn new_file(mut self) -> Self {
        self.is_new_file = true;
        self
    }

    /// Mark this as a mode-only change.
    pub fn mode_change(mut self, old_mode: &str, new_mode: &str) -> Self {
        self.old_mode = Some(old_mode.to_string());
        self.new_mode = Some(new_mode.to_string());
        self
    }

    /// Set the old path for a rename.
    pub fn rename_from(mut self, old_path: &str) -> Self {
        self.old_path = Some(old_path.to_string());
        self
    }

    /// Add a hunk to this file.
    ///
    /// # Panics
    ///
    /// Panics if MAX_HUNKS_PER_FILE would be exceeded.
    pub fn add_hunk(mut self, hunk: HunkBuilder) -> Self {
        assert!(
            self.hunks.len() < MAX_HUNKS_PER_FILE,
            "Cannot add more than {} hunks to a file",
            MAX_HUNKS_PER_FILE
        );
        self.hunks.push(hunk);
        self
    }

    /// Build the diff output for this file.
    pub fn build(&self) -> String {
        let mut lines = Vec::new();

        // Determine the "a" and "b" paths
        let a_path = self.old_path.as_deref().unwrap_or(&self.path);
        let b_path = &self.path;

        // Git diff header
        lines.push(format!("diff --git a/{} b/{}", a_path, b_path));

        // Handle special cases
        if let (Some(old_mode), Some(new_mode)) = (&self.old_mode, &self.new_mode) {
            lines.push(format!("old mode {}", old_mode));
            lines.push(format!("new mode {}", new_mode));
            return lines.join("\n");
        }

        if self.is_deleted {
            lines.push("deleted file mode 100644".to_string());
            lines.push("index 1111111..0000000".to_string());
            lines.push(format!("--- a/{}", a_path));
            lines.push("+++ /dev/null".to_string());
            // Add the hunks
            for hunk in &self.hunks {
                lines.push(hunk.build());
            }
            return lines.join("\n");
        }

        if self.is_new_file {
            lines.push("new file mode 100644".to_string());
        }

        lines.push("index 0000000..1111111 100644".to_string());

        if self.is_binary {
            lines.push(format!("Binary files a/{} and b/{} differ", a_path, b_path));
            return lines.join("\n");
        }

        // Handle renames
        if self.old_path.is_some() {
            lines.push("similarity index 90%".to_string());
            lines.push(format!("rename from {}", a_path));
            lines.push(format!("rename to {}", b_path));
        }

        // File markers
        if self.is_new_file {
            lines.push("--- /dev/null".to_string());
        } else {
            lines.push(format!("--- a/{}", a_path));
        }
        lines.push(format!("+++ b/{}", b_path));

        // Add the hunks
        for hunk in &self.hunks {
            lines.push(hunk.build());
        }

        lines.join("\n")
    }
}

/// A builder for a hunk within a file diff.
#[derive(Debug, Clone)]
pub struct HunkBuilder {
    old_start: u32,
    old_count: u32,
    new_start: u32,
    new_count: u32,
    lines: Vec<HunkLine>,
}

#[derive(Debug, Clone)]
enum HunkLine {
    Context(String),
    Add(String),
    Remove(String),
}

impl HunkBuilder {
    /// Create a new hunk builder.
    pub fn new(old_start: u32, old_count: u32, new_start: u32, new_count: u32) -> Self {
        Self {
            old_start,
            old_count,
            new_start,
            new_count,
            lines: Vec::new(),
        }
    }

    /// Create a hunk for adding lines to the end of a file.
    pub fn for_additions(start_line: u32, count: u32) -> Self {
        Self::new(start_line.saturating_sub(1), 1, start_line, count + 1)
    }

    /// Add a context line.
    ///
    /// # Panics
    ///
    /// Panics if MAX_LINES_PER_HUNK would be exceeded.
    pub fn context(mut self, content: &str) -> Self {
        self.check_line_limits(content);
        self.lines.push(HunkLine::Context(content.to_string()));
        self
    }

    /// Add an added line.
    ///
    /// # Panics
    ///
    /// Panics if MAX_LINES_PER_HUNK would be exceeded.
    pub fn add_line(mut self, content: &str) -> Self {
        self.check_line_limits(content);
        self.lines.push(HunkLine::Add(content.to_string()));
        self
    }

    /// Add a removed line.
    ///
    /// # Panics
    ///
    /// Panics if MAX_LINES_PER_HUNK would be exceeded.
    pub fn remove(mut self, content: &str) -> Self {
        self.check_line_limits(content);
        self.lines.push(HunkLine::Remove(content.to_string()));
        self
    }

    /// Add multiple added lines.
    pub fn add_lines(mut self, lines: &[&str]) -> Self {
        for line in lines {
            self = self.add_line(line);
        }
        self
    }

    /// Add multiple removed lines.
    pub fn remove_lines(mut self, lines: &[&str]) -> Self {
        for line in lines {
            self = self.remove(line);
        }
        self
    }

    fn check_line_limits(&self, content: &str) {
        assert!(
            self.lines.len() < MAX_LINES_PER_HUNK,
            "Cannot add more than {} lines to a hunk",
            MAX_LINES_PER_HUNK
        );
        assert!(
            content.len() <= MAX_LINE_LENGTH,
            "Line content cannot exceed {} bytes",
            MAX_LINE_LENGTH
        );
    }

    /// Build the hunk output.
    pub fn build(&self) -> String {
        let mut output = Vec::new();

        // Hunk header
        output.push(format!(
            "@@ -{},{} +{},{} @@",
            self.old_start, self.old_count, self.new_start, self.new_count
        ));

        // Lines
        for line in &self.lines {
            match line {
                HunkLine::Context(content) => output.push(format!(" {}", content)),
                HunkLine::Add(content) => output.push(format!("+{}", content)),
                HunkLine::Remove(content) => output.push(format!("-{}", content)),
            }
        }

        output.join("\n")
    }
}

/// A generated diff with metadata for testing.
#[derive(Debug, Clone)]
pub struct GeneratedDiff {
    /// The full diff text.
    pub text: String,
    /// Expected number of files.
    pub expected_files: usize,
    /// Expected number of added lines (when using Scope::Added).
    pub expected_added_lines: usize,
    /// Expected number of changed lines (when using Scope::Changed).
    pub expected_changed_lines: usize,
    /// Paths of files in the diff.
    pub file_paths: Vec<String>,
}

impl GeneratedDiff {
    /// Create a simple diff with added lines.
    pub fn with_additions(path: &str, lines: &[&str]) -> Self {
        let diff = DiffBuilder::new()
            .file(path)
            .hunk(0, 0, 1, lines.len() as u32)
            .add_lines_from_slice(lines)
            .done()
            .done()
            .build();

        Self {
            text: diff,
            expected_files: 1,
            expected_added_lines: lines.len(),
            expected_changed_lines: 0,
            file_paths: vec![path.to_string()],
        }
    }

    /// Create a diff with changed lines (removed + added).
    pub fn with_changes(path: &str, removed: &[&str], added: &[&str]) -> Self {
        let mut hunk = HunkBuilder::new(1, removed.len() as u32, 1, added.len() as u32);
        for line in removed {
            hunk = hunk.remove(line);
        }
        for line in added {
            hunk = hunk.add_line(line);
        }

        let diff = DiffBuilder::new()
            .file(path)
            .add_hunk_directly(hunk)
            .done()
            .build();

        Self {
            text: diff,
            expected_files: 1,
            expected_added_lines: added.len(),
            expected_changed_lines: added.len(),
            file_paths: vec![path.to_string()],
        }
    }

    /// Create a binary file diff.
    pub fn binary(path: &str) -> Self {
        let diff = DiffBuilder::new().file(path).binary().done().build();

        Self {
            text: diff,
            expected_files: 0,
            expected_added_lines: 0,
            expected_changed_lines: 0,
            file_paths: vec![path.to_string()],
        }
    }

    /// Create a deleted file diff.
    pub fn deleted(path: &str, removed_lines: &[&str]) -> Self {
        let mut hunk = HunkBuilder::new(1, removed_lines.len() as u32, 1, 0);
        for line in removed_lines {
            hunk = hunk.remove(line);
        }

        let file = FileBuilder::new(path).deleted().add_hunk(hunk);
        let diff = DiffBuilder::new().add_file(file).build();

        Self {
            text: diff,
            expected_files: 0, // Deleted files have no lines extracted
            expected_added_lines: 0,
            expected_changed_lines: 0,
            file_paths: vec![path.to_string()],
        }
    }

    /// Create a renamed file diff.
    pub fn renamed(old_path: &str, new_path: &str, added_lines: &[&str]) -> Self {
        let hunk = HunkBuilder::new(1, 1, 1, added_lines.len() as u32 + 1)
            .context("fn existing() {}")
            .add_lines_from_slice(added_lines);

        let file = FileBuilder::new(new_path)
            .rename_from(old_path)
            .add_hunk(hunk);
        let diff = DiffBuilder::new().add_file(file).build();

        Self {
            text: diff,
            expected_files: 1,
            expected_added_lines: added_lines.len(),
            expected_changed_lines: 0,
            file_paths: vec![new_path.to_string()],
        }
    }
}

// Extension trait to add helper methods
impl HunkBuilderInProgress {
    /// Add multiple lines at once.
    pub fn add_lines_from_slice(mut self, lines: &[&str]) -> Self {
        for line in lines {
            self = self.add_line(line);
        }
        self
    }
}

impl HunkBuilder {
    /// Add multiple lines at once.
    pub fn add_lines_from_slice(mut self, lines: &[&str]) -> Self {
        for line in lines {
            self = self.add_line(line);
        }
        self
    }
}

impl FileBuilderInProgress {
    /// Add a pre-built hunk directly.
    pub fn add_hunk_directly(mut self, hunk: HunkBuilder) -> Self {
        self.file_builder = self.file_builder.add_hunk(hunk);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_simple_addition() {
        let diff = DiffBuilder::new()
            .file("src/lib.rs")
            .hunk(1, 1, 1, 2)
            .context("fn existing() {}")
            .add_line("fn new_function() {}")
            .done()
            .done()
            .build();

        assert!(diff.contains("diff --git a/src/lib.rs b/src/lib.rs"));
        assert!(diff.contains("+fn new_function() {}"));
        assert!(diff.contains(" fn existing() {}"));
    }

    #[test]
    fn build_binary_file() {
        let diff = DiffBuilder::new().file("image.png").binary().done().build();

        assert!(diff.contains("Binary files"));
        assert!(diff.contains("differ"));
    }

    #[test]
    fn build_deleted_file() {
        let file = FileBuilder::new("old.rs").deleted().add_hunk(
            HunkBuilder::new(1, 2, 1, 0)
                .remove("fn a() {}")
                .remove("fn b() {}"),
        );

        let diff = DiffBuilder::new().add_file(file).build();

        assert!(diff.contains("deleted file mode"));
        assert!(diff.contains("-fn a() {}"));
    }

    #[test]
    fn build_renamed_file() {
        let file = FileBuilder::new("new/path.rs")
            .rename_from("old/path.rs")
            .add_hunk(
                HunkBuilder::new(1, 1, 1, 2)
                    .context("fn existing() {}")
                    .add_line("fn added() {}"),
            );

        let diff = DiffBuilder::new().add_file(file).build();

        assert!(diff.contains("rename from old/path.rs"));
        assert!(diff.contains("rename to new/path.rs"));
    }

    #[test]
    fn build_mode_change() {
        let diff = DiffBuilder::new()
            .file("script.sh")
            .mode_change("100644", "100755")
            .done()
            .build();

        assert!(diff.contains("old mode 100644"));
        assert!(diff.contains("new mode 100755"));
    }

    #[test]
    fn build_multiple_files() {
        let diff = DiffBuilder::new()
            .file("src/a.rs")
            .hunk(1, 0, 1, 1)
            .add_line("fn a() {}")
            .done()
            .done()
            .file("src/b.rs")
            .hunk(1, 0, 1, 1)
            .add_line("fn b() {}")
            .done()
            .done()
            .build();

        assert!(diff.contains("diff --git a/src/a.rs b/src/a.rs"));
        assert!(diff.contains("diff --git a/src/b.rs b/src/b.rs"));
        assert!(diff.contains("+fn a() {}"));
        assert!(diff.contains("+fn b() {}"));
    }

    #[test]
    fn generated_diff_with_additions() {
        let diff = GeneratedDiff::with_additions("src/lib.rs", &["fn a() {}", "fn b() {}"]);

        assert_eq!(diff.expected_files, 1);
        assert_eq!(diff.expected_added_lines, 2);
        assert_eq!(diff.expected_changed_lines, 0);
        assert!(diff.text.contains("+fn a() {}"));
        assert!(diff.text.contains("+fn b() {}"));
    }

    #[test]
    fn build_for_scope_delegates_to_build() {
        let diff = DiffBuilder::new()
            .file("src/lib.rs")
            .hunk(1, 0, 1, 1)
            .add_line("fn added() {}")
            .done()
            .done()
            .build_for_scope(diffguard_types::Scope::Added);

        assert!(diff.contains("+fn added() {}"));
    }

    #[test]
    fn in_progress_flags_and_remove_lines() {
        let diff = DiffBuilder::new()
            .file("old.rs")
            .deleted()
            .hunk(1, 1, 0, 0)
            .remove("fn old() {}")
            .done()
            .done()
            .build();

        assert!(diff.contains("deleted file mode"));
        assert!(diff.contains("-fn old() {}"));
    }

    #[test]
    fn in_progress_new_file_and_rename() {
        let diff_new = DiffBuilder::new()
            .file("new.rs")
            .new_file()
            .hunk(0, 0, 1, 1)
            .add_line("fn new_file() {}")
            .done()
            .done()
            .build();

        assert!(diff_new.contains("new file mode"));
        assert!(diff_new.contains("+fn new_file() {}"));

        let diff_renamed = DiffBuilder::new()
            .file("renamed.rs")
            .rename_from("old_name.rs")
            .hunk(1, 1, 1, 1)
            .context("fn existing() {}")
            .done()
            .done()
            .build();

        assert!(diff_renamed.contains("rename from old_name.rs"));
        assert!(diff_renamed.contains("rename to renamed.rs"));
    }

    #[test]
    fn generated_diff_with_changes() {
        let diff = GeneratedDiff::with_changes("src/lib.rs", &["fn old() {}"], &["fn new() {}"]);

        assert_eq!(diff.expected_files, 1);
        assert_eq!(diff.expected_added_lines, 1);
        assert_eq!(diff.expected_changed_lines, 1);
        assert!(diff.text.contains("-fn old() {}"));
        assert!(diff.text.contains("+fn new() {}"));
    }

    #[test]
    fn generated_diff_binary() {
        let diff = GeneratedDiff::binary("image.png");

        assert_eq!(diff.expected_files, 0);
        assert_eq!(diff.expected_added_lines, 0);
        assert!(diff.text.contains("Binary files"));
    }

    #[test]
    #[should_panic(expected = "Cannot add more than")]
    fn enforces_max_files() {
        let mut builder = DiffBuilder::new();
        for i in 0..=MAX_FILES {
            builder = builder.file(&format!("file{}.rs", i)).done();
        }
    }

    #[test]
    #[should_panic(expected = "Cannot add more than")]
    fn enforces_max_lines_per_hunk() {
        let mut hunk = HunkBuilder::new(1, 1, 1, 1);
        for i in 0..=MAX_LINES_PER_HUNK {
            hunk = hunk.add_line(&format!("line {}", i));
        }
    }

    #[test]
    fn hunk_new_start_in_header() {
        // Regression test: new_start should appear in the hunk header, not hardcoded +1
        let hunk = HunkBuilder::new(10, 3, 42, 5).add_line("test line");
        let output = hunk.build();

        assert!(
            output.contains("+42,"),
            "Hunk header should contain '+42,' for new_start=42, got: {}",
            output
        );
        assert!(
            output.contains("@@ -10,3 +42,5 @@"),
            "Full hunk header should be '@@ -10,3 +42,5 @@', got: {}",
            output
        );
    }

    #[test]
    fn hunk_builder_for_additions_and_batch_methods() {
        let hunk = HunkBuilder::for_additions(10, 2)
            .add_lines(&["line1", "line2"])
            .remove_lines(&["old1"]);
        let output = hunk.build();

        assert!(output.contains("@@ -9,1 +10,3 @@"));
        assert!(output.contains("+line1"));
        assert!(output.contains("+line2"));
        assert!(output.contains("-old1"));
    }

    #[test]
    fn hunk_builder_add_lines_from_slice() {
        let hunk = HunkBuilder::new(1, 0, 1, 2).add_lines_from_slice(&["a", "b"]);
        let output = hunk.build();
        assert!(output.contains("+a"));
        assert!(output.contains("+b"));
    }

    #[test]
    fn file_builder_add_hunk_directly() {
        let hunk = HunkBuilder::new(1, 0, 1, 1).add_line("fn added() {}");
        let diff = DiffBuilder::new()
            .file("src/inline.rs")
            .add_hunk_directly(hunk)
            .done()
            .build();

        assert!(diff.contains("diff --git a/src/inline.rs b/src/inline.rs"));
        assert!(diff.contains("+fn added() {}"));
    }

    #[test]
    fn generated_diff_deleted_and_renamed() {
        let deleted = GeneratedDiff::deleted("old.rs", &["fn a() {}", "fn b() {}"]);
        assert_eq!(deleted.expected_files, 0);
        assert!(deleted.text.contains("deleted file mode"));

        let renamed = GeneratedDiff::renamed("old.rs", "new.rs", &["fn added() {}"]);
        assert_eq!(renamed.expected_files, 1);
        assert_eq!(renamed.expected_added_lines, 1);
        assert!(renamed.text.contains("rename from old.rs"));
        assert!(renamed.text.contains("rename to new.rs"));
    }
}
