#![no_main]

use libfuzzer_sys::fuzz_target;

use diffguard_domain::{PreprocessOptions, Preprocessor};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    let mut p1 = Preprocessor::new(PreprocessOptions::comments_only());
    let mut p2 = Preprocessor::new(PreprocessOptions::strings_only());
    let mut p3 = Preprocessor::new(PreprocessOptions::comments_and_strings());

    // Process multiple lines to exercise multi-line state.
    for line in s.lines().take(32) {
        let _ = p1.sanitize_line(line);
        let _ = p2.sanitize_line(line);
        let _ = p3.sanitize_line(line);
    }
});
