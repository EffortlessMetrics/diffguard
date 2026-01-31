#![no_main]

use libfuzzer_sys::fuzz_target;

use diffguard_diff::parse_unified_diff;
use diffguard_types::Scope;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = parse_unified_diff(&s, Scope::Added);
    let _ = parse_unified_diff(&s, Scope::Changed);
});
