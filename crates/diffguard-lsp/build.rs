// Build script to verify find_similar_rules has #[must_use] attribute
//
// This build script checks that the find_similar_rules function in config.rs
// has the #[must_use] attribute. If the attribute is missing, the build fails.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let config_rs_path = Path::new(&manifest_dir).join("src/config.rs");

    let config_content = fs::read_to_string(&config_rs_path).expect("Failed to read config.rs");

    // Look for the find_similar_rules function declaration and check if it has #[must_use]
    let lines: Vec<&str> = config_content.lines().collect();

    let mut has_must_use = false;
    let mut found_function = false;

    for i in 0..lines.len() {
        let line = lines[i].trim();

        // Look for the function declaration
        if line.starts_with("pub fn find_similar_rules")
            || line.starts_with("fn find_similar_rules")
        {
            found_function = true;

            // Check preceding lines for #[must_use]
            // Typically the attribute is 1-2 lines before the function
            for j in (0..i).rev() {
                let prev_line = lines[j].trim();
                if prev_line.is_empty() {
                    continue;
                }
                if prev_line == "#[must_use]" {
                    has_must_use = true;
                }
                break;
            }

            if has_must_use {
                println!("cargo:warning=find_similar_rules has #[must_use] attribute - OK");
            } else {
                println!("cargo:error=find_similar_rules is MISSING #[must_use] attribute!");
                println!(
                    "cargo:warning=This attribute prevents callers from silently discarding similarity results."
                );
                std::process::exit(1);
            }
            break;
        }
    }

    if !found_function {
        println!("cargo:warning=find_similar_rules function not found in config.rs");
    }
}
