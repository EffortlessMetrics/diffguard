# Green Test Output for diffguard-bench

## Test Command
```
cargo test -p diffguard-bench
```

## Output
```
warning: unused imports: `Finding` and `Severity`
   --> bench/fixtures.rs:196:33
    |
196 |         CheckReceipt, DiffMeta, Finding, Severity, TimingMetrics, ToolMeta, Verdict, VerdictCounts,
    |                                 ^^^^^^^  ^^^^^^^^
    |
    = note: `#[warn(unused_variables)]` on by default

warning: unused variable: `num_findings`
   --> bench/fixtures.rs:192:5
    |
192 |     num_findings: usize,
    |     ^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_num_findings`
    |
    = note: `#[warn(unused_variables)]` on by default

warning: `diffguard-bench` (lib test) generated 2 warnings (run `cargo fix --lib -p diffguard-bench --tests` to apply 2 suggestions)
warning: `diffguard-bench` (lib) generated 2 warnings (2 duplicates)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.56s
     Running unittests lib.rs (target/debug/deps/diffguard_bench-76a383128f8afb89)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests diffguard_bench

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Workspace Test Results
```
cargo test --workspace
...
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Summary
- **result**: passed
- **0 failed**
- Warnings are pre-existing and unrelated to documentation changes
