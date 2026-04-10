# Test Output for work-93f8df2f
# Branch: feat/work-93f8df2f/xml-output-escape-xml-control-chars
# Package: diffguard-core

```
Finished `test` profile [unoptimized + debuginfo] target(s) in 0.16s
     Running unittests src/lib.rs (target/debug/deps/diffguard_core-eb54202daf525fcb)
     Running tests/properties.rs (target/debug/deps/properties-0043aa4d449e60f8)
     Running tests/snapshot_tests.rs (target/debug/deps/snapshot_tests-69921491f58785ae)
     Running tests/test_checkstyle.rs (target/debug/deps/test_checkstyle-d70fd656d6f612db)
     Running tests/test_gitlab_quality.rs (target/debug/deps/test_gitlab_quality-6a3f0d36436d66ee)
   Doc-tests diffguard_core


running 9 tests
test snapshot_checkstyle_deterministic ... ok
test snapshot_checkstyle_empty ... ok
test snapshot_checkstyle_no_column ... ok
test snapshot_checkstyle_all_severities ... ok
test snapshot_checkstyle_single_finding ... ok
test snapshot_checkstyle_multiple_files ... ok
test snapshot_checkstyle_multiple_findings_same_file ... ok
test snapshot_checkstyle_xml_declaration ... ok
test snapshot_checkstyle_special_chars ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s


running 5 tests
test snapshot_gitlab_quality_prettyprinted ... ok
test snapshot_gitlab_quality_fingerprint_deterministic ... ok
test snapshot_gitlab_quality_empty ... ok
test snapshot_gitlab_quality_single_finding ... ok
test snapshot_gitlab_quality_all_severities ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Summary
- Total tests: 14 passed
- Failures: 0 failed
- Output contains "passed" and "0 failed": YES