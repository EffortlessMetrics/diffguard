#!/usr/bin/env node
// Runs all validation tests and reports overall status.

const { execSync } = require('child_process');
const path = require('path');

const tests = [
  'validate-package-json.js',
  'validate-extension-js.js',
  'validate-manifest.js',
  'validate-files.js',
  'validate-edge-cases.js',
];

console.log('='.repeat(60));
console.log('DiffGuard VS Code Extension - Red Tests');
console.log('These tests define "done" for the LSP client rewrite.');
console.log('='.repeat(60));

let totalPassed = 0;
let totalFailed = 0;

for (const test of tests) {
  const testPath = path.join(__dirname, test);
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Running: ${test}`);
  console.log('='.repeat(60));
  try {
    execSync(`node "${testPath}"`, { stdio: 'inherit', cwd: __dirname });
    totalPassed++;
  } catch (e) {
    totalFailed++;
  }
}

console.log('\n' + '='.repeat(60));
console.log(`OVERALL: ${totalPassed}/${tests.length} test suites passed`);
if (totalFailed > 0) {
  console.log(`${totalFailed} test suite(s) FAILED - implementation is not complete`);
} else {
  console.log('All test suites PASSED - implementation is complete!');
}
console.log('='.repeat(60));

process.exit(totalFailed > 0 ? 1 : 0);
