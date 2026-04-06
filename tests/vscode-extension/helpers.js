const path = require('path');

const EXT_DIR = path.resolve(__dirname, '../../editors/vscode-diffguard');
const PKG_PATH = path.join(EXT_DIR, 'package.json');
const EXT_PATH = path.join(EXT_DIR, 'extension.js');

let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, message) {
  if (condition) {
    passed++;
  } else {
    failed++;
    failures.push(message);
    console.log(`  FAIL: ${message}`);
  }
}

function section(name) {
  console.log(`\n=== ${name} ===`);
}

function summary() {
  console.log('\n' + '='.repeat(50));
  console.log(`RESULTS: ${passed} passed, ${failed} failed`);
  if (failures.length > 0) {
    console.log('\nFailures:');
    failures.forEach((f, i) => console.log(`  ${i + 1}. ${f}`));
  }
  console.log('='.repeat(50));
  return failed === 0;
}

module.exports = { EXT_DIR, PKG_PATH, EXT_PATH, assert, section, summary };
