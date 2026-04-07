#!/usr/bin/env node
// Tests for required files in the extension directory
// Tests Tasks 4, 5, 7 (LICENSE, .vscodeignore, CHANGELOG)

const fs = require('fs');
const path = require('path');
const { EXT_DIR, assert, section, summary } = require('./helpers');

section('LICENSE file (Task 4, M-6)');
const licensePath = path.join(EXT_DIR, 'LICENSE');
assert(fs.existsSync(licensePath), 'LICENSE file must exist');
if (fs.existsSync(licensePath)) {
  const content = fs.readFileSync(licensePath, 'utf8');
  assert(content.length > 100, 'LICENSE must contain license text (not empty)');
  assert(
    /MIT|Apache/i.test(content),
    'LICENSE must contain MIT or Apache license text'
  );
}

section('CHANGELOG.md (Task 7, S-5)');
const changelogPath = path.join(EXT_DIR, 'CHANGELOG.md');
assert(fs.existsSync(changelogPath), 'CHANGELOG.md must exist');
if (fs.existsSync(changelogPath)) {
  const content = fs.readFileSync(changelogPath, 'utf8');
  assert(content.length > 10, 'CHANGELOG.md must not be empty');
  assert(
    /0\.2\.0|v0\.2\.0/i.test(content),
    'CHANGELOG.md must contain a v0.2.0 entry'
  );
  assert(
    /lsp|language server|LSP/i.test(content),
    'CHANGELOG.md must mention LSP integration'
  );
}

section('.vscodeignore (Task 5, S-4)');
const vscodeignorePath = path.join(EXT_DIR, '.vscodeignore');
assert(fs.existsSync(vscodeignorePath), '.vscodeignore must exist');
if (fs.existsSync(vscodeignorePath)) {
  const content = fs.readFileSync(vscodeignorePath, 'utf8');
  assert(
    /\.vscode\//.test(content),
    '.vscodeignore must exclude .vscode/'
  );
  assert(
    /\.gitignore/.test(content),
    '.vscodeignore must exclude .gitignore'
  );
  assert(
    /\.vsix/.test(content),
    '.vscodeignore must exclude *.vsix files'
  );
}

section('README.md (Task 7)');
const readmePath = path.join(EXT_DIR, 'README.md');
assert(fs.existsSync(readmePath), 'README.md must exist');
if (fs.existsSync(readmePath)) {
  const content = fs.readFileSync(readmePath, 'utf8');
  assert(content.length > 100, 'README.md must have meaningful content');
  assert(
    /diffguard-lsp|diffguard\.serverPath/.test(content),
    'README.md must mention diffguard-lsp binary or serverPath setting'
  );
}

section('package-lock.json (Task 1)');
const lockPath = path.join(EXT_DIR, 'package-lock.json');
assert(fs.existsSync(lockPath), 'package-lock.json must exist');
if (fs.existsSync(lockPath)) {
  try {
    const raw = fs.readFileSync(lockPath, 'utf8');
    const lock = JSON.parse(raw);
    assert(
      lock.name === 'diffguard-vscode' || lock.lockfileVersion,
      'package-lock.json must be a valid lockfile'
    );
  } catch (e) {
    assert(false, `package-lock.json must be valid JSON: ${e.message}`);
  }
}

// --- Summary ---
const success = summary();
process.exit(success ? 0 : 1);
