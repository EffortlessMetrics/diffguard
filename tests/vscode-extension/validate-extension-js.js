#!/usr/bin/env node
// Tests for Task 2: extension.js must be a proper LSP client
// These tests should FAIL against current shell-exec code and PASS after rewrite.

const fs = require('fs');
const { EXT_PATH, assert, section, summary } = require('./helpers');

section('extension.js existence');
let src;
try {
  src = fs.readFileSync(EXT_PATH, 'utf8');
  assert(true, 'extension.js exists and is readable');
} catch (e) {
  assert(false, `extension.js cannot be read: ${e.message}`);
  process.exit(1);
}

// --- Exports ---
section('Module exports');
assert(
  /module\.exports\s*=\s*\{/.test(src) || /exports\s*\.\s*(activate|deactivate)/.test(src),
  'module.exports must export activate and deactivate'
);
assert(
  /function\s+activate\s*\(/.test(src) || /const\s+activate\s*=/.test(src) || /exports\.activate\s*=/.test(src),
  'must define activate function'
);
assert(
  /function\s+deactivate\s*\(/.test(src) || /const\s+deactivate\s*=/.test(src) || /exports\.deactivate\s*=/.test(src),
  'must define deactivate function'
);

// --- LanguageClient import ---
section('LanguageClient import (M-1)');
assert(
  /require\s*\(\s*['"]vscode-languageclient['"]\s*\)/.test(src) ||
  /require\s*\(\s*['"]vscode-languageclient\/node['"]\s*\)/.test(src) ||
  /from\s+['"]vscode-languageclient['"]/.test(src),
  'must import from vscode-languageclient'
);
assert(
  /LanguageClient/.test(src),
  'must reference LanguageClient class'
);
assert(
  /ServerOptions/.test(src) || /serverOptions/.test(src),
  'must define ServerOptions'
);

// --- v9 Executable API (M-7) ---
section('v9 Executable API pattern (M-7)');
// Should NOT use the old v8 run/debug pattern
const usesOldPattern = /run\s*:\s*\{[^}]*module\s*:/.test(src) && /debug\s*:\s*\{[^}]*module\s*:/.test(src);
assert(
  !usesOldPattern,
  'must NOT use deprecated v8 run/debug module binding pattern'
);
// Should use Executable-style object with command
assert(
  /command\s*:/.test(src),
  'must define command property (Executable API)'
);

// --- Document selector (M-8) ---
section('Document selector (M-8)');
assert(
  /documentSelector/.test(src),
  'must set documentSelector'
);
assert(
  /scheme\s*:\s*['"]file['"]/.test(src),
  'documentSelector must include scheme: "file"'
);

// --- Binary discovery (M-2) ---
section('Binary discovery strategy (M-2)');
assert(
  /serverPath/.test(src),
  'must reference diffguard.serverPath setting'
);
assert(
  /diffguard-lsp/.test(src),
  'must have "diffguard-lsp" as fallback binary name'
);
// Should read from VS Code config
assert(
  /get\s*\(\s*['"]diffguard\.serverPath['"]/.test(src) ||
  /configuration\s*\.\s*get\s*\(\s*['"]diffguard\.serverPath['"]/.test(src) ||
  /config\s*\.\s*get\s*\(\s*['"]serverPath['"]/.test(src),
  'must read diffguard.serverPath from VS Code config'
);

// --- Initialization options (M-3) ---
section('Initialization options mapping (M-3)');
assert(
  /initializationOptions/.test(src),
  'must set initializationOptions'
);
const initKeys = ['configPath', 'noDefaultRules', 'maxFindings', 'forceLanguage'];
for (const key of initKeys) {
  assert(
    src.includes(key),
    `initializationOptions must include "${key}"`
  );
}

// --- Lifecycle management (M-4) ---
section('Lifecycle management (M-4)');
assert(
  /deactivate\s*\([^)]*\)\s*\{[\s\S]*?(stop|dispose)/.test(src) ||
  /deactivate\s*=\s*\(?[^)]*\)?\s*=>\s*\{[\s\S]*?(stop|dispose)/.test(src) ||
  /function\s+deactivate[\s\S]*?(stop|dispose)/.test(src),
  'deactivate() must call client.stop() or client.dispose()'
);
assert(
  /context\.subscriptions\.push/.test(src),
  'must push client to context.subscriptions for cleanup'
);

// --- Error handling (S-1, AC-5) ---
section('Error handling (AC-5)');
assert(
  /showErrorMessage/.test(src),
  'must show error notification to user'
);
assert(
  /ENOENT|not found|cannot find|install/.test(src),
  'must handle binary-not-found case with user-friendly message'
);

// --- Synchronization ---
section('LSP synchronization');
assert(
  /synchronize/.test(src),
  'must set synchronize options'
);
assert(
  /configurationSection/.test(src),
  'must set synchronize.configurationSection'
);
assert(
  /['"]diffguard['"]/.test(src),
  'configurationSection must be "diffguard"'
);

// --- Should NOT shell out for primary operation (M-1) ---
section('No shell-exec for primary operation (M-1)');
const usesExecFile = /execFile\s*\(/.test(src) || /exec\s*\(/.test(src);
if (usesExecFile) {
  // execFile/exec might be used for legacy runCheck command (S-3), but NOT as primary mechanism
  // Check it's not in activate main flow
  const activateMatch = src.match(/function\s+activate[\s\S]*?(?=function\s+|$)/);
  if (activateMatch) {
    const activateBody = activateMatch[0];
    assert(
      !/execFile\s*\(/.test(activateBody),
      'activate() must NOT use execFile - should use LanguageClient instead'
    );
  }
}

// --- Summary ---
const success = summary();
process.exit(success ? 0 : 1);
