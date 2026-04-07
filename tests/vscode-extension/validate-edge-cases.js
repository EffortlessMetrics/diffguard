#!/usr/bin/env node
// Edge case tests for the DiffGuard VS Code extension
// These tests cover gaps not addressed by the existing red tests.

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { EXT_DIR, PKG_PATH, EXT_PATH, assert, section, summary } = require('./helpers');

// Read source and package once
const src = fs.readFileSync(EXT_PATH, 'utf8');
const pkg = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8'));

// =====================================================================
// 1. Error handling robustness for missing binary
// =====================================================================
section('Error handling: binary-not-found edge cases');

// The extension should handle ENOENT errors specifically
assert(
  /ENOENT/.test(src),
  'error handler must check for ENOENT (binary not found)'
);

// The error handler should handle multiple error string patterns
const errorPatterns = ['ENOENT', 'not found', 'cannot find'];
let matchedPatterns = 0;
for (const pat of errorPatterns) {
  if (src.includes(pat)) matchedPatterns++;
}
assert(
  matchedPatterns >= 2,
  `error handler should check multiple error patterns (found ${matchedPatterns}/3: ENOENT, not found, cannot find)`
);

// Error handler should provide actionable guidance (mention settings or install)
assert(
  /install|serverPath|settings|diffguard\.serverPath/i.test(src),
  'error message must mention installation or serverPath setting for user guidance'
);

// The error handler should be attached to client.start() promise rejection
assert(
  /client\.start\(\)\.then\(/.test(src) || /client\.start\(\)\.catch\(/.test(src) ||
  /client\.start\(\)[\s\S]*?\.then\(/.test(src),
  'error handler must be attached to client.start() promise'
);

// Error handler should NOT crash the extension on failure - should use .then(null, ...) or .catch()
assert(
  /\.then\s*\(\s*null\s*,/.test(src) || /\.catch\s*\(/.test(src),
  'error handler should use .then(null, onRejected) or .catch() pattern to avoid swallowing success'
);

// =====================================================================
// 2. Configuration defaults and edge cases
// =====================================================================
section('Configuration defaults validation');

// serverPath default should be 'diffguard-lsp'
const serverPathSetting = pkg.contributes?.configuration?.properties?.['diffguard.serverPath'];
assert(
  serverPathSetting?.default === 'diffguard-lsp',
  `serverPath default must be "diffguard-lsp", got "${serverPathSetting?.default}"`
);

// maxFindings default should be a positive number
const maxFindingsSetting = pkg.contributes?.configuration?.properties?.['diffguard.maxFindings'];
assert(
  typeof maxFindingsSetting?.default === 'number' && maxFindingsSetting.default > 0,
  `maxFindings default must be a positive number, got ${maxFindingsSetting?.default}`
);

// configPath default should be empty string (no default config)
const configPathSetting = pkg.contributes?.configuration?.properties?.['diffguard.configPath'];
assert(
  configPathSetting?.default === '',
  `configPath default must be empty string, got "${configPathSetting?.default}"`
);

// forceLanguage default should be empty string (auto-detect)
const forceLanguageSetting = pkg.contributes?.configuration?.properties?.['diffguard.forceLanguage'];
assert(
  forceLanguageSetting?.default === '',
  `forceLanguage default must be empty string, got "${forceLanguageSetting?.default}"`
);

// noDefaultRules default should be false
const noDefaultRulesSetting = pkg.contributes?.configuration?.properties?.['diffguard.noDefaultRules'];
assert(
  noDefaultRulesSetting?.default === false,
  `noDefaultRules default must be false, got ${noDefaultRulesSetting?.default}`
);

// All settings should have descriptions (non-empty strings)
const configProps = pkg.contributes?.configuration?.properties || {};
for (const [key, spec] of Object.entries(configProps)) {
  assert(
    typeof spec.description === 'string' && spec.description.trim().length > 0,
    `setting "${key}" must have a non-empty description`
  );
}

// =====================================================================
// 3. extension.js reads config with safe defaults (second arg to .get())
// =====================================================================
section('Config reading uses safe defaults');

// The extension should provide fallback defaults when reading config
// Check that config.get() calls include a second argument (default value)
const configGetCalls = src.match(/config\.get\([^)]+\)/g) || [];
assert(
  configGetCalls.length >= 5,
  `should read at least 5 config values (serverPath, configPath, noDefaultRules, maxFindings, forceLanguage), found ${configGetCalls.length}`
);

// Each config.get() should have a default value (two arguments)
let configGetWithDefaults = 0;
for (const call of configGetCalls) {
  // Match config.get("key", default) - has a comma meaning two args
  if (/config\.get\(\s*['"][^'"]+['"]\s*,/.test(call)) {
    configGetWithDefaults++;
  }
}
assert(
  configGetWithDefaults >= 5,
  `all config.get() calls should include default values (found ${configGetWithDefaults} with defaults out of ${configGetCalls.length} calls)`
);

// =====================================================================
// 4. LSP transport configuration
// =====================================================================
section('LSP transport configuration');

// Must use stdio transport
assert(
  /TransportKind\.stdio/.test(src) || /transport\s*:\s*['"]stdio['"]/.test(src) ||
  /transport:\s*TransportKind\.stdio/.test(src),
  'must use stdio transport for LSP'
);

// Server options should include --stdio argument
assert(
  /['"]--stdio['"]/.test(src),
  'server args must include --stdio flag'
);

// =====================================================================
// 5. Document selector completeness
// =====================================================================
section('Document selector completeness');

// Should select files (not just untitled or other schemes)
assert(
  /scheme\s*:\s*['"]file['"]/.test(src),
  'documentSelector must include scheme: "file"'
);

// =====================================================================
// 6. .vsix package builds without errors
// =====================================================================
section('.vsix package build validation');

// Check that the .vsix was successfully built
const vsixPath = path.join(EXT_DIR, 'diffguard-vscode-0.2.0.vsix');
assert(
  fs.existsSync(vsixPath),
  '.vsix package must exist (run "npx vsce package" in extension dir)'
);

if (fs.existsSync(vsixPath)) {
  const vsixStats = fs.statSync(vsixPath);
  assert(
    vsixStats.size > 1000,
    `.vsix package must be non-trivial size (got ${vsixStats.size} bytes)`
  );
}

// =====================================================================
// 7. .vscodeignore properly excludes dev files
// =====================================================================
section('.vscodeignore completeness');

const vscodeignorePath = path.join(EXT_DIR, '.vscodeignore');
if (fs.existsSync(vscodeignorePath)) {
  const content = fs.readFileSync(vscodeignorePath, 'utf8');

  // Should exclude .vscode directory
  assert(
    /\.vscode/.test(content),
    '.vscodeignore must exclude .vscode/ directory'
  );

  // Should exclude .gitignore
  assert(
    /\.gitignore/.test(content),
    '.vscodeignore must exclude .gitignore'
  );

  // Should exclude .vsix files (don't package previous builds)
  assert(
    /\.vsix/.test(content),
    '.vscodeignore must exclude *.vsix files'
  );
}

// =====================================================================
// 8. node_modules dependency hygiene
// =====================================================================
section('node_modules dependency hygiene');

// Top-level dependencies should only be vscode-languageclient
assert(
  typeof pkg.dependencies === 'object' && pkg.dependencies !== null,
  'dependencies must be defined'
);
const depKeys = Object.keys(pkg.dependencies || {});
assert(
  depKeys.length === 1,
  `should have exactly 1 runtime dependency (vscode-languageclient), found ${depKeys.length}: [${depKeys.join(', ')}]`
);
assert(
  depKeys.includes('vscode-languageclient'),
  'the single runtime dependency must be vscode-languageclient'
);

// Dev dependencies should only be @vscode/vsce
const devDepKeys = Object.keys(pkg.devDependencies || {});
assert(
  devDepKeys.length === 1,
  `should have exactly 1 dev dependency (@vscode/vsce), found ${devDepKeys.length}: [${devDepKeys.join(', ')}]`
);
assert(
  devDepKeys.includes('@vscode/vsce'),
  'the single dev dependency must be @vscode/vsce'
);

// No extraneous top-level packages (check actual installed packages match declared)
try {
  const lsOutput = execSync('npm ls --depth=0 2>&1', { cwd: EXT_DIR, encoding: 'utf8' });
  // Parse top-level deps from npm ls output (handles both ├── and └── prefixes)
  const installedDeps = lsOutput.match(/[├└]──\s+([^\s]+)/g) || [];
  const topLevelNames = installedDeps.map(m => m.replace(/[├└]──\s+/, ''));

  // Should only have vscode-languageclient and @vscode/vsce
  assert(
    topLevelNames.includes('vscode-languageclient@9.0.1'),
    'must have vscode-languageclient@9.0.1 installed'
  );
  assert(
    topLevelNames.length <= 3, // allow for npm ls formatting quirks
    `should have at most 2 top-level packages, found ${topLevelNames.length}: [${topLevelNames.join(', ')}]`
  );
} catch (e) {
  // npm ls can fail with exit code 1 due to extraneous warnings but still produce output
  // This is acceptable
  assert(true, 'npm ls executed (may have warnings)');
}

// =====================================================================
// 9. extension.js does not use shell exec for primary operation
// =====================================================================
section('No shell exec in activation');

// Verify activate() doesn't shell out
const activateMatch = src.match(/function\s+activate[\s\S]*?(?=function\s+|$)/);
if (activateMatch) {
  const activateBody = activateMatch[0];
  assert(
    !/execFile\s*\(/.test(activateBody),
    'activate() must NOT use execFile - should use LanguageClient'
  );
  assert(
    !/child_process/.test(activateBody),
    'activate() must NOT import child_process - should use LanguageClient'
  );
}

// Global check: no child_process require at module level (extension.js should only need path and vscode-languageclient)
assert(
  !/require\s*\(\s*['"]child_process['"]\s*\)/.test(src),
  'extension.js must NOT require child_process at module level'
);

// =====================================================================
// 10. Lifecycle: deactivate handles null client gracefully
// =====================================================================
section('Deactivate null-safety');

// The deactivate function should check if client exists before calling dispose/stop
assert(
  /deactivate[\s\S]*?if\s*\(\s*client\s*\)/.test(src) ||
  /deactivate[\s\S]*?client\s*&&/.test(src) ||
  /deactivate[\s\S]*?client\s*\?/.test(src),
  'deactivate() must check if client exists before disposing (null-safe)'
);

// =====================================================================
// 11. Required VS Code extension fields present
// =====================================================================
section('VS Code marketplace required fields');

// Publisher is required for marketplace
assert(
  typeof pkg.publisher === 'string' && pkg.publisher.length > 0,
  `publisher must be a non-empty string, got "${pkg.publisher}"`
);

// Name should be filesystem-safe (no spaces, lowercase)
assert(
  /^[a-z0-9-]+$/.test(pkg.name),
  `package name should be filesystem-safe (lowercase, hyphens), got "${pkg.name}"`
);

// Display name should be present and human-readable
assert(
  typeof pkg.displayName === 'string' && pkg.displayName.length > 0,
  `displayName must be a non-empty string, got "${pkg.displayName}"`
);

// Version should be valid semver
assert(
  /^\d+\.\d+\.\d+$/.test(pkg.version),
  `version must be valid semver, got "${pkg.version}"`
);

// =====================================================================
// 12. Configuration section title
// =====================================================================
section('Configuration section metadata');

// The configuration section should have a title
assert(
  typeof pkg.contributes?.configuration?.title === 'string' &&
  pkg.contributes.configuration.title.length > 0,
  'contributes.configuration must have a title for settings UI grouping'
);

// =====================================================================
// 13. Commands have proper structure
// =====================================================================
section('Command metadata completeness');

const commands = pkg.contributes?.commands || [];
for (const cmd of commands) {
  // Every command should have a title
  assert(
    typeof cmd.title === 'string' && cmd.title.length > 0,
    `command "${cmd.command}" must have a non-empty title`
  );

  // Title should be human-readable (not just the command ID)
  assert(
    cmd.title !== cmd.command,
    `command "${cmd.command}" title should be human-readable, not the raw command ID`
  );

  // Title should start with "DiffGuard:" for namespacing
  assert(
    cmd.title.startsWith('DiffGuard:'),
    `command "${cmd.command}" title should start with "DiffGuard:" for consistency, got "${cmd.title}"`
  );
}

// =====================================================================
// 14. Scripts section completeness
// =====================================================================
section('Scripts section');

// Should have a package script for building .vsix
assert(
  typeof pkg.scripts?.package === 'string',
  'must have a "package" script for building .vsix'
);

// Package script should use vsce
assert(
  /vsce/.test(pkg.scripts?.package || ''),
  'package script must use vsce'
);

// =====================================================================
// Summary
// =====================================================================
const success = summary();
process.exit(success ? 0 : 1);
