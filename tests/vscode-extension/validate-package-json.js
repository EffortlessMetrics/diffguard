#!/usr/bin/env node
// Tests for Task 1 (npm deps) and Task 3 (manifest fields)
// These tests should FAIL against current code and PASS after implementation.

const fs = require('fs');
const { PKG_PATH, assert, section, summary } = require('./helpers');

section('package.json existence and parsing');
let pkg;
try {
  const raw = fs.readFileSync(PKG_PATH, 'utf8');
  pkg = JSON.parse(raw);
  assert(true, 'package.json exists and is valid JSON');
} catch (e) {
  assert(false, `package.json cannot be read or parsed: ${e.message}`);
  process.exit(1);
}

// --- Task 3: Version ---
section('Version (Task 3)');
assert(pkg.version === '0.2.0', `version must be "0.2.0", got "${pkg.version}"`);

// --- Task 3: Repository ---
section('Repository field (Task 3)');
assert(
  typeof pkg.repository === 'object' && pkg.repository !== null,
  'repository must be an object'
);
if (pkg.repository) {
  assert(
    pkg.repository.type === 'git',
    `repository.type must be "git", got "${pkg.repository.type}"`
  );
  assert(
    pkg.repository.url === 'https://github.com/effortlessmetrics/diffguard',
    `repository.url must point to diffguard repo, got "${pkg.repository.url}"`
  );
}

// --- Task 3: Engine ---
section('Engine constraint (Task 3)');
assert(
  pkg.engines && typeof pkg.engines.vscode === 'string',
  'engines.vscode must be a string'
);
if (pkg.engines && pkg.engines.vscode) {
  assert(
    pkg.engines.vscode.includes('1.85'),
    `engines.vscode must require ^1.85.0, got "${pkg.engines.vscode}"`
  );
}

// --- Task 1: Dependencies ---
section('Dependencies (Task 1)');
assert(
  pkg.dependencies && typeof pkg.dependencies === 'object',
  'dependencies must be an object'
);
if (pkg.dependencies) {
  assert(
    'vscode-languageclient' in pkg.dependencies,
    `vscode-languageclient must be in dependencies, found: ${Object.keys(pkg.dependencies).join(', ') || 'none'}`
  );
  if (pkg.dependencies['vscode-languageclient']) {
    const ver = pkg.dependencies['vscode-languageclient'];
    assert(
      ver.includes('9') || ver === '*' || ver.startsWith('^9') || ver.startsWith('~9') || ver.startsWith('>=9'),
      `vscode-languageclient should be v9.x, got "${ver}"`
    );
  }
}

// --- Task 1: Dev Dependencies ---
section('Dev Dependencies (Task 1)');
assert(
  pkg.devDependencies && typeof pkg.devDependencies === 'object',
  'devDependencies must be an object'
);
if (pkg.devDependencies) {
  assert(
    '@vscode/vsce' in pkg.devDependencies,
    `@vscode/vsce must be in devDependencies, found: ${Object.keys(pkg.devDependencies).join(', ') || 'none'}`
  );
}

// --- Task 3: Main entry point ---
section('Main entry point (Task 3)');
assert(
  pkg.main === './extension.js',
  `main must be "./extension.js", got "${pkg.main}"`
);

// --- Task 3: Activation events ---
section('Activation events (Task 3)');
assert(
  Array.isArray(pkg.activationEvents),
  'activationEvents must be an array'
);
if (Array.isArray(pkg.activationEvents)) {
  assert(
    pkg.activationEvents.includes('onStartupFinished'),
    `activationEvents must include "onStartupFinished", got: [${pkg.activationEvents.join(', ')}]`
  );
}

// --- Task 3: Commands ---
section('Commands (Task 3)');
const commands = pkg.contributes?.commands || [];
assert(Array.isArray(commands), 'contributes.commands must be an array');
const cmdIds = commands.map(c => c.command);
assert(
  cmdIds.includes('diffguard.explainRule'),
  `commands must include "diffguard.explainRule", found: [${cmdIds.join(', ')}]`
);
assert(
  cmdIds.includes('diffguard.reloadConfig'),
  `commands must include "diffguard.reloadConfig", found: [${cmdIds.join(', ')}]`
);
assert(
  cmdIds.includes('diffguard.showRuleUrl'),
  `commands must include "diffguard.showRuleUrl", found: [${cmdIds.join(', ')}]`
);

// Old shell-exec command should be removed (or kept as convenience per S-3)
// We check it's not the ONLY command
assert(
  cmdIds.length >= 3,
  `must have at least 3 commands (LSP commands), found ${cmdIds.length}: [${cmdIds.join(', ')}]`
);

// --- Task 3: Configuration contributions ---
section('Configuration contributions (Task 3)');
const configProps = pkg.contributes?.configuration?.properties || {};
assert(
  typeof configProps === 'object' && Object.keys(configProps).length > 0,
  'contributes.configuration.properties must be a non-empty object'
);

const requiredSettings = [
  { key: 'diffguard.serverPath', type: 'string' },
  { key: 'diffguard.configPath', type: 'string' },
  { key: 'diffguard.noDefaultRules', type: 'boolean' },
  { key: 'diffguard.maxFindings', type: 'number' },
  { key: 'diffguard.forceLanguage', type: 'string' },
];

for (const setting of requiredSettings) {
  assert(
    setting.key in configProps,
    `configuration must include "${setting.key}"`
  );
  if (configProps[setting.key]) {
    assert(
      configProps[setting.key].type === setting.type,
      `${setting.key}.type must be "${setting.type}", got "${configProps[setting.key].type}"`
    );
  }
}

// --- M-5: License field ---
section('License field (M-5)');
assert(
  typeof pkg.license === 'string' && pkg.license.length > 0,
  `license field must be a non-empty string, got "${pkg.license}"`
);

// --- Summary ---
const success = summary();
process.exit(success ? 0 : 1);
