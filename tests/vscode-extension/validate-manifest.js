#!/usr/bin/env node
// Tests for manifest completeness: all required VS Code extension fields
// Should FAIL against current incomplete manifest, PASS after Task 3 implementation.

const fs = require('fs');
const { PKG_PATH, assert, section, summary } = require('./helpers');

section('package.json existence');
let pkg;
try {
  const raw = fs.readFileSync(PKG_PATH, 'utf8');
  pkg = JSON.parse(raw);
  assert(true, 'package.json exists and is valid JSON');
} catch (e) {
  assert(false, `package.json cannot be read or parsed: ${e.message}`);
  process.exit(1);
}

// --- Required top-level fields ---
section('Required top-level fields');
const requiredFields = ['name', 'displayName', 'description', 'version', 'publisher', 'engines', 'categories', 'main', 'contributes'];
for (const field of requiredFields) {
  assert(field in pkg, `must have "${field}" field`);
}

// --- Categories ---
section('Categories');
assert(
  Array.isArray(pkg.categories) && pkg.categories.length > 0,
  'categories must be a non-empty array'
);
if (Array.isArray(pkg.categories)) {
  assert(
    pkg.categories.includes('Linters'),
    'categories must include "Linters"'
  );
}

// --- Contributes completeness ---
section('Contributes completeness');
assert(
  pkg.contributes && typeof pkg.contributes === 'object',
  'contributes must be an object'
);
if (pkg.contributes) {
  assert(
    Array.isArray(pkg.contributes.commands),
    'contributes.commands must be an array'
  );
  assert(
    pkg.contributes.configuration && typeof pkg.contributes.configuration === 'object',
    'contributes.configuration must be an object'
  );
  assert(
    pkg.contributes.configuration && pkg.contributes.configuration.properties && typeof pkg.contributes.configuration.properties === 'object',
    'contributes.configuration.properties must be an object'
  );
}

// --- Configuration section title ---
section('Configuration section');
if (pkg.contributes?.configuration) {
  // title or $title is optional but nice to have
  assert(
    typeof pkg.contributes.configuration === 'object',
    'configuration section must be present'
  );
}

// --- Command structure validation ---
section('Command structure');
const commands = pkg.contributes?.commands || [];
for (const cmd of commands) {
  assert(
    typeof cmd.command === 'string' && cmd.command.startsWith('diffguard.'),
    `command id must start with "diffguard.", got "${cmd.command}"`
  );
  assert(
    typeof cmd.title === 'string' && cmd.title.length > 0,
    `command "${cmd.command}" must have a non-empty title`
  );
}

// --- Setting structure validation ---
section('Setting structure');
const props = pkg.contributes?.configuration?.properties || {};
for (const [key, spec] of Object.entries(props)) {
  assert(
    typeof spec.type === 'string',
    `setting "${key}" must have a type`
  );
  assert(
    'default' in spec,
    `setting "${key}" must have a default value`
  );
  assert(
    typeof spec.description === 'string' && spec.description.length > 0,
    `setting "${key}" must have a description`
  );
}

// --- Summary ---
const success = summary();
process.exit(success ? 0 : 1);
