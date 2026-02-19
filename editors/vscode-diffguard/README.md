# diffguard VS Code Extension (Basic)

This is a basic extension scaffold that adds one command:

- `diffguard: Run Staged Check`

It runs:

```bash
diffguard check --staged --out <temp-report-path>
```

and shows a summary notification with finding counts.

## Development

1. Open this folder in VS Code.
2. Press `F5` to launch an Extension Development Host.
3. Run `diffguard: Run Staged Check` from the Command Palette.

The extension expects `diffguard` to be available on `PATH`.
