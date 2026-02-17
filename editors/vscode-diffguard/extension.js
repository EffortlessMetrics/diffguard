const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFile } = require("child_process");
const vscode = require("vscode");

function runDiffguard(workspacePath, output) {
  return new Promise((resolve, reject) => {
    const reportPath = path.join(os.tmpdir(), "diffguard-vscode-report.json");
    const args = ["check", "--staged", "--out", reportPath];

    execFile("diffguard", args, { cwd: workspacePath }, (error, stdout, stderr) => {
      if (stdout) {
        output.append(stdout.trimEnd());
      }
      if (stderr) {
        output.append(stderr.trimEnd());
      }

      if (error) {
        reject(error);
        return;
      }

      try {
        const receipt = JSON.parse(fs.readFileSync(reportPath, "utf8"));
        resolve(receipt);
      } catch (parseError) {
        reject(parseError);
      }
    });
  });
}

function activate(context) {
  const output = vscode.window.createOutputChannel("diffguard");

  const command = vscode.commands.registerCommand("diffguard.runCheck", async () => {
    const workspace = vscode.workspace.workspaceFolders?.[0];
    if (!workspace) {
      vscode.window.showErrorMessage("diffguard: open a workspace first");
      return;
    }

    output.clear();
    output.appendLine("Running diffguard check --staged ...");
    output.show(true);

    try {
      const receipt = await runDiffguard(workspace.uri.fsPath, output);
      const counts = receipt?.verdict?.counts || {};
      const summary = `diffguard: info=${counts.info || 0}, warn=${counts.warn || 0}, error=${counts.error || 0}`;
      output.appendLine(summary);
      vscode.window.showInformationMessage(summary);
    } catch (error) {
      const message = `diffguard failed: ${error.message || String(error)}`;
      output.appendLine(message);
      vscode.window.showErrorMessage(message);
    }
  });

  context.subscriptions.push(command);
  context.subscriptions.push(output);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
