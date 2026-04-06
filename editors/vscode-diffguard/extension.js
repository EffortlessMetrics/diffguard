const path = require("path");
const vscode = require("vscode");
const {
  LanguageClient,
  TransportKind,
} = require("vscode-languageclient/node");

let client;

function activate(context) {
  const config = vscode.workspace.getConfiguration("diffguard");
  const serverPath = config.get("serverPath", "diffguard-lsp");

  const serverOptions = {
    command: serverPath,
    args: ["--stdio"],
    transport: TransportKind.stdio,
  };

  const clientOptions = {
    documentSelector: [{ scheme: "file" }],
    synchronize: {
      configurationSection: "diffguard",
    },
    initializationOptions: {
      configPath: config.get("configPath", ""),
      noDefaultRules: config.get("noDefaultRules", false),
      maxFindings: config.get("maxFindings", 100),
      forceLanguage: config.get("forceLanguage", ""),
    },
  };

  client = new LanguageClient(
    "diffguard",
    "DiffGuard Language Server",
    serverOptions,
    clientOptions
  );

  client.start().then(null, (err) => {
    if (String(err).includes("ENOENT") || String(err).includes("not found") || String(err).includes("cannot find")) {
      vscode.window.showErrorMessage(
        `DiffGuard: Language server binary "${serverPath}" not found. Please install diffguard-lsp or set diffguard.serverPath in settings.`
      );
    }
  });

  context.subscriptions.push(client);
}

function deactivate() {
  if (client) {
    return client.dispose();
  }
}

module.exports = {
  activate,
  deactivate,
};
