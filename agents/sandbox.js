// agents/sandbox.js
const { Sandbox } = require('@e2b/code-interpreter');
let currentSandbox = null;

async function creerSandbox() {
  if (currentSandbox) return currentSandbox;
  console.log('🔧 Création sandbox E2B...');
  currentSandbox = await Sandbox.create({
    apiKey: process.env.E2B_API_KEY,
    timeoutMs: 1000 * 60 * 30,
  });
  console.log(`✅ Sandbox créée : ${currentSandbox.sandboxId}`);
  return currentSandbox;
}

async function executerCommande(commande, timeout = 30000) {
  try {
    const sandbox = await creerSandbox();
    const result = await sandbox.commands.run(commande, { timeoutMs: timeout });
    return { success: result.exitCode === 0, stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode };
  } catch (error) {
    return { success: false, stdout: '', stderr: error.message, exitCode: -1 };
  }
}

async function fermerSandbox() {
  if (currentSandbox) {
    await currentSandbox.kill();
    currentSandbox = null;
    console.log('🔒 Sandbox fermée');
  }
}

module.exports = { creerSandbox, executerCommande, fermerSandbox };
