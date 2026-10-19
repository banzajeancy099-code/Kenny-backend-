// agents/sandbox.js
const { Sandbox } = require('@e2b/code-interpreter');
let currentSandbox = null;

async function creerSandbox() {
  if (currentSandbox) {
    // Vérifier si la sandbox est encore connectée, sinon la reconnecter
    try {
      const info = await currentSandbox.getInfo();
      if (info.state === 'running') return currentSandbox;
    } catch (e) {
      // La sandbox est en pause ou morte, on la reconnecte
    }
  }
  
  console.log('🔧 Création/Reconnexion sandbox E2B...');
  
  // On crée avec un timeout long (1h max pour le plan gratuit)
  // ET on active le cycle de vie "pause + auto-resume"
  currentSandbox = await Sandbox.create({
    apiKey: process.env.E2B_API_KEY,
    timeoutMs: 1000 * 60 * 60, // 1 heure (max du plan Hobby)
    lifecycle: {
      onTimeout: 'pause',      // Au lieu de tuer, on met en pause
      autoResume: true,        // Réveil auto quand on envoie une commande
    },
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
    // Si la sandbox est morte, on réessaie une fois
    if (error.message.includes('not found') || error.message.includes('deadline')) {
      console.log('⚠️ Sandbox perdue, recréation...');
      currentSandbox = null;
      try {
        const sandbox = await creerSandbox();
        const result = await sandbox.commands.run(commande, { timeoutMs: timeout });
        return { success: result.exitCode === 0, stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode };
      } catch (e) {
        return { success: false, stdout: '', stderr: e.message, exitCode: -1 };
      }
    }
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
