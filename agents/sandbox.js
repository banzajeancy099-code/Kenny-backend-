// agents/sandbox.js
const { Sandbox } = require('@e2b/code-interpreter');

let currentSandbox = null;

// Répertoire racine par défaut de E2B code-interpreter
const ROOT = '/home/user';

// ============================================
// 🔧 CRÉATION / RECONNEXION
// ============================================
async function creerSandbox() {
  if (currentSandbox) {
    try {
      const info = await currentSandbox.getInfo();
      if (info.state === 'running') return currentSandbox;
      // Sandbox en pause → on tente de la reprendre
      if (info.state === 'paused') {
        console.log('⏸️ Sandbox en pause, tentative de reprise...');
        try {
          await currentSandbox.commands.run('echo resume', { timeoutMs: 10000 });
          console.log('▶️ Sandbox reprise avec succès');
          return currentSandbox;
        } catch (e) {
          console.log('⚠️ Reprise échouée:', e.message);
          currentSandbox = null;
        }
      }
    } catch (e) {
      // Sandbox morte ou injoignable → on recrée
      console.log('⚠️ getInfo échoué:', e.message);
      currentSandbox = null;
    }
  }

  console.log('🔧 Création sandbox E2B...');

  currentSandbox = await Sandbox.create({
    apiKey: process.env.E2B_API_KEY,
    timeoutMs: 1000 * 60 * 60, // 1h
    lifecycle: {
      onTimeout: 'pause',
      autoResume: true
    }
  });

  console.log(`✅ Sandbox créée : ${currentSandbox.sandboxId}`);

  // S'assurer que le répertoire racine existe
  try {
    await currentSandbox.commands.run(`mkdir -p ${ROOT}`, { timeoutMs: 10000 });
  } catch (e) {
    console.log('⚠️ mkdir ROOT échoué:', e.message);
  }

  return currentSandbox;
}

// ============================================
// 📤 UPLOAD DES FICHIERS DANS LA SANDBOX
// ============================================
async function uploaderDansSandbox(blocks) {
  if (!Array.isArray(blocks) || blocks.length === 0) {
    throw new Error('uploaderDansSandbox : aucun fichier à uploader');
  }

  const sb = await creerSandbox();
  console.log(`📤 Upload de ${blocks.length} fichiers dans la sandbox...`);

  // 1) Créer tous les sous-dossiers nécessaires (mkdir -p)
  const dirs = new Set();
  for (const b of blocks) {
    if (!b || !b.nom) continue;
    const parts = b.nom.split('/').filter(Boolean);
    if (parts.length > 1) {
      let acc = '';
      for (let i = 0; i < parts.length - 1; i++) {
        acc += (acc ? '/' : '') + parts[i];
        dirs.add(acc);
      }
    }
  }

  if (dirs.size > 0) {
    const dirList = [...dirs].map(d => `'${ROOT}/${d}'`).join(' ');
    const mk = await sb.commands.run(`mkdir -p ${dirList}`, { timeoutMs: 15000 });
    if (mk.exitCode !== 0) {
      throw new Error(`mkdir échoué : ${mk.stderr || mk.stdout || 'exitCode=' + mk.exitCode}`);
    }
    console.log(`📁 Dossiers créés : ${[...dirs].join(', ')}`);
  }

  // 2) Écrire chaque fichier via l'API filesystem (chemin ABSOLU)
  for (const b of blocks) {
    if (!b || !b.nom) continue;
    const absPath = `${ROOT}/${b.nom}`;
    try {
      // Certaines versions exposent files.write, d'autres filesystem.write
      if (sb.files && typeof sb.files.write === 'function') {
        await sb.files.write(absPath, b.contenu ?? '');
      } else if (sb.filesystem && typeof sb.filesystem.write === 'function') {
        await sb.filesystem.write(absPath, b.contenu ?? '');
      } else {
        throw new Error('API filesystem indisponible sur la sandbox');
      }
    } catch (e) {
      throw new Error(`Échec écriture ${absPath} : ${e.message}`);
    }
  }

  // 3) Vérification : lister les fichiers écrits
  try {
    const check = await sb.commands.run(
      `find ${ROOT} -type f -not -path '*/node_modules/*' -not -path '*/.cache/*' | sort`,
      { timeoutMs: 10000 }
    );
    console.log('[SANDBOX] Fichiers présents :\n' + (check.stdout || '(vide)'));
  } catch (e) {
    console.log('⚠️ Vérification fichiers échouée:', e.message);
  }

  console.log(`✅ ${blocks.length} fichiers uploadés dans la sandbox`);
  return sb;
}

// Alias pour compatibilité avec l'ancien nom (typo)
const aderDansSandbox = uploaderDansSandbox;

// ============================================
// ▶️ EXÉCUTION DE COMMANDE
// ============================================
async function executerCommande(commande, timeout = 30000) {
  try {
    const sandbox = await creerSandbox();
    const result = await sandbox.commands.run(commande, { timeoutMs: timeout });
    return {
      success: result.exitCode === 0,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      exitCode: result.exitCode
    };
  } catch (error) {
    // Sandbox morte → recréation + retry une fois
    const msg = error && error.message ? error.message : String(error);
    if (msg.includes('not found') || msg.includes('deadline') || msg.includes('timed out')) {
      console.log('⚠️ Sandbox perdue, recréation...');
      currentSandbox = null;
      try {
        const sandbox = await creerSandbox();
        const result = await sandbox.commands.run(commande, { timeoutMs: timeout });
        return {
          success: result.exitCode === 0,
          stdout: result.stdout || '',
          stderr: result.stderr || '',
          exitCode: result.exitCode
        };
      } catch (e) {
        return { success: false, stdout: '', stderr: e.message, exitCode: -1 };
      }
    }
    return { success: false, stdout: '', stderr: msg, exitCode: -1 };
  }
}

// ============================================
// 🔒 FERMETURE
// ============================================
async function fermerSandbox() {
  if (currentSandbox) {
    try {
      await currentSandbox.kill();
    } catch (e) {
      console.log('⚠️ kill sandbox échoué:', e.message);
    }
    currentSandbox = null;
    console.log('🔒 Sandbox fermée');
  }
}

module.exports = {
  creerSandbox,
  uploaderDansSandbox,
  aderDansSandbox,   // alias pour compat
  executerCommande,
  fermerSandbox
};
