// Vérifie qu'un nom de fichier est "sain" (pas dégénéré, pas de traversée).
// Renvoie true si le nom est utilisable, false sinon.
//
// Corrections :
// - Segments '..' uniquement (au lieu d'includes('..'))
//   → autorise 'foo..bar.py' (nom légitime), bloque '../../etc/passwd'
// - Rejette les caractères Unicode invisibles/directionnels
//   → mais autorise les accents (noms français, etc. légitimes)
// - Rejette les noms trop longs (limite filesystem typique : 255 bytes)
function nomFichierValide(nom) {
  if (typeof nom !== 'string') return false;
  if (nom.length === 0) return false;
  if (nom.length > 255) return false;
  if (nom === '.' || nom === '/' || nom === '..') return false;
  if (nom.startsWith('/')) return false;
  if (nom.endsWith('/')) return false;
  if (nom.split('/').some(seg => seg === '..')) return false;
  if (/[\x00-\x1f\u200B-\u200F\u2028-\u202F\uFEFF]/.test(nom)) return false;
  if (nom !== nom.trim()) return false;
  return true;
}
// Extrait les infos d'une CommandExitError E2B v1, si applicable.
// Renvoie null si ce n'est PAS une erreur de commande (exit ≠ 0),
// ce qui permet de distinguer "commande a échoué" de "sandbox morte".
function extraireCommandExitError(error) {
  if (!error) return null;

  const hasExitCode =
    typeof error.exitCode === 'number' ||
    typeof error.exit_code === 'number';

  const isNamedCommandExit =
    error.name === 'CommandExitError' ||
    error.constructor?.name === 'CommandExitError';

  if (!hasExitCode && !isNamedCommandExit) return null;

  return {
    exitCode: error.exitCode ?? error.exit_code ?? 1,
    stdout: error.stdout || '',
    stderr: error.stderr || error.message || ''
  };
}

// ============================================
// 🔧 CRÉATION / RECONNEXION
// ============================================
async function creerSandbox() {
  if (currentSandbox) {
    try {
      // getInfo peut pendre → timeout 5s (avec clearTimeout propre)
      let timeoutId;
      const info = await Promise.race([
        currentSandbox.getInfo(),
        new Promise((_, rej) => {
          timeoutId = setTimeout(() => rej(new Error('getInfo timeout')), 5000);
        })
      ]).finally(() => clearTimeout(timeoutId));

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
          try { await currentSandbox.kill(); } catch (_) {}
          currentSandbox = null;
        }
      } else {
        // État inattendu (expired, dead, ...) → on tue et on recrée
        console.log(`⚠️ Sandbox en état "${info.state}", kill + recréation`);
        try { await currentSandbox.kill(); } catch (_) {}
        currentSandbox = null;
      }
    } catch (e) {
      // Sandbox morte ou injoignable → on recrée
      console.log('⚠️ getInfo échoué:', e.message);
      try { await currentSandbox.kill(); } catch (_) {}
      currentSandbox = null;
    }
  }

  console.log('🔧 Création sandbox E2B...');

  currentSandbox = await Sandbox.create({
    apiKey: process.env.E2B_API_KEY,
    timeoutMs: 1000 * 60 * 60 // 1h
    // Pas de lifecycle ici — non supporté fiable en E2B v1 pour create().
    // → le sandbox est tué à expiration, pas mis en pause.
  });

  console.log(`✅ Sandbox créée : ${currentSandbox.sandboxId}`);

  // S'assurer que le répertoire racine existe.
  // Échec = sandbox inutilisable → kill + throw.
  try {
    const mk = await currentSandbox.commands.run(`mkdir -p ${ROOT}`, { timeoutMs: 10000 });
    if (mk.exitCode !== 0) {
      throw new Error(`mkdir ROOT exit ${mk.exitCode}: ${mk.stderr || mk.stdout}`);
    }
  } catch (e) {
    try { await currentSandbox.kill(); } catch (_) {}
    currentSandbox = null;
    throw new Error(`Sandbox inutilisable (mkdir ROOT échoué): ${e.message}`);
  }

  return currentSandbox;
}

// ============================================
// 💀 KILL COHÉRENT (tue + reset currentSandbox)
// ============================================
async function killSandbox(sb) {
  if (!sb) return;
  try {
    await sb.kill();
  } catch (e) {
    console.log('⚠️ kill sandbox échoué:', e.message);
  }
  if (currentSandbox === sb) {
    currentSandbox = null;
  }
}

// ============================================
// 📤 UPLOAD DES FICHIERS DANS LA SANDBOX
// ============================================
async function uploaderDansSandbox(blocks) {
  if (!Array.isArray(blocks) || blocks.length === 0) {
    throw new Error('uploaderDansSandbox : aucun fichier à uploader');
  }

  const sb = await creerSandbox();

  // Toute erreur après ce point doit kill la sandbox (fuite E2B évitée)
    try {
  // 0) Filtrer les fichiers valides AVANT le log (comptage cohérent)   
  const fichiersValides = blocks.filter(...);                        
  const fichiersRejetes = blocks.filter(b =>                          
    !b || !b.nom || !nomFichierValide(b.nom)                           
  );                                                                
                                                                          
  if (fichiersValides.length === 0) {                              
    const noms = ...                                                    
    ...                                                                  
    throw new Error(                                                     
      `uploaderDansSandbox : aucun fichier valide. ` +                   
      `Noms rejetés : ...`                                               
    );                                                                   
  }                                                                      
                                                                          
  console.log(                                                           
  `📤 Upload de ...` +                                                 
  (fichiersRejetes.length > 0                                       
    ? `...`                                                             
    : '') +                                                            
  ' dans la sandbox...'                                                
);                                                                     
    // 1) Créer tous les sous-dossiers nécessaires (mkdir -p)
    const dirs = new Set();
    for (const b of fichiersValides) {
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
      // shQuote sur chaque chemin (protection apostrophes)
      const dirList = [...dirs].map(d => shQuote(`${ROOT}/${d}`)).join(' ');
      const mk = await sb.commands.run(`mkdir -p ${dirList}`, { timeoutMs: 15000 });
      if (mk.exitCode !== 0) {
        throw new Error(`mkdir échoué : ${mk.stderr || mk.stdout || 'exitCode=' + mk.exitCode}`);
      }
      console.log(`📁 Dossiers créés : ${[...dirs].join(', ')}`);
    }

    // 2) Écrire chaque fichier via l'API filesystem (chemin ABSOLU).
    // Une seule API supportée en E2B v1 = sb.files.write.
    if (!sb.files || typeof sb.files.write !== 'function') {
      throw new Error(
        'E2B SDK invalide : sb.files.write indisponible. ' +
        'Vérifie la version de @e2b/code-interpreter.'
      );
    }

    for (const b of fichiersValides) {
      const absPath = `${ROOT}/${b.nom}`;
      try {
        await sb.files.write(absPath, b.contenu ?? '');
      } catch (e) {
        throw new Error(`Échec écriture ${absPath} : ${e.message}`);
      }
    }

    // 3) Vérification : tous les fichiers attendus sont bien présents
    const expectedCount = fichiersValides.length;
    try {
      const count = await sb.commands.run(
        `find ${ROOT} -type f -not -path '*/node_modules/*' -not -path '*/.cache/*' | wc -l`,
        { timeoutMs: 10000 }
      );
      const actual = parseInt((count.stdout || '0').trim(), 10);
      if (!Number.isFinite(actual) || actual < expectedCount) {
        const err = new Error(
          `Upload incomplet : ${actual}/${expectedCount} fichiers écrits dans la sandbox`
        );
        err.code = 'UPLOAD_INCOMPLETE';
        throw err;
      }
      console.log(`[SANDBOX] ${actual} fichiers présents (attendu: ${expectedCount})`);
    } catch (e) {
      // Erreur structurée de notre part → propagation
      if (e.code === 'UPLOAD_INCOMPLETE') throw e;
      // Sinon c'est la commande find qui a échoué → warn mais on continue
      console.log('⚠️ Vérification fichiers échouée:', e.message);
    }

    console.log(`✅ ${fichiersValides.length} fichiers uploadés dans la sandbox`);
    return sb;

  } catch (e) {
    // Nettoyage défensif sur toute erreur d'upload
    console.log('❌ Upload échoué, kill sandbox...');
    await killSandbox(sb);
    throw e;
  }
}

// ⚠️ DETTE TECHNIQUE : alias conservé pour compatibilité avec un ancien nom (typo).
//    Vérifier les usages avant suppression :
//      grep -rn "aderDansSandbox" --include="*.js" . | grep -v "agents/sandbox.js"
//    Si aucun résultat → supprimer la ligne ci-dessous + l'export dans module.exports.
const aderDansSandbox = uploaderDansSandbox;

// ============================================
// ▶️ EXÉCUTION DE COMMANDE
// ============================================
// ⚠️ Si la sandbox est perdue et recréée, les fichiers uploadés sont PERDUS.
//    executerCommande() ne re-uploade PAS. L'appelant doit rappeler
//    uploaderDansSandbox() si nécessaire.
//
// Contrat de retour :
//   - success: true          → exitCode = 0
//   - success: false         → exitCode = code de sortie réel si la commande a
//                              échoué normalement (ex: grep sans résultat → 1)
//   - success: false         → exitCode = -1 si l'infrastructure a échoué et
//                              qu'aucun code de sortie fiable n'est disponible
// ============================================
async function executerCommande(commande, timeout = 30000) {
  try {
    const sandbox = await creerSandbox();
    const result = await sandbox.commands.run(commande, { timeoutMs: timeout });
    const exitCode = result.exitCode ?? -1;
    return {
      success: exitCode === 0,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      exitCode
    };
  } catch (error) {
    const msg = error && error.message ? error.message : String(error);

    // 1) Commande échouée NORMALEMENT (exit ≠ 0) → pas de retry, on renvoie
    //    les vraies infos (stdout, stderr, exitCode). C'est le cas le plus
    //    fréquent avec E2B v1 qui throw CommandExitError pour exit ≠ 0.
    const cmdErr = extraireCommandExitError(error);
    if (cmdErr) {
      return {
        success: false,
        stdout: cmdErr.stdout,
        stderr: cmdErr.stderr,
        exitCode: cmdErr.exitCode
      };
    }

    // 2) Sandbox morte (vraiment) → tentative de recréation + retry.
    //    Attention : les fichiers uploadés sont perdus, c'est documenté.
    const isSandboxDead =
      /\bsandbox\b.*\b(dead|not running|terminated|expired|killed)\b/i.test(msg) ||
      /\b(deadline|timeout)\b.*\bsandbox\b/i.test(msg);

    if (isSandboxDead) {
      console.log('⚠️ Sandbox perdue, recréation...');
      if (currentSandbox) {
        try { await currentSandbox.kill(); } catch (_) {}
        currentSandbox = null;
      }
      try {
        const sb2 = await creerSandbox();
        const result = await sb2.commands.run(commande, { timeoutMs: timeout });
        const exitCode = result.exitCode ?? -1;
        return {
          success: exitCode === 0,
          stdout: result.stdout || '',
          stderr: result.stderr || '',
          exitCode
        };
      } catch (e) {
        return {
          success: false,
          stdout: '',
          stderr: `Sandbox perdue puis recréation échouée : ${e.message}`,
          exitCode: -1
        };
      }
    }

    // 3) Autre erreur d'infrastructure (non retry-able)
    return {
      success: false,
      stdout: '',
      stderr: msg,
      exitCode: -1
    };
  }
}

// ============================================
// 🔒 FERMETURE
// ============================================
async function fermerSandbox() {
  if (currentSandbox) {
    const sb = currentSandbox;
    await killSandbox(sb);
    console.log('🔒 Sandbox fermée');
  } else {
    console.log('🔒 Aucune sandbox à fermer');
  }
}

module.exports = {
  creerSandbox,
  killSandbox,
  uploaderDansSandbox,
  aderDansSandbox,   // ⚠️ DETTE : voir commentaire au-dessus de sa déclaration
  executerCommande,
  fermerSandbox
}; 
