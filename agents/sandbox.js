// agents/sandbox.js
// ============================================
// 🏗️ SANDBOX — Gestion de la sandbox E2B v1 (durcie)
// ============================================

const path = require('path');
const { Sandbox } = require('@e2b/code-interpreter');

// ============================================
// 📐 CONSTANTES / CONFIG
// ============================================

const ROOT = '/home/user';
const ROOT_PREFIX = ROOT + '/';

// Timeout par défaut de la sandbox (configurable via env).
const SANDBOX_TIMEOUT_MS = (() => {
  const v = parseInt(process.env.E2B_SANDBOX_TIMEOUT_MS || '', 10);
  return Number.isFinite(v) && v > 0 ? v : 1000 * 60 * 60; // 1h défaut
})();

// Nombre de tentatives pour la création de sandbox (erreurs transitoires).
const SANDBOX_CREATE_RETRIES = (() => {
  const v = parseInt(process.env.E2B_CREATE_RETRIES || '', 10);
  return Number.isFinite(v) && v >= 0 ? v : 2;
})();

// Délai de backoff de base entre tentatives (ms, exponentiel).
const SANDBOX_CREATE_BACKOFF_MS = (() => {
  const v = parseInt(process.env.E2B_CREATE_BACKOFF_MS || '', 10);
  return Number.isFinite(v) && v > 0 ? v : 500;
})();

// Timeouts internes (unifiés, surchargeables).
const TIMEOUTS = {
  getInfo: 5000,
  ping: 8000,
  pingResume: 10000,
  mkdirRoot: 10000,
  mkdirDirs: 15000,
  testFile: 5000,
  defaultCommand: 30000
};

// ============================================
// 🪵 LOGGER (niveaux, désactivable)
// ============================================

const LOG_LEVEL = (process.env.SANDBOX_LOG_LEVEL || 'info').toLowerCase();
const LOG_LEVELS = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };
const LOG_CURRENT = LOG_LEVELS[LOG_LEVEL] ?? LOG_LEVELS.info;

const log = {
  error: (...a) => LOG_CURRENT >= LOG_LEVELS.error && console.error('❌', ...a),
  warn:  (...a) => LOG_CURRENT >= LOG_LEVELS.warn  && console.warn('⚠️', ...a),
  info:  (...a) => LOG_CURRENT >= LOG_LEVELS.info  && console.log('ℹ️', ...a),
  ok:    (...a) => LOG_CURRENT >= LOG_LEVELS.info  && console.log('✅', ...a),
  debug: (...a) => LOG_CURRENT >= LOG_LEVELS.debug && console.log('🐛', ...a)
};

// ============================================
// 🔒 ÉTAT GLOBAL
// ============================================

let currentSandbox = null;

// Verrou pour éviter les créations concurrentes de sandbox.
// Contient la promesse en cours (partagée entre appelants concurrents).
let creationEnCours = null;

// Compteur de génération : incrémenté à chaque kill/recréation.
// Permet à un appelant de savoir si la sandbox a été recréée entre deux
// opérations (et donc si son état — fichiers uploadés — a été perdu).
let generationSandbox = 0;

// ============================================
// 🧰 HELPERS GÉNÉRIQUES
// ============================================

// Échappe une chaîne pour un usage entre apostrophes shell.
function shQuote(s) {
  return `'${String(s).replace(/'/g, "'\\''")}'`;
}

// Pause annulable/non bloquante pour la sortie du process.
// On NE fait PAS unref : si c'est le seul handle actif (cas d'un retry
// isolé), unref ferait sortir le process trop tôt.
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Course entre une promesse et un timeout, avec nettoyage GARANTI du timer.
// Signature : avecTimeout(promesseOuFactory, ms, label)
// On accepte une factory pour éviter les promesses "orphelines" si on
// décide de ne pas lancer l'opération.
async function avecTimeout(factory, ms, label = 'operation') {
  let timer = null;
  try {
    const p = typeof factory === 'function' ? factory() : factory;
    const timeoutP = new Promise((_, rej) => {
      timer = setTimeout(
        () => rej(Object.assign(new Error(`${label} timeout (${ms}ms)`), { code: 'TIMEOUT', label })),
        ms
      );
    });
    return await Promise.race([p, timeoutP]);
  } finally {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  }
}

// Vérifie qu'un nom de fichier relatif est "sain" (pas de traversée, pas de
// caractère de contrôle, pas de réservé Windows, pas de bidi/zero-width).
function nomFichierValide(nom) {
  if (typeof nom !== 'string') return false;
  if (nom.length === 0 || nom.length > 1024) return false;
  if (nom === '.' || nom === '/' || nom === '..') return false;
  if (nom.startsWith('/') || nom.endsWith('/')) return false;

  const segments = nom.split('/');
  for (const seg of segments) {
    if (seg === '' || seg === '.' || seg === '..') return false;
    if (seg.length > 255) return false;
    // Réservés Windows + séparateurs alternatifs
    if (/[<>:"|?*\\]/.test(seg)) return false;
    // Contrôle (0x00-0x1F), DEL (0x7F), bidi/zero-width, BOM, surrogates isolés
    if (/[\x00-\x1f\x7f\u200B-\u200F\u2028-\u202F\uFEFF]/.test(seg)) return false;
    if (seg !== seg.trim()) return false;
  }
  return true;
}

// Construit un chemin absolu DANS la sandbox, en garantissant le confinement
// sous ROOT. Belt-and-braces face à un futur changement de validation.
function cheminSandbox(nomRelatif) {
  const abs = path.posix.join(ROOT, nomRelatif);
  if (abs !== ROOT && !abs.startsWith(ROOT_PREFIX)) {
    throw Object.assign(
      new Error(`Chemin hors ROOT refusé : ${nomRelatif}`),
      { code: 'PATH_ESCAPE' }
    );
  }
  return abs;
}

// ============================================
// 🩺 DIAGNOSTIC SANDBOX
// ============================================

// Extrait les infos d'une CommandExitError E2B v1, si applicable.
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

// Détecte un vrai état "sandbox morte" (et pas juste un timeout de commande).
function estSandboxMorte(message) {
  if (!message) return false;
  const m = String(message);

  // Timeout sans marqueur de mort explicite → pas considéré comme mort.
  if (/\btimeout\b/i.test(m) && !/\b(dead|terminated|expired|killed|not running|not found|stopped)\b/i.test(m)) {
    return false;
  }
  // "expired" seul est ambigu → mort uniquement si "sandbox" est présent.
  if (/\bexpired\b/i.test(m) && !/\bsandbox\b/i.test(m)) {
    return false;
  }
  // Réseau transitoire : pas une mort (on laisse l'appelant retenter si besoin).
  if (/\b(ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|socket hang up|connection reset)\b/i.test(m)) {
    return false;
  }

  return (
    /\bsandbox\b.*\b(dead|not running|terminated|expired|killed|stopped|not found)\b/i.test(m) ||
    /\b(dead|terminated|expired|killed|stopped)\b.*\bsandbox\b/i.test(m) ||
    /\bnot running\b/i.test(m)
  );
}

// Ping applicatif : retourne true si la sandbox répond à `echo`.
async function pingSandbox(sb, timeoutMs = TIMEOUTS.ping) {
  if (!sb) return false;
  try {
    const res = await avecTimeout(
      () => sb.commands.run('echo __ping__', { timeoutMs }),
      timeoutMs + 1000,
      'ping'
    );
    return typeof res?.stdout === 'string' && res.stdout.includes('__ping__');
  } catch (_) {
    return false;
  }
}

// Vérifie l'existence d'un fichier.
// Retourne un OBJET { existe, incertain } :
//   - existe=true   : le fichier est là
//   - existe=false  : le fichier n'est pas là (réponse fiable)
//   - incertain=true: on n'a pas pu conclure (erreur réseau, timeout…)
async function etatFichier(sb, absPath, timeoutMs = TIMEOUTS.testFile) {
  try {
    const r = await avecTimeout(
      () => sb.commands.run(
        `test -f ${shQuote(absPath)} && echo __OK__ || echo __MISSING__`,
        { timeoutMs }
      ),
      timeoutMs + 1000,
      'test-file'
    );
    const out = r.stdout || '';
    if (out.includes('__OK__')) return { existe: true, incertain: false };
    if (out.includes('__MISSING__')) return { existe: false, incertain: false };
    // Réponse inattendue : on ne peut pas conclure.
    return { existe: false, incertain: true };
  } catch (_) {
    return { existe: false, incertain: true };
  }
}

// ============================================
// 🔁 REJEU DE COMMANDES (whitelist stricte)
// ============================================
//
// Une commande est rejouable UNIQUEMENT si :
//   1. elle commence par une commande de la whitelist,
//   2. elle ne contient AUCUN méta-caractère shell susceptible d'écrire,
//   3. elle ne contient aucune option destructive connue.
//
// Le but n'est PAS d'être exhaustif — c'est d'être conservateur. En cas de
// doute, on ne rejoue pas.

const CMDS_WHITELIST = /^(ls|cat|pwd|echo|which|test|find|head|tail|grep|wc|stat|file|tree|id|uname|whoami|date|env|printenv)\b/;
const SHELL_DANGEREUX = /[><|;&$`\\(){}[\]*?!~]/;
const OPTIONS_DESTRUCTIVES = /(?:^|\s)(-delete|-exec|-execdir|-ok|-okdir|--remove|--force)\b/;

function commandeRejouable(commande) {
  if (typeof commande !== 'string') return false;
  const trimmed = commande.trim();
  if (!CMDS_WHITELIST.test(trimmed)) return false;
  if (SHELL_DANGEREUX.test(trimmed)) return false;
  if (OPTIONS_DESTRUCTIVES.test(trimmed)) return false;
  return true;
}

// ============================================
// 🔧 CRÉATION / RECONNEXION
// ============================================

// Tente de réutiliser la sandbox existante ; sinon la tue proprement.
// Retourne la sandbox réutilisable ou null.
async function tenterReutilisation(sbActuelle) {
  let info = null;
  let infoError = null;

  try {
    info = await avecTimeout(() => sbActuelle.getInfo(), TIMEOUTS.getInfo, 'getInfo');
  } catch (e) {
    infoError = e;
  }

  // Si getInfo échoue ou est vide : ping applicatif AVANT de tuer.
  if (infoError || !info) {
    log.warn('getInfo échoué ou vide, test de ping applicatif...');
    if (await pingSandbox(sbActuelle, TIMEOUTS.ping)) {
      log.ok('Sandbox toujours vivante malgré getInfo KO — réutilisation');
      return sbActuelle;
    }
    log.warn('Sandbox non réactive au ping — kill + recréation');
    await killSandbox(sbActuelle);
    return null;
  }

  if (info.state === 'running') return sbActuelle;

  if (info.state === 'paused') {
    log.info('⏸️ Sandbox en pause, tentative de reprise...');
    if (await pingSandbox(sbActuelle, TIMEOUTS.pingResume)) {
      log.ok('▶️ Sandbox reprise avec succès');
      return sbActuelle;
    }
    log.warn('Reprise échouée');
    await killSandbox(sbActuelle);
    return null;
  }

  log.warn(`Sandbox en état "${info.state}", kill + recréation`);
  await killSandbox(sbActuelle);
  return null;
}

async function creerSandbox() {
  if (creationEnCours) return creationEnCours;

  const promesse = (async () => {
    if (!process.env.E2B_API_KEY) {
      throw new Error("E2B_API_KEY manquante dans l'environnement");
    }

    if (currentSandbox) {
      const sbActuelle = currentSandbox;
      const reutilisable = await tenterReutilisation(sbActuelle);
      if (reutilisable) return reutilisable;
    }

    let derniereErreur = null;
    for (let tentative = 0; tentative <= SANDBOX_CREATE_RETRIES; tentative++) {
      if (tentative > 0) {
        const delai = SANDBOX_CREATE_BACKOFF_MS * Math.pow(2, tentative - 1);
        log.info(`🔁 Tentative création sandbox ${tentative + 1}/${SANDBOX_CREATE_RETRIES + 1} dans ${delai}ms...`);
        await sleep(delai);
      }

      let sb = null;
      try {
        log.info('🔧 Création sandbox E2B...');
        sb = await avecTimeout(
          () => Sandbox.create({
            apiKey: process.env.E2B_API_KEY,
            timeoutMs: SANDBOX_TIMEOUT_MS
          }),
          Math.max(SANDBOX_TIMEOUT_MS, 30000),
          'sandbox.create'
        );
        log.ok(`Sandbox créée : ${sb.sandboxId}`);

        // Smoke test : mkdir ROOT doit fonctionner.
        const mk = await avecTimeout(
          () => sb.commands.run(`mkdir -p ${ROOT}`, { timeoutMs: TIMEOUTS.mkdirRoot }),
          TIMEOUTS.mkdirRoot + 2000,
          'mkdir-root'
        );
        if (mk.exitCode !== 0) {
          throw new Error(`mkdir ROOT exit ${mk.exitCode}: ${mk.stderr || mk.stdout}`);
        }

        currentSandbox = sb;
        generationSandbox++;
        return sb;
      } catch (e) {
        derniereErreur = e;
        log.warn(`Création sandbox échouée (tentative ${tentative + 1}): ${e.message}`);
        if (sb) {
          try { await sb.kill(); } catch (_) {}
        }
      }
    }

    throw new Error(
      `Création sandbox échouée après ${SANDBOX_CREATE_RETRIES + 1} tentative(s) : ${derniereErreur?.message}`
    );
  })();

  // Empêche un "unhandled rejection" si le propriétaire se déconnecte.
  promesse.catch(() => {});
  creationEnCours = promesse;

  try {
    return await promesse;
  } finally {
    // On ne libère le verrou que si c'est toujours NOTRE promesse
    // (évite qu'un kill simultané remette un null inattendu).
    if (creationEnCours === promesse) creationEnCours = null;
  }
}

// ============================================
// 💀 KILL COHÉRENT
// ============================================

async function killSandbox(sb) {
  if (!sb) return;
  try {
    await avecTimeout(() => sb.kill(), 10000, 'sandbox.kill');
  } catch (e) {
    log.warn('kill sandbox échoué:', e.message);
  }
  if (currentSandbox === sb) {
    currentSandbox = null;
    generationSandbox++;
  }
}

// ============================================
// 📤 UPLOAD DES FICHIERS
// ============================================

async function uploaderDansSandbox(blocks) {
  if (!Array.isArray(blocks) || blocks.length === 0) {
    throw new Error('uploaderDansSandbox : aucun fichier à uploader');
  }

  // 1) Validation / filtrage
  const fichiersValides = [];
  const fichiersRejetes = [];
  for (const b of blocks) {
    if (b && nomFichierValide(b.nom)) fichiersValides.push(b);
    else fichiersRejetes.push(b);
  }

  if (fichiersValides.length === 0) {
    const noms = fichiersRejetes.map(b => b && b.nom).slice(0, 5);
    const plus = fichiersRejetes.length > 5 ? ` (+${fichiersRejetes.length - 5} autres)` : '';
    throw new Error(
      `uploaderDansSandbox : aucun fichier valide. ` +
      `Noms rejetés : ${noms.map(n => n || '(sans nom)').join(', ')}${plus}`
    );
  }

  // 2) Détection de doublons AVANT toute I/O.
  const cheminsVus = new Set();
  for (const b of fichiersValides) {
    if (cheminsVus.has(b.nom)) {
      throw new Error(`uploaderDansSandbox : chemin dupliqué "${b.nom}"`);
    }
    cheminsVus.add(b.nom);
  }

  // 3) Validation du contenu.
  for (const b of fichiersValides) {
    const c = b.contenu;
    if (c != null && typeof c !== 'string' && !Buffer.isBuffer(c)) {
      throw new Error(`Contenu non supporté pour ${b.nom} (attendu: string ou Buffer)`);
    }
  }

  const sb = await creerSandbox();

  try {
    log.info(
      `📤 Upload de ${fichiersValides.length} fichiers` +
      (fichiersRejetes.length > 0 ? ` (${fichiersRejetes.length} ignoré(s) : nom invalide)` : '') +
      ' dans la sandbox...'
    );

    // 4) mkdir -p de tous les sous-dossiers nécessaires.
    const dirs = new Set();
    for (const b of fichiersValides) {
      const parts = b.nom.split('/').filter(Boolean);
      let acc = '';
      for (let i = 0; i < parts.length - 1; i++) {
        acc += (acc ? '/' : '') + parts[i];
        dirs.add(acc);
      }
    }
    if (dirs.size > 0) {
      const dirList = [...dirs].map(d => shQuote(cheminSandbox(d))).join(' ');
      const mk = await avecTimeout(
        () => sb.commands.run(`mkdir -p ${dirList}`, { timeoutMs: TIMEOUTS.mkdirDirs }),
        TIMEOUTS.mkdirDirs + 2000,
        'mkdir-dirs'
      );
      if (mk.exitCode !== 0) {
        throw new Error(`mkdir échoué : ${mk.stderr || mk.stdout || 'exitCode=' + mk.exitCode}`);
      }
      log.debug(`Dossiers créés : ${[...dirs].join(', ')}`);
    }

    // 5) Écriture via l'API filesystem (chemin ABSOLU validé).
    if (!sb.files || typeof sb.files.write !== 'function') {
      throw new Error(
        'E2B SDK invalide : sb.files.write indisponible. ' +
        'Vérifie la version de @e2b/code-interpreter.'
      );
    }
    for (const b of fichiersValides) {
      const absPath = cheminSandbox(b.nom);
      try {
        await avecTimeout(
          () => sb.files.write(absPath, b.contenu ?? ''),
          30000,
          `write ${b.nom}`
        );
      } catch (e) {
        throw new Error(`Échec écriture ${absPath} : ${e.message}`);
      }
    }

    // 6) Vérification FIABLE : chaque fichier doit exister.
    //    - On distingue "absent" de "incertain".
    //    - Un "incertain" isolé déclenche UN retry avant de conclure.
    const manquants = [];
    const incertains = [];
    for (const b of fichiersValides) {
      const absPath = cheminSandbox(b.nom);
      let r = await etatFichier(sb, absPath);
      if (r.incertain) {
        // Un seul retry avant de classer en incertain définitif.
        await sleep(150);
        r = await etatFichier(sb, absPath);
      }
      if (r.incertain) incertains.push(b.nom);
      else if (!r.existe) manquants.push(b.nom);
    }

    if (incertains.length > 0) {
      const err = new Error(
        `Upload indéterminé : ${incertains.length} fichier(s) impossible(s) à vérifier ` +
        `(erreur réseau/timeout) : ${incertains.slice(0, 10).join(', ')}`
      );
      err.code = 'UPLOAD_UNCERTAIN';
      err.incertains = incertains;
      // On ne tue PAS la sandbox : les fichiers sont probablement là.
      throw err;
    }

    if (manquants.length > 0) {
      const apercu = manquants.slice(0, 10).join(', ');
      const plus = manquants.length > 10 ? ` (+${manquants.length - 10} autres)` : '';
      const err = new Error(
        `Upload incomplet : ${manquants.length}/${fichiersValides.length} fichiers manquants : ${apercu}${plus}`
      );
      err.code = 'UPLOAD_INCOMPLETE';
      err.manquants = manquants;
      throw err;
    }

    log.ok(`${fichiersValides.length} fichiers uploadés et vérifiés dans la sandbox`);
    return sb;

  } catch (e) {
    // On ne tue que sur incomplétude franche, pas sur incertitude réseau.
    if (e.code !== 'UPLOAD_UNCERTAIN') {
      log.warn('Upload échoué, kill sandbox...');
      await killSandbox(sb);
    }
    throw e;
  }
}

// ⚠️ Alias déprécié conservé pour compatibilité ascendante.
let _aliasAvertissementEmis = false;
/** @deprecated Utiliser `uploaderDansSandbox`. */
function aderDansSandbox(...args) {
  if (!_aliasAvertissementEmis) {
    _aliasAvertissementEmis = true;
    log.warn('aderDansSandbox() est déprécié : migrer vers uploaderDansSandbox().');
  }
  return uploaderDansSandbox(...args);
}

// ============================================
// ▶️ EXÉCUTION DE COMMANDE
// ============================================

async function runOnce(sandbox, commande, timeout) {
  const result = await sandbox.commands.run(commande, { timeoutMs: timeout });
  const exitCode = typeof result.exitCode === 'number' ? result.exitCode : -1;
  return {
    success: exitCode === 0,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    exitCode
  };
}

async function executerCommande(commande, timeout = TIMEOUTS.defaultCommand) {
  // Note : on capture la génération au début pour pouvoir signaler à
  // l'appelant si la sandbox a été recréée pendant l'exécution (=> son état
  // — fichiers uploadés — a été perdu).
  const generationAvant = generationSandbox;

  let sandbox;
  try {
    sandbox = await creerSandbox();
  } catch (e) {
    return {
      success: false,
      stdout: '',
      stderr: `Création sandbox échouée : ${e.message}`,
      exitCode: -1,
      recreee: false
    };
  }

  try {
    const res = await runOnce(sandbox, commande, timeout);
    return { ...res, recreee: generationSandbox !== generationAvant };
  } catch (error) {
    const msg = error && error.message ? error.message : String(error);

    // Erreur de sortie de commande : pas de recréation.
    const cmdErr = extraireCommandExitError(error);
    if (cmdErr) {
      return {
        success: false,
        stdout: cmdErr.stdout,
        stderr: cmdErr.stderr,
        exitCode: cmdErr.exitCode,
        recreee: generationSandbox !== generationAvant
      };
    }

    // Timeout pur de la commande : PAS une mort de sandbox.
    if (error && error.code === 'TIMEOUT') {
      return {
        success: false,
        stdout: '',
        stderr: msg,
        exitCode: -1,
        recreee: generationSandbox !== generationAvant
      };
    }

    if (!estSandboxMorte(msg)) {
      return {
        success: false,
        stdout: '',
        stderr: msg,
        exitCode: -1,
        recreee: generationSandbox !== generationAvant
      };
    }

    // Sandbox morte.
log.warn('Sandbox perdue, recréation...');
await killSandbox(sandbox);

    if (!commandeRejouable(commande)) {
      return {
        success: false,
        stdout: '',
        stderr:
          `Sandbox perdue pendant une commande non rejouable : ${msg}. ` +
          `La commande n'a pas été relancée pour éviter un effet de bord partiel.`,
        exitCode: -1,
        recreee: true // la sandbox a bien été perdue
      };
    }

    try {
      const sb2 = await creerSandbox();
      const res = await runOnce(sb2, commande, timeout);
      return { ...res, recreee: true };
    } catch (e) {
      return {
        success: false,
        stdout: '',
        stderr: `Sandbox perdue puis recréation échouée : ${e.message}`,
        exitCode: -1,
        recreee: true
      };
    }
  }
}

// ============================================
// 🔒 FERMETURE
// ============================================

async function fermerSandbox() {
  if (currentSandbox) {
    await killSandbox(currentSandbox);
    log.info('🔒 Sandbox fermée');
  } else {
    log.debug('🔒 Aucune sandbox à fermer');
  }
}

// ============================================
// 📦 EXPORTS
// ============================================

module.exports = {
  // API publique
  creerSandbox,
  killSandbox,
  uploaderDansSandbox,
  executerCommande,
  fermerSandbox,

  // Déprécié
  aderDansSandbox,

  // Helpers exposés (utiles aux tests et à l'observabilité)
  _internals: {
    nomFichierValide,
    cheminSandbox,
    estSandboxMorte,
    commandeRejouable,
    pingSandbox,
    etatFichier,
    avecTimeout,
    ROOT,
    get generation() { return generationSandbox; },
    get currentSandbox() { return currentSandbox; }
  }
};
