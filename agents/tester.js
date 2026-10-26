// agents/tester.js
// ============================================
// 🧪 TESTER — Pipeline de test complet dans sandbox E2B v1.x
// ============================================
// Gère :
// - CommandExitError de E2B v1 (throw au lieu de retourner)
// - pip install / npm install auto
// - Test séquentiel : syntaxe → install → imports → run
// - Extraction fichierCoupable depuis traceback (filtré _test_imports.py)
// - Détection type projet (flask, fastapi, django, node, script)
// - Création auto des __init__.py RÉCURSIFS
// - Exit codes > 128 (signaux SIGKILL, SIGSEGV, etc.)
// - Cleanup des fichiers temporaires (succès ET échec)
// - Échappement shell systématique (py_compile, run, dirs)
// - Validation requirements.txt (anti-RCE : --index-url, file://, etc.)
// - Mapping timeout E2B → exitCode 124
// - Timeout géré dans testerImports (projet Flask/FastAPI)
// ============================================
//
// ⚠️ CONTRAT API :
//   - En cas de SUCCÈS : le sandbox n'est PAS tué. L'appelant DOIT appeler
//     `result.sandbox.kill()` quand il a fini de l'utiliser.
//   - En cas d'EXCEPTION INTERNE : le sandbox est tué automatiquement.
//
// ⚠️ HYPOTHÈSE : `sandbox.uploaderDansSandbox()` doit tuer son propre sandbox
//   en cas d'échec d'upload. Sinon, ce module ne peut pas nettoyer (sb === null).
// ============================================

const sandbox = require('./sandbox');

const ROOT = '/home/user';

// ============================================
// 🧰 HELPERS
// ============================================

// Échappe une chaîne pour un usage entre apostrophes shell
function shQuote(s) {
  return `'${String(s).replace(/'/g, "'\\''")}'`;
}

// Échappe les backticks pour éviter de casser un bloc ```markdown```
function safeMd(s) {
  return String(s == null ? '' : s).replace(/`/g, '\\`');
}

// Tronque en gardant la fin (utile pour les tracebacks : le vrai crash est à la fin)
function tailTruncate(s, n) {
  if (!s) return '';
  return s.length > n ? '…' + s.slice(-n) : s;
}

// Extrait les fichiers projet (filtre _test*, _kenny*, _test_imports.py) d'un traceback
function extraireFichiersProjet(text) {
  if (!text) return [];
  return [...text.matchAll(/File "\/home\/user\/([^"]+\.py)"/g)]
    .map(m => m[1])
    .filter(f =>
      !f.startsWith('_test') &&
      !f.startsWith('_kenny') &&
      f !== '_test_imports.py'
    );
}

// Formate une liste de modules pour les messages (max N + "autres")
function formaterListeModules(modules, max = 30) {
  if (modules.length <= max) return modules.join(', ');
  return modules.slice(0, max).join(', ') + ` (+${modules.length - max} autres)`;
}

// ============================================
// 🔍 DÉTECTION TYPE DE PROJET
// ============================================
function detecterTypeProjet(blocks) {
  // On n'analyse QUE les fichiers .py pour éviter les faux positifs
  // (README.md qui contient "from django", tests de parser, etc.)
  const pyBlocks = blocks.filter(b => (b.nom || '').endsWith('.py'));

  const has = (pattern) => pyBlocks.some(b => {
    // Retire les commentaires inline (#) pour éviter les faux positifs
    const content = (b.contenu || '')
      .split('\n')
      .map(l => l.split('#')[0])
      .join('\n');
    return content.includes(pattern);
  });

  const hasFile = (name) => blocks.some(b => b.nom === name);

  if (has('from django')) return { type: 'django', needsInstall: true };
  if (has('from fastapi')) return { type: 'fastapi', needsInstall: true };
  if (has('from flask')) return { type: 'flask', needsInstall: true };
  if (hasFile('package.json')) return { type: 'node', needsInstall: true };
  if (hasFile('requirements.txt')) return { type: 'python', needsInstall: true };
  return { type: 'script', needsInstall: false };
}

// ============================================
// 🔒 VALIDATION requirements.txt (anti-RCE)
// ============================================
function validerRequirements(txt) {
  const BLOQUES = [
    // Directives pip dangereuses en début de ligne
    /^\s*--(index-url|extra-index-url|trusted-host|find-links|editable)\b/i,
    /^\s*(-e|-f|-i|-r|--index-url|--extra-index-url|--find-links|--editable)\s/i,
    // URL directe (wheel ou source depuis n'importe où, y compris file://)
    /@\s*(https?|file|ftp):\/\//i,
  ];
  const suspects = [];
  for (const raw of txt.split('\n')) {
    const l = raw.trim();
    if (!l || l.startsWith('#')) continue;
    // Retire un éventuel commentaire inline avant test
    const cmd = l.split('#')[0].trim();
    if (!cmd) continue;
    if (BLOQUES.some(r => r.test(cmd))) suspects.push(cmd);
  }
  return suspects;
}

// ============================================
// 🛡️ RUN SÉCURISÉ (catch CommandExitError / Timeout E2B v1)
// ============================================
async function runSure(sb, cmd, options = {}) {
  try {
    const result = await sb.commands.run(cmd, {
      timeoutMs: options.timeoutMs || 30000,
      background: false
    });
    return {
      exitCode: result.exitCode ?? 0,
      stdout: result.stdout || '',
      stderr: result.stderr || ''
    };
  } catch (e) {
    const msg = e.message || '';

    // Détection timeout INVERSÉE : on accepte tout "timeout" SAUF les
    // erreurs réseau légitimes (pip/npm). Couvre plus de variations E2B.
    const isNetworkError =
      /(pypi\.org|registry\.npmjs|connection|econnrefused|enotfound|getaddrinfo|network|ssl)/i.test(msg);

    const isSandboxTimeout =
      e.name === 'TimeoutError' ||
      (/\btime(d)?\s*out\b/i.test(msg) && !isNetworkError);

    if (isSandboxTimeout) {
      console.log(`[TEST] ⏱️ runSure timeout sandbox: ${msg.substring(0, 120)}`);
      return { exitCode: 124, stdout: '', stderr: `Sandbox timeout: ${msg}` };
    }

    // exitCode peut être un string (ex: 'ENOENT') → on force en Number
    const rawCode = e.exitCode ?? e.exit_code ?? e.code ?? 1;
    const exitCode = Number.isFinite(Number(rawCode)) ? Number(rawCode) : 1;
    const stdout = e.stdout || '';
    const stderr = e.stderr || msg;
    console.log(`[TEST] ⚠️ runSure catch: exitCode=${exitCode}, msg=${msg.substring(0, 120)}`);
    return { exitCode, stdout, stderr };
  }
}

// ============================================
// 📦 INSTALLATION DES DÉPENDANCES
// ============================================
async function installerDependances(sb, blocks) {
  const reqFile = blocks.find(b => b.nom === 'requirements.txt');
  if (reqFile) {
    // Validation anti-RCE
    const suspects = validerRequirements(reqFile.contenu || '');
    if (suspects.length > 0) {
      console.log(`[TEST] ⚠️ requirements.txt suspect: ${suspects.length} ligne(s)`);
      return {
        success: false,
        stderr:
          `requirements.txt contient des directives suspectes :\n` +
          `\`\`\`\n${safeMd(suspects.join('\n'))}\n\`\`\`\n\n` +
          `Ces directives permettent d'exécuter du code arbitraire ` +
          `(--index-url, -e, --find-links, URL directe, file://). ` +
          `Utilise uniquement des packages PyPI standards sans URL ni option pip.`
      };
    }

    console.log('[TEST] pip install -r requirements.txt...');
    const pip = await runSure(
      sb,
      `cd ${ROOT} && pip install -q -r requirements.txt 2>&1`,
      { timeoutMs: 180000 }
    );
    console.log(`[TEST] pip exitCode: ${pip.exitCode}`);

    // Timeout pip → message clair et actionnable
    if (pip.exitCode === 124) {
      return {
        success: false,
        stderr:
          `⚠️ Timeout (180s) pendant \`pip install\`.\n` +
          `Le projet a probablement des dépendances trop lourdes (torch, tensorflow, ...).\n` +
          `Réduis les dépendances ou utilise des versions plus légères.`
      };
    }

    if (pip.exitCode !== 0) {
      return {
        success: false,
        stderr: `pip install échoué (exit ${pip.exitCode}):\n\`\`\`\n${safeMd((pip.stdout || pip.stderr || '').substring(0, 2000))}\n\`\`\``
      };
    }
  }

  const pkgFile = blocks.find(b => b.nom === 'package.json');
  if (pkgFile) {
    console.log('[TEST] npm install...');
    const npm = await runSure(
      sb,
      `cd ${ROOT} && npm install --silent 2>&1`,
      { timeoutMs: 180000 }
    );
    console.log(`[TEST] npm exitCode: ${npm.exitCode}`);

    // Timeout npm → message clair
    if (npm.exitCode === 124) {
      return {
        success: false,
        stderr:
          `⚠️ Timeout (180s) pendant \`npm install\`.\n` +
          `Le projet a probablement des dépendances trop lourdes.\n` +
          `Réduis les dépendances.`
      };
    }

    if (npm.exitCode !== 0) {
      return {
        success: false,
        stderr: `npm install échoué:\n\`\`\`\n${safeMd((npm.stdout || npm.stderr || '').substring(0, 2000))}\n\`\`\``
      };
    }
  }

  return { success: true };
}

// ============================================
// 🧪 SYNTAXE (py_compile)
// ============================================
async function testerSyntaxe(sb, blocks) {
  const pyFiles = blocks.filter(b => b.nom.endsWith('.py'));
  if (pyFiles.length === 0) return { success: true };

  // -B : ne pas écrire de __pycache__ (évite de polluer le sandbox)
  const list = pyFiles.map(b => shQuote(b.nom)).join(' ');
  const res = await runSure(
    sb,
    `cd ${ROOT} && python3 -B -m py_compile ${list} 2>&1`,
    { timeoutMs: 20000 }
  );

  if (res.exitCode !== 0) {
    const log = (res.stdout + '\n' + res.stderr).trim();
    const fichiersProjet = extraireFichiersProjet(log);
    const fileMatch = log.match(/File "\/home\/user\/([^"]+\.py)"/) ||
                      log.match(/([a-zA-Z0-9_\/\-]+\.py)['"]?[,:]?\s/);
    const fichierCoupable = fichiersProjet.length > 0
      ? fichiersProjet[0]
      : (fileMatch ? fileMatch[1] : null);

    return {
      success: false,
      stderr: `ERREUR DE SYNTAXE PYTHON :\n\`\`\`\n${safeMd(log.substring(0, 2500))}\n\`\`\``,
      fichierCoupable
    };
  }

  return { success: true };
}

// ============================================
// 🔗 IMPORTS (teste tous les .py)
// ============================================
async function testerImports(sb, blocks) {
  const pyFiles = blocks.filter(b => b.nom.endsWith('.py'));
  if (pyFiles.length === 0) return { success: true };

  // Convertit moteur/config.py → moteur.config
  // On n'exclut que __init__ et __main__ (les _utils.py, _config.py sont légitimes)
  const modules = pyFiles
    .map(b => b.nom.replace(/\.py$/, '').replace(/\//g, '.'))
    .filter(m => !m.endsWith('__init__') && !m.endsWith('__main__'));

  if (modules.length === 0) return { success: true };

  const script = `
import sys, os, traceback, importlib
sys.path.insert(0, ${JSON.stringify(ROOT)})
os.chdir(${JSON.stringify(ROOT)})

modules = ${JSON.stringify(modules)}
errors = []
for mod in modules:
    try:
        importlib.import_module(mod)
    except SystemExit:
        pass
    except Exception:
        errors.append(f"### MODULE {mod}")
        errors.append(traceback.format_exc())

if errors:
    print("IMPORT_ERRORS_START")
    print("\\n".join(errors))
    print("IMPORT_ERRORS_END")
    sys.exit(1)
else:
    print("ALL_IMPORTS_OK")
`.trim();

  // Écriture du script de test protégée localement (message clair en cas d'échec)
  try {
    await sb.files.write(`${ROOT}/_test_imports.py`, script);
  } catch (e) {
    return {
      success: false,
      stderr: `Impossible d'écrire le script de test des imports :\n\`\`\`\n${safeMd(e.message || String(e))}\n\`\`\``,
      fichierCoupable: null
    };
  }

  // Timeout adaptatif (60s min, jusqu'à 180s) au nombre de modules
  // (projets ML avec torch/tensorflow = chaque import peut prendre 20-30s)
  const timeoutImport = Math.min(
    60000 * Math.max(1, Math.ceil(modules.length / 5)),
    180000
  );

  const res = await runSure(
    sb,
    `cd ${ROOT} && python3 _test_imports.py 2>&1`,
    { timeoutMs: timeoutImport }
  );

  // ⏱️ Timeout : un module démarre probablement un serveur/loop au niveau module
  // ou projet trop lent (ML). On distingue les deux via stdout partiel.
  if (res.exitCode === 124) {
    const listeModules = formaterListeModules(modules);
    const aProduitSortie = (res.stdout || '').trim().length > 0;

    if (aProduitSortie) {
      return {
        success: false,
        stderr:
          `⚠️ Timeout ${Math.round(timeoutImport / 1000)}s pendant le test des imports (sortie partielle).\n` +
          `Le projet est probablement lent (imports lourds type torch/tensorflow) ` +
          `ou un module démarre un serveur au niveau module.\n` +
          `Modules testés : ${safeMd(listeModules)}\n` +
          `Sortie partielle :\n\`\`\`\n${safeMd(res.stdout.substring(0, 1000))}\n\`\`\``,
        fichierCoupable: null
      };
    }

    return {
      success: false,
      stderr:
        `⚠️ Timeout ${Math.round(timeoutImport / 1000)}s pendant le test des imports.\n` +
        `Un fichier démarre probablement un serveur ou une boucle infinie au niveau module ` +
        `(code qui ne devrait s'exécuter que sous \`if __name__ == '__main__'\`).\n` +
        `Modules testés : ${safeMd(listeModules)}`,
      fichierCoupable: null
    };
  }

  const out = res.stdout + '\n' + res.stderr;

  if (out.includes('IMPORT_ERRORS_START') || res.exitCode !== 0) {
    const match = out.match(/### MODULE ([\w.]+)\n([\s\S]*?)(?=### MODULE|IMPORT_ERRORS_END|$)/);
    const moduleEnErreur = match ? match[1] : '?';
    const traceback = match ? match[2].trim() : out;

    const fichiersProjet = extraireFichiersProjet(traceback);
    const fichierCoupable = fichiersProjet.length > 0
      ? fichiersProjet[0]
      : moduleEnErreur.replace(/\./g, '/') + '.py';

    return {
      success: false,
      stderr: `ERREUR D'IMPORT dans ${safeMd(moduleEnErreur)} :\n\`\`\`\n${safeMd(traceback.substring(0, 2500))}\n\`\`\``,
      fichierCoupable
    };
  }

  return { success: true };
}

// ============================================
// ▶️ RUN (exécution réelle du main)
// ============================================
async function testerRun(sb, mainFile, typeProjet) {
  const timeoutSec = typeProjet === 'script' ? 10 : 20;
  const timeoutMs = (timeoutSec + 15) * 1000;

  const escapedNom = shQuote(mainFile.nom);

  const cmd = `
cd ${ROOT} && timeout ${timeoutSec} python3 ${escapedNom} > /tmp/run_out.log 2> /tmp/run_err.log
EXIT=$?
echo "___EXIT___:$EXIT"
echo "___OUT_START___"
cat /tmp/run_out.log
echo "___OUT_END___"
echo "___ERR_START___"
cat /tmp/run_err.log
echo "___ERR_END___"
`.trim();

  const res = await runSure(sb, cmd, { timeoutMs });
  const log = res.stdout + '\n' + res.stderr;

  const exitMatch = log.match(/___EXIT___:(\d+)/);
  const exit = exitMatch ? parseInt(exitMatch[1]) : -1;

  const outMatch = log.match(/___OUT_START___\n?([\s\S]*?)___OUT_END___/);
  const errMatch = log.match(/___ERR_START___\n?([\s\S]*?)___ERR_END___/);
  const stdout = outMatch ? outMatch[1].trim() : '';
  const stderr = errMatch ? errMatch[1].trim() : '';

  // Cas 0 : impossible de récupérer le code de sortie (wrapper cassé, sandbox mort)
  if (exit === -1) {
    return {
      success: false,
      stderr:
        `⚠️ Impossible de récupérer le code de sortie du script.\n` +
        `La sandbox a peut-être été interrompue ou le wrapper bash a échoué.\n` +
        `Sortie brute :\n\`\`\`\n${safeMd((log || '').substring(0, 800))}\n\`\`\``,
      fichierCoupable: mainFile.nom
    };
  }

  // Exit codes > 128 = processus tué par signal (SIGKILL=137, SIGSEGV=139, etc.)
  if (exit > 128) {
    const signal = exit - 128;
    const signalNames = {
      1: 'SIGHUP', 2: 'SIGINT', 3: 'SIGQUIT', 6: 'SIGABRT',
      9: 'SIGKILL', 11: 'SIGSEGV', 15: 'SIGTERM'
    };
    const signalName = signalNames[signal] || `signal ${signal}`;
    return {
      success: false,
      stderr:
        `⚠️ Processus tué par ${signalName} (exit ${exit}).\n` +
        `Sortie: ${safeMd(stdout.substring(0, 500))}\n` +
        `${safeMd(tailTruncate(stderr, 1000))}`
    };
  }

  // Cas 1 : timeout (124) = serveur qui tourne (ou type non-script)
  if (exit === 124) {
    const serveurPattern = /(running on|serving|listening|http:\/\/|localhost|127\.0\.0\.1|werkzeug|flask|uvicorn|gunicorn|fastapi|django)/i;
    const ressembleServeur = serveurPattern.test(stdout) || serveurPattern.test(stderr);

    if (ressembleServeur || typeProjet !== 'script') {
      return {
        success: true,
        stdout: `✅ Serveur lancé et stable (timeout ${timeoutSec}s atteint).\n${safeMd(stdout.substring(0, 1000))}`
      };
    }
    return {
      success: false,
      stderr:
        `⚠️ Timeout ${timeoutSec}s sans serveur détecté.\n` +
        `Note : le test exécute le script ${timeoutSec}s puis l'interrompt. ` +
        `Un script long mais correct déclenchera ce message — vérifie d'abord ` +
        `s'il ne s'agit pas simplement d'un traitement volumineux, avant de "réparer" du code.\n` +
        `Sortie: ${safeMd(stdout.substring(0, 800))}`
    };
  }

  // Cas 2 : exit 0 = succès
  if (exit === 0 && !stderr.includes('Traceback')) {
    return {
      success: true,
      stdout: `✅ Script exécuté avec succès.\n${safeMd(stdout.substring(0, 1000)) || '(pas de sortie)'}`
    };
  }

  // Cas 3 : crash
  const fichiersProjet = extraireFichiersProjet(stderr);
  const fichierCoupable = fichiersProjet.length > 0
    ? fichiersProjet[0]
    : mainFile.nom;

  return {
    success: false,
    stderr: `ERREUR D'EXÉCUTION dans ${safeMd(fichierCoupable)} :\n\`\`\`\n${safeMd(stderr.substring(0, 2500))}\n\`\`\``,
    fichierCoupable
  };
}

// ============================================
// 🧹 CLEANUP
// ============================================
async function cleanupTemp(sb) {
  try {
    await sb.commands.run(
      `cd ${ROOT} && rm -f _test_imports.py 2>/dev/null || true`,
      { timeoutMs: 5000 }
    );
    console.log(`🧹 Fichiers temporaires nettoyés`);
  } catch (e) {
    console.warn(`⚠️ Cleanup échoué:`, e.message);
  }
}

// ============================================
// 🚀 PIPELINE COMPLET
// ============================================
async function testerCodePython(blocks) {
  let sb = null;
  let sbKilled = false;

  try {
    console.log(`[TEST] === Début test (${blocks.length} fichiers) ===`);

    // 1. Upload (hypothèse : uploaderDansSandbox tue son sandbox en cas d'échec)
    sb = await sandbox.uploaderDansSandbox(blocks);
    console.log(`[TEST] ✅ Upload OK`);

    // 2. Détection type
    const typeInfo = detecterTypeProjet(blocks);
    console.log(`[TEST] Type détecté: ${typeInfo.type}`);

    // 3. Créer les __init__.py RÉCURSIFS (a/b/c → a/, a/b/, a/b/c/)
    const pyFiles = blocks.filter(b => b.nom.endsWith('.py'));
    const dirsWithPy = new Set();
    for (const f of pyFiles) {
      const parts = f.nom.split('/').slice(0, -1);
      for (let i = 1; i <= parts.length; i++) {
        dirsWithPy.add(parts.slice(0, i).join('/'));
      }
    }

    for (const dir of dirsWithPy) {
      const initPath = `${dir}/__init__.py`;
      if (!blocks.some(b => b.nom === initPath)) {
        try {
          const safeDir = shQuote(dir);
          await sb.commands.run(
            `cd ${ROOT} && mkdir -p ${safeDir} && touch ${safeDir}/__init__.py`,
            { timeoutMs: 5000 }
          );
          console.log(`📝 ${initPath} créé (auto)`);
        } catch (e) {
          console.log(`⚠️ Impossible de créer ${initPath}:`, e.message);
        }
      }
    }

    // 4. Fichier principal (priorité claire, pas de || mort)
    const CANDIDATS = ['run.py', 'main.py', 'app.py', 'server.py', 'interface/serveur.py'];
    let mainFile = blocks.find(b => CANDIDATS.includes(b.nom));

    if (!mainFile) {
      const basenameOk = (b) => {
        const base = b.nom.split('/').pop();
        return base === 'serveur.py'
          && !/(^|\/)(test|tests|spec|__tests__)\//.test(b.nom)
          && !base.startsWith('test_')
          && !base.includes('backup');
      };
      mainFile = blocks.find(basenameOk);
    }

    if (!mainFile) {
      return {
        success: false,
        stderr: 'Aucun fichier principal trouvé (run.py, main.py, app.py, server.py)',
        exitCode: 1,
        sandbox: sb
      };
    }

    // 5. Syntaxe
    console.log(`[TEST] Test syntaxe...`);
    const syn = await testerSyntaxe(sb, blocks);
    if (!syn.success) return { ...syn, exitCode: 1, sandbox: sb };
    console.log(`[TEST] ✅ Syntaxe OK`);

    // 6. Installation des dépendances
    if (typeInfo.needsInstall) {
      console.log(`[TEST] Installation dépendances...`);
      const inst = await installerDependances(sb, blocks);
      if (!inst.success) return { ...inst, exitCode: 1, sandbox: sb };
      console.log(`[TEST] ✅ Dépendances OK`);
    }

    // 7. Imports
    console.log(`[TEST] Test imports...`);
    const imp = await testerImports(sb, blocks);
    if (!imp.success) return { ...imp, exitCode: 1, sandbox: sb };
    console.log(`[TEST] ✅ Imports OK`);

    // 8. Run
    console.log(`[TEST] Test run...`);
    const run = await testerRun(sb, mainFile, typeInfo.type);

    return {
      ...run,
      exitCode: run.success ? 0 : 1,
      sandbox: sb
    };

  } catch (e) {
    console.error('[TEST] ❌ Exception:', e);
    console.error('[TEST] Message:', e.message);
    console.error('[TEST] Stack:', e.stack);
    if (sb && typeof sb.kill === 'function') {
      sbKilled = true;
      await sb.kill().catch(() => {});
    }
    return {
      success: false,
      stderr: `Erreur interne sandbox :\n${safeMd(e.message)}\n\nStack:\n${safeMd((e.stack || '').substring(0, 800))}`,
      stdout: '',
      exitCode: 1
    };
  } finally {
    // 🧹 Cleanup systématique (succès ET échec), sauf si le sandbox a déjà été tué
    if (sb && !sbKilled) {
      await cleanupTemp(sb);
    }
  }
}

module.exports = { testerCodePython, detecterTypeProjet };
