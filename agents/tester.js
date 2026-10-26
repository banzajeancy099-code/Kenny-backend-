// agents/tester.js
// ============================================
// 🧪 TESTER — Pipeline de test complet dans sandbox E2B v1.x
// ============================================
// Gère :
// - CommandExitError de E2B v1 (throw au lieu de retourner)
// - pip install / npm install auto
// - Test séquentiel : syntaxe → install → imports → run
// - Extraction fichierCoupable depuis traceback
// - Détection type projet (flask, fastapi, django, node, script)
// ============================================

const sandbox = require('./sandbox');

const ROOT = '/home/user';

// ============================================
// 🔍 DÉTECTION TYPE DE PROJET
// ============================================
function detecterTypeProjet(blocks) {
  const has = (pattern) => blocks.some(b => (b.contenu || '').includes(pattern));
  const hasFile = (name) => blocks.some(b => b.nom === name);

  if (has('from django')) return { type: 'django', needsInstall: true };
  if (has('from fastapi')) return { type: 'fastapi', needsInstall: true };
  if (has('from flask')) return { type: 'flask', needsInstall: true };
  if (hasFile('package.json')) return { type: 'node', needsInstall: true };
  if (hasFile('requirements.txt')) return { type: 'python', needsInstall: true };
  return { type: 'script', needsInstall: false };
}

// ============================================
// 🛡️ RUN SÉCURISÉ (catch CommandExitError E2B v1)
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
      stderr: result.stderr || '',
      threw: false
    };
  } catch (e) {
    // E2B v1 : CommandExitError contient exitCode + stdout + stderr
    const exitCode = e.exitCode ?? e.exit_code ?? (e.code ?? 1);
    const stdout = e.stdout || '';
    const stderr = e.stderr || e.message || '';
    console.log(`[TEST] ⚠️ runSure catch: exitCode=${exitCode}, msg=${e.message}`);
    return { exitCode, stdout, stderr, threw: true };
  }
}

// ============================================
// 📦 INSTALLATION DES DÉPENDANCES
// ============================================
async function installerDependances(sb, blocks) {
  const reqFile = blocks.find(b => b.nom === 'requirements.txt');
  if (reqFile) {
    console.log('[TEST] pip install -r requirements.txt...');
    const pip = await runSure(
      sb,
      `cd ${ROOT} && pip install -q -r requirements.txt 2>&1`,
      { timeoutMs: 180000 }
    );
    console.log(`[TEST] pip exitCode: ${pip.exitCode}`);
    if (pip.exitCode !== 0) {
      return {
        success: false,
        stderr: `pip install échoué (exit ${pip.exitCode}):\n\`\`\`\n${(pip.stdout || pip.stderr || '').substring(0, 2000)}\n\`\`\``
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
    if (npm.exitCode !== 0) {
      return {
        success: false,
        stderr: `npm install échoué:\n\`\`\`\n${(npm.stdout || npm.stderr || '').substring(0, 2000)}\n\`\`\``
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

  const list = pyFiles.map(b => `'${b.nom}'`).join(' ');
  const res = await runSure(
    sb,
    `cd ${ROOT} && python3 -m py_compile ${list} 2>&1`,
    { timeoutMs: 20000 }
  );

  if (res.exitCode !== 0) {
    const log = (res.stdout + '\n' + res.stderr).trim();
    const fileMatch = log.match(/File "\/home\/user\/([^"]+\.py)"/) ||
                      log.match(/([a-zA-Z0-9_\/\-]+\.py)['"]?[,:]?\s/);
    return {
      success: false,
      stderr: `ERREUR DE SYNTAXE PYTHON :\n\`\`\`\n${log.substring(0, 2500)}\n\`\`\``,
      fichierCoupable: fileMatch ? fileMatch[1] : null
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
  const modules = pyFiles
    .map(b => b.nom.replace(/\.py$/, '').replace(/\//g, '.'))
    .filter(m => !m.includes('__init__') && !m.startsWith('_'));

  if (modules.length === 0) return { success: true };

  const script = `
import sys, os, traceback, importlib
sys.path.insert(0, '${ROOT}')
os.chdir('${ROOT}')

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

  await sb.files.write(`${ROOT}/_test_imports.py`, script);
  const res = await runSure(
    sb,
    `cd ${ROOT} && python3 _test_imports.py 2>&1`,
    { timeoutMs: 60000 }
  );

  const out = res.stdout + '\n' + res.stderr;
if (out.includes('IMPORT_ERRORS_START') || res.exitCode !== 0) {
  const match = out.match(/### MODULE ([\w.]+)\n([\s\S]*?)(?=### MODULE|IMPORT_ERRORS_END|$)/);
  const moduleEnErreur = match ? match[1] : '?';
  const traceback = match ? match[2].trim() : out;
  
  // ⚠️ FIX #3 + #8 : Ignorer _test_imports.py et _kenny_*
  const allMatches = [...traceback.matchAll(/File "\/home\/user\/([^"]+\.py)"/g)];
  const fichiersProjet = allMatches
    .map(m => m[1])
    .filter(f => 
      !f.startsWith('_test') && 
      !f.startsWith('_kenny') && 
      f !== '_test_imports.py'
    );
  
  // Prendre le premier fichier du projet (le plus profond dans la stack)
  const fichierCoupable = fichiersProjet.length > 0 
    ? fichiersProjet[0] 
    : moduleEnErreur.replace(/\./g, '/') + '.py';

  return {
    success: false,
    stderr: `ERREUR D'IMPORT dans ${moduleEnErreur} :\n\`\`\`\n${traceback.substring(0, 2500)}\n\`\`\``,
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

  const cmd = `
cd ${ROOT} && timeout ${timeoutSec} python3 ${mainFile.nom} > /tmp/run_out.log 2> /tmp/run_err.log
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

  // Cas 1 : timeout (124) = serveur qui tourne
  if (exit === 124) {
    const serveurPattern = /(running on|serving|listening|http:\/\/|localhost|127\.0\.0\.1|werkzeug|flask|uvicorn|gunicorn|fastapi|django)/i;
    const ressembleServeur = serveurPattern.test(stdout) || serveurPattern.test(stderr);

    if (ressembleServeur || typeProjet !== 'script') {
      return {
        success: true,
        stdout: `✅ Serveur lancé et stable (timeout ${timeoutSec}s atteint).\n${stdout.substring(0, 1000)}`
      };
    }
    return {
      success: false,
      stderr: `⚠️ Timeout ${timeoutSec}s sans serveur détecté.\nSortie: ${stdout.substring(0, 800)}`
    };
  }

  // Cas 2 : exit 0 = succès
  if (exit === 0 && !stderr.includes('Traceback')) {
    return {
      success: true,
      stdout: `✅ Script exécuté avec succès.\n${stdout.substring(0, 1000) || '(pas de sortie)'}`
    };
  }

// Cas 3 : crash
// ⚠️ FIX #8 : Ignorer les fichiers internes
const allMatches = [...stderr.matchAll(/File "\/home\/user\/([^"]+\.py)"/g)];
const fichiersProjet = allMatches
  .map(m => m[1])
  .filter(f => 
    !f.startsWith('_test') && 
    !f.startsWith('_kenny') && 
    f !== '_test_imports.py'
  );

const fichierCoupable = fichiersProjet.length > 0 
  ? fichiersProjet[0] 
  : mainFile.nom;

return {
  success: false,
  stderr: `ERREUR D'EXÉCUTION dans ${fichierCoupable} :\n\`\`\`\n${stderr.substring(0, 2500)}\n\`\`\``,
  fichierCoupable
};

// ============================================
// 🚀 PIPELINE COMPLET
// ============================================
async function testerCodePython(blocks) {
  let sb = null;
  try {
    console.log(`[TEST] === Début test (${blocks.length} fichiers) ===`);

    // 1. Upload
    sb = await sandbox.uploaderDansSandbox(blocks);
    console.log(`[TEST] ✅ Upload OK`);

    // 2. Détection type
    const typeInfo = detecterTypeProjet(blocks);
    console.log(`[TEST] Type détecté: ${typeInfo.type}`);

    // 🔧 FIX #6 : Créer les __init__.py manquants
const pyFiles = blocks.filter(b => b.nom.endsWith('.py'));
const dirsWithPy = new Set();
for (const f of pyFiles) {
  const parts = f.nom.split('/');
  if (parts.length > 1) {
    dirsWithPy.add(parts.slice(0, -1).join('/'));
  }
}

for (const dir of dirsWithPy) {
  const initPath = `${dir}/__init__.py`;
  if (!blocks.some(b => b.nom === initPath)) {
    try {
      await sb.commands.run(`cd ${ROOT} && touch ${initPath}`, { timeoutMs: 5000 });
      console.log(`📝 ${initPath} créé (auto)`);
    } catch (e) {
      console.log(`⚠️ Impossible de créer ${initPath}:`, e.message);
    }
  }
}
    // 3. Fichier principal
    const mainFile = blocks.find(b => b.nom === 'run.py')
              || blocks.find(b => b.nom === 'main.py')
              || blocks.find(b => b.nom === 'app.py')
              || blocks.find(b => b.nom === 'server.py')
              || blocks.find(b => b.nom === 'interface/serveur.py')  // ← AJOUT
              || blocks.find(b => b.nom.endsWith('/serveur.py'))      // ← AJOUT
              || blocks.find(b => b.nom.includes('serveur'));         // ← AJOUT
    
    if (!mainFile) {
      return {
        success: false,
        stderr: 'Aucun fichier principal trouvé (run.py, main.py, app.py, server.py)',
        exitCode: 1,
        sandbox: sb
      };
    }

    // 4. Syntaxe
    console.log(`[TEST] Test syntaxe...`);
    const syn = await testerSyntaxe(sb, blocks);
    if (!syn.success) return { ...syn, exitCode: 1, sandbox: sb };
    console.log(`[TEST] ✅ Syntaxe OK`);

    // 5. Install
    if (typeInfo.needsInstall) {
      console.log(`[TEST] Installation dépendances...`);
      const inst = await installerDependances(sb, blocks);
      if (!inst.success) return { ...inst, exitCode: 1, sandbox: sb };
      console.log(`[TEST] ✅ Dépendances OK`);
    }

    // 6. Imports
    console.log(`[TEST] Test imports...`);
    const imp = await testerImports(sb, blocks);
    if (!imp.success) return { ...imp, exitCode: 1, sandbox: sb };
    console.log(`[TEST] ✅ Imports OK`);

    // 7. Run
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
    if (sb && typeof sb.kill === 'function') await sb.kill().catch(() => {});
    return {
      success: false,
      stderr: `Erreur interne sandbox :\n${e.message}\n\nStack:\n${(e.stack || '').substring(0, 800)}`,
      stdout: '',
      exitCode: 1
    };
  }
}

module.exports = { testerCodePython, detecterTypeProjet };
