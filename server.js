const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { Client } = require('pg');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const antivirus = require('./agents/antivirus');
const sandbox = require('./agents/sandbox');

// [NEW] Garde-fous process
process.on('unhandledRejection', (err) => console.error('🔴 UnhandledRejection:', err));
process.on('uncaughtException', (err) => console.error('🔴 UncaughtException:', err));

const app = express();
const PORT = process.env.PORT || 3000;

// Constantes
const LIMITE_FREE = 50;
const MAX_HISTORY = 30;
const MAX_TERMINAL_HISTORY = 10;

// [FIX #18] CORS restreint
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim());
app.use(cors({
  origin: ALLOWED_ORIGINS.includes('*') ? true : ALLOWED_ORIGINS,
  credentials: true
}));
app.use(express.json({ limit: '2mb' }));

// [FIX #20] Rate limiting sur routes coûteuses
const iaLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Trop de requêtes IA, réessaie dans 1 minute.' },
  standardHeaders: true,
  legacyHeaders: false
});

// ============================================
// VARIABLES GLOBALES
// ============================================
const GLOBAL_KEYS = {
  gemini: process.env.GEMINI_API_KEY,
  neon: process.env.NEON_API_KEY,
  neonConn: process.env.NEON_CONNECTION_STRING,
  github: process.env.GITHUB_TOKEN,
  cloudflare: process.env.CLOUDFLARE_TOKEN,
  cloudflareAI: process.env.CLOUDFLARE_AI_TOKEN,
  cloudflareAccount: process.env.CLOUDFLARE_ACCOUNT_ID,
  render: process.env.RENDER_TOKEN,
  renderOwner: process.env.RENDER_OWNER_ID,
  e2b: process.env.E2B_API_KEY
};

// [FIX #22] Clé d'encryption obligatoire hors development
const ENCRYPTION_KEY_RAW = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY_RAW) {
  if (process.env.NODE_ENV !== 'development') {
    throw new Error('❌ ENCRYPTION_KEY obligatoire (hors NODE_ENV=development).');
  }
  console.warn('⚠️ ENCRYPTION_KEY absente — fallback DEV utilisé. NE PAS UTILISER EN PROD.');
}
const ENCRYPTION_KEY = crypto.scryptSync(
  ENCRYPTION_KEY_RAW || 'kenny_default_secret_key_2026',
  'kenny_salt_v1',
  32
);

const GEMINI_MODEL = 'gemini-3.8-flash';
const GEMINI_URL = (key) =>
  `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${key}`;

// ============================================
// 🛡️ WHITELIST AGENT GEMINI
// ============================================
const AGENT_COMMAND_WHITELIST = [
  /^ls(\s+[\w\-\.\/\*]+)*$/,
  /^cat\s+[\w\-\.\/]+$/,
  /^head\s+(-\d+\s+)?[\w\-\.\/]+$/,
  /^tail\s+(-\d+\s+)?[\w\-\.\/]+$/,
  /^find\s+\.[\s\w\-\*\.\"\'\(\)\/]+$/,
  /^tree(\s+[\w\-\.\/]+)?$/,
  /^pwd$/,
  /^which\s+\w+$/,
  /^stat\s+[\w\-\.\/]+$/,
  /^wc\s+-l\s+[\w\-\.\/]+$/,
  /^grep\s+(-n\s+)?["']?[\w\-\.]+["']?\s+[\w\-\.\/]+$/,
  /^python3?\s+--version$/,
  /^python3?\s+-c\s+["'][^"'`$\\]{1,200}["'](\s+2>&1)?$/,
  /^python3?\s+-m\s+py_compile\s+(?!.*\.\.)[\w\-\.\/\s]+(\s+2>&1)?$/,
  /^pip\s+list$/,
  /^pip\s+show\s+[\w\-]+$/,
  /^pip\s+freeze$/,
  /^timeout\s+\d+\s+python3?\s+(run|main|app)\.py(\s+2>&1)?$/,
  /^python3?\s+(run|main|app)\.py(\s+2>&1)?$/,
  /^pip\s+install\s+(flask|numpy|scipy|pandas|matplotlib|requests|python-dotenv|sqlalchemy|psycopg2-binary|beautifulsoup4|lxml|openpyxl|jinja2|werkzeug)(\s+[\w\.\<\>=]+)?$/,
  /^pip\s+install\s+-r\s+requirements\.txt$/
];

const AGENT_COMMAND_BLACKLIST = [
  /rm\s+-rf/, /sudo/, /chmod/, /chown/,
  /curl\s+/, /wget\s+/, /\bnc\s+/, /\bssh\s+/,
  /apt-get/, /apt\s+/,
  /\.\.\//, /;\s*rm/, /\|\s*sh/, /\|\s*bash/,
  /eval\s+/, /exec\s+/, />\s*\/dev/,
  /mkfs/, /dd\s+if=/, /:\(\)\s*\{/,
  /-delete/, /-exec\b/, /-execdir/, /-ok\b/, /-okdir/,
  /-fprint\b/, /-fprintf\b/, /-fls\b/,
  /python3?\s+-c\s+["'][^"']*\b(import|from)\s+(os|sys|subprocess|shutil|pty|socket|importlib)/i,
  /python3?\s+-c\s+["'][^"']*__import__/,
  /python3?\s+-c\s+["'][^"']*open\s*\(/,
  /python3?\s+-c\s+["'][^"']*exec\s*\(/,
  /python3?\s+-c\s+["'][^"']*eval\s*\(/,
  /`/, /\$\(/,
  /\bos\s*\.\s*system/, /\bsubprocess\s*\./,
];

function verifierCommandeAgent(cmd) {
  const cmdTrimmed = cmd.trim();
  for (const regex of AGENT_COMMAND_BLACKLIST) {
    if (regex.test(cmdTrimmed)) {
      return { allowed: false, reason: `Commande bloquée (sécurité) : ${cmdTrimmed}` };
    }
  }
  for (const regex of AGENT_COMMAND_WHITELIST) {
    if (regex.test(cmdTrimmed)) return { allowed: true };
  }
  return {
    allowed: false,
    reason: `Commande non autorisée. Permises : ls, cat, head, tail, find, tree, pwd, python3 -c, py_compile, pip list, timeout python3 run.py, pip install.`
  };
}

const IV_LENGTH = 16;

function chiffrer(text) {
  if (text === null || text === undefined) return null;
  const str = String(text);
  if (str === '') return '';
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(str);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function dechiffrer(text) {
  if (text === null || text === undefined) return null;
  if (typeof text !== 'string') return null;
  if (text === '') return '';
  const parts = text.split(':');
  if (parts.length !== 2) return null;
  const [ivHex, encHex] = parts;
  // Correction de la syntaxe cassée (\vert{}\vert{} -> ||)
  if (!/^[0-9a-f]{32}$/i.test(ivHex) || !/^[0-9a-f]+$/i.test(encHex)) return null;
  try {
    const iv = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (e) {
    return null;
  }
}

async function withPg(fn, connString = null) {
  const client = await getNeonClient(connString);
  try {
    return await fn(client);
  } finally {
    await client.end().catch(() => {});
  }
}

async function getNeonClient(connString = null) {
  const client = new Client({
    connectionString: connString || GLOBAL_KEYS.neonConn,
    ssl: { rejectUnauthorized: false },
    statement_timeout: 30000,
    query_timeout: 30000
  });
  await client.connect();
  return client;
}

async function verifierProprietaireProjet(firebase_uid, project_id) {
  if (!firebase_uid || !project_id) return false;
  try {
    return await withPg(async (client) => {
      const r = await client.query(
        `SELECT p.id FROM projects p
           JOIN users u ON u.id = p.user_id
         WHERE p.id = $1 AND u.firebase_uid = $2`,
        [project_id, firebase_uid]
      );
      return r.rows.length > 0;
    });
  } catch (e) {
    console.error('verifierProprietaireProjet:', e.message);
    return false;
  }
}

async function getKeysForUser(firebase_uid) {
  const keys = { ...GLOBAL_KEYS };
  if (!firebase_uid) return keys;
  try {
    await withPg(async (client) => {
      const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
      if (user.rows.length === 0) return;
      const userId = user.rows[0].id;
      const envVars = await client.query('SELECT key, value FROM env_variables WHERE user_id = $1', [userId]);
      for (const row of envVars.rows) {
        const k = row.key.toUpperCase().trim();
        const v = dechiffrer(row.value);
        if (v === null) continue;
        if (k === 'GEMINI_API_KEY' || k === 'GEMINI') keys.gemini = v;
        else if (k === 'NEON_API_KEY' || k === 'NEON') keys.neon = v;
        else if (k === 'NEON_CONNECTION_STRING' || k === 'NEON_CONN') keys.neonConn = v;
        else if (k === 'GITHUB_TOKEN' || k === 'GITHUB') keys.github = v;
        else if (k === 'CLOUDFLARE_TOKEN' || k === 'CLOUDFLARE') keys.cloudflare = v;
        else if (k === 'CLOUDFLARE_AI_TOKEN' || k === 'CLOUDFLARE_AI') keys.cloudflareAI = v;
        else if (k === 'CLOUDFLARE_ACCOUNT_ID' || k === 'CLOUDFLARE_ACCOUNT') keys.cloudflareAccount = v;
        else if (k === 'RENDER_TOKEN' || k === 'RENDER') keys.render = v;
        else if (k === 'RENDER_OWNER_ID' || k === 'RENDER_OWNER') keys.renderOwner = v;
        else if (k === 'E2B_API_KEY' || k === 'E2B') keys.e2b = v;
      }
    });
  } catch (e) {
    console.error('getKeysForUser error:', e.message);
  }
  return keys;
}

async function verifierQuota(firebase_uid) {
  try {
    return await withPg(async (client) => {
      const user = await client.query(
        'SELECT id, plan FROM users WHERE firebase_uid = $1',
        [firebase_uid]
      );
      if (user.rows.length === 0) return { allowed: false, error: 'User non trouvé' };
      const u = user.rows[0];

      if (u.plan === 'pro' || u.plan === 'premium') {
        return { allowed: true, remaining: '∞', plan: u.plan };
      }

      const today = new Date().toISOString().split('T')[0];

      const updated = await client.query(
        `UPDATE users
           SET commands_today = CASE
                 WHEN last_command_reset IS NULL OR last_command_reset::date <> $2::date
                 THEN 1
                 ELSE commands_today + 1
               END,
               last_command_reset = $2::date
         WHERE id = $1
           AND (
             last_command_reset IS NULL
             OR last_command_reset::date <> $2::date
             OR commands_today < $3
           )
         RETURNING commands_today`,
        [u.id, today, LIMITE_FREE]
      );

      if (updated.rowCount === 0) {
        return {
          allowed: false,
          error: `Limite atteinte (${LIMITE_FREE}/jour). Passe au plan Pro.`,
          plan: u.plan,
          used: LIMITE_FREE,
          limit: LIMITE_FREE
        };
      }

      const used = updated.rows[0].commands_today;
      return {
        allowed: true,
        plan: u.plan,
        used,
        limit: LIMITE_FREE,
        remaining: LIMITE_FREE - used
      };
    });
  } catch (e) {
    console.error('verifierQuota error:', e.message);
    return { allowed: false, error: e.message };
  }
}

app.get('/', (req, res) => {
  res.json({ message: 'Kenny OK', gemini: GLOBAL_KEYS.gemini ? '✅' : '❌', model: GEMINI_MODEL });
});

app.post('/api/user/sync', async (req, res) => {
  const { firebase_uid, email } = req.body;
  if (!firebase_uid || !email) return res.status(400).json({ error: 'Champs requis' });
  try {
    const userId = await withPg(async (client) => {
      const existing = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
      if (existing.rows.length > 0) {
        const id = existing.rows[0].id;
        await client.query('UPDATE users SET last_login = NOW() WHERE id = $1', [id]);
        return id;
      }
      const inserted = await client.query(
        'INSERT INTO users (firebase_uid, email) VALUES ($1, $2) RETURNING id',
        [firebase_uid, email]
      );
      return inserted.rows[0].id;
    });
    res.json({ success: true, user_id: userId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/env/load/:firebase_uid', async (req, res) => {
  try {
    const variables = await withPg(async (client) => {
      const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [req.params.firebase_uid]);
      if (user.rows.length === 0) return [];
      const result = await client.query(
        'SELECT key, value FROM env_variables WHERE user_id = $1 ORDER BY created_at ASC',
        [user.rows[0].id]
      );
      return result.rows.map(r => ({
        key: r.key,
        value: (r.value === null || r.value === undefined) ? '' : '••••••••'
      }));
    });
    res.json({ success: true, variables });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/env/save', async (req, res) => {
  const { firebase_uid, variables } = req.body;
  if (!firebase_uid || !Array.isArray(variables)) return res.status(400).json({ error: 'Champs requis' });

  try {
    await withPg(async (client) => {
      const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
      if (user.rows.length === 0) {
        const err = new Error('User non trouvé');
        err.status = 404;
        throw err;
      }
      const userId = user.rows[0].id;

      const old = await client.query('SELECT key, value FROM env_variables WHERE user_id = $1', [userId]);
      const oldMap = new Map();
      for (const row of old.rows) oldMap.set(row.key, row.value);

      const seenKeys = new Set();
      for (const v of variables) {
        if (!v.key || !v.key.trim()) continue;
        const trimmedKey = v.key.trim();
        if (seenKeys.has(trimmedKey)) {
          const err = new Error(`Variable "${trimmedKey}" en double`);
          err.status = 400;
          throw err;
        }
        seenKeys.add(trimmedKey);
        if (v.value === '••••••••' && !oldMap.has(trimmedKey)) {
          const err = new Error(`Variable "${trimmedKey}" : valeur masquée mais inexistante`);
          err.status = 400;
          throw err;
        }
      }

      await client.query('BEGIN');
      try {
        await client.query('DELETE FROM env_variables WHERE user_id = $1', [userId]);
        for (const v of variables) {
          if (!v.key || !v.key.trim()) continue;
          const trimmedKey = v.key.trim();
          
          let encrypted;
          if (v.value === '••••••••' && oldMap.has(trimmedKey)) {
            encrypted = oldMap.get(trimmedKey);
          } else {
            encrypted = (v.value === null || v.value === undefined) ? null : chiffrer(v.value);
          }

          await client.query(
            'INSERT INTO env_variables (user_id, key, value) VALUES ($1, $2, $3)',
            [userId, trimmedKey, encrypted]
          );
        }
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      }
    });
    res.json({ success: true });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});

app.post('/api/env/test', iaLimiter, async (req, res) => {
  const { key, value } = req.body;
  if (!key || !value) return res.status(400).json({ error: 'Champs requis' });
  const results = {};
  const k = key.toUpperCase().trim();
  try {
    if (k === 'GEMINI_API_KEY' || k === 'GEMINI') {
      await axios.post(GEMINI_URL(value), {
        contents: [{ role: 'user', parts: [{ text: 'test' }] }]
      }, { timeout: 10000 });
      results[key] = '✅ OK';
    } else if (k === 'NEON_API_KEY' || k === 'NEON') {
      await axios.get('https://console.neon.tech/api/v2/projects', {
        headers: { 'Authorization': `Bearer ${value}` },
        timeout: 10000
      });
      results[key] = '✅ OK';
    } else if (k === 'NEON_CONNECTION_STRING' || k === 'NEON_CONN') {
  try {
    const url = new URL(value);
    if (!url.hostname.endsWith('.neon.tech') && url.hostname !== 'localhost') {
      results[key] = '❌ Hôte Neon attendu (.neon.tech)';
      return res.json({ success: true, results });
    }
  } catch {
    results[key] = '❌ URL invalide';
    return res.json({ success: true, results });
  }
  const c = new Client({ connectionString: value, ssl: { rejectUnauthorized: false } });
  try {
    await c.connect();
    await c.query('SELECT 1');
  } finally {
    await c.end().catch(() => {});
  }
    results[key] = '✅ OK';
} else if (k === 'GITHUB_TOKEN' || k === 'GITHUB') {
      await axios.get('https://api.github.com/user', {
        headers: { 'Authorization': `token ${value}` },
        timeout: 10000
      });
      results[key] = '✅ OK';
    } else if (k === 'CLOUDFLARE_TOKEN' || k === 'CLOUDFLARE' || k === 'CLOUDFLARE_AI_TOKEN' || k === 'CLOUDFLARE_AI') {
      await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', {
        headers: { 'Authorization': `Bearer ${value}` },
        timeout: 10000
      });
      results[key] = '✅ OK';
    } else if (k === 'CLOUDFLARE_ACCOUNT_ID' || k === 'CLOUDFLARE_ACCOUNT') {
      const uuidRe = /^[0-9a-f]{32}$/i;
      results[key] = uuidRe.test(value.replace(/-/g, '')) ? '✅ Format UUID valide' : '⚠️ Ne ressemble pas à un Account ID';
    } else if (k === 'RENDER_TOKEN' || k === 'RENDER') {
      await axios.get('https://api.render.com/v1/services?limit=1', {
        headers: { 'Authorization': `Bearer ${value}` },
        timeout: 10000
      });
      results[key] = '✅ OK';
    } else if (k === 'RENDER_OWNER_ID' || k === 'RENDER_OWNER') {
      results[key] = /^[a-z0-9]+$/i.test(value) ? '✅ Format plausible' : '⚠️ Format douteux';
      } else if (k === 'E2B_API_KEY' || k === 'E2B') {
    results[key] = '⚠️ Test non implémenté';
  } else {
    results[key] = '⚠️ Type inconnu';
  }

  } catch (e) {
    results[key] = '❌ ' + (e.response?.status || e.message);
  }
  res.json({ success: true, results });
});

app.post('/api/projects/create', async (req, res) => {
  const { firebase_uid, name } = req.body;
  if (!firebase_uid || !name) return res.status(400).json({ error: 'Champs requis' });
  try {
    const project = await withPg(async (client) => {
      const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
      if (user.rows.length === 0) {
        const err = new Error('User non trouvé'); err.status = 404; throw err;
      }
      const p = await client.query(
        'INSERT INTO projects (user_id, name) VALUES ($1, $2) RETURNING *',
        [user.rows[0].id, name]
      );
      return p.rows[0];
    });
    res.json({ success: true, project });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});

app.get('/api/projects/list/:firebase_uid', async (req, res) => {
  try {
    const projects = await withPg(async (client) => {
      const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [req.params.firebase_uid]);
      if (user.rows.length === 0) return [];
      const p = await client.query(
        'SELECT * FROM projects WHERE user_id = $1 ORDER BY created_at DESC',
        [user.rows[0].id]
      );
      return p.rows;
    });
    res.json({ success: true, projects });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/projects/:project_id/details', async (req, res) => {
  const firebase_uid = req.headers['x-firebase-uid'];
  if (!firebase_uid) return res.status(400).json({ error: 'Header x-firebase-uid requis' });
  try {
    const data = await withPg(async (client) => {
      const project = await client.query(
        `SELECT p.* FROM projects p
           JOIN users u ON u.id = p.user_id
         WHERE p.id = $1 AND u.firebase_uid = $2`,
        [req.params.project_id, firebase_uid]
      );
      if (project.rows.length === 0) {
        const err = new Error('Projet non trouvé ou accès refusé'); err.status = 404; throw err;
      }
      const messages = await client.query(
        'SELECT role, content FROM conversation_memory WHERE project_id = $1 ORDER BY created_at ASC',
        [req.params.project_id]
      );
      const files = await client.query(
        'SELECT * FROM files WHERE project_id = $1 ORDER BY created_at ASC',
        [req.params.project_id]
      );
      const workspace = await client.query(
        'SELECT * FROM workspaces WHERE project_id = $1',
        [req.params.project_id]
      );
      return {
        project: project.rows[0],
        messages: messages.rows,
        files: files.rows,
        workspace: workspace.rows[0] || null
      };
    });
    res.json({ success: true, ...data });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});

async function creerRepoGitHub(name, userToken) {
  if (!userToken) return { success: false, error: 'Token GitHub manquant' };
  try {
    const repoName = 'kenny-' + name.toLowerCase().replace(/[^a-z0-9-]/g, '-').substring(0, 40) + '-' + Date.now().toString(36);
    const res = await axios.post('https://api.github.com/user/repos',
      { name: repoName, private: true, auto_init: true, description: 'App générée par Kenny' },
      { headers: { 'Authorization': `token ${userToken}`, 'Accept': 'application/vnd.github.v3+json' } }
    );
    return { success: true, repo: res.data.full_name, clone_url: res.data.clone_url, repo_url: res.data.html_url };
  } catch (e) {
    return { success: false, error: e.response?.data?.message || e.message };
  }
}

async function creerProjetNeon(name, neonKey) {
  if (!neonKey) return { success: false, error: 'Clé Neon manquante' };
  try {
    const projectName = 'kenny-' + name.toLowerCase().replace(/[^a-z0-9-]/g, '-').substring(0, 40) + '-' + Date.now().toString(36);
    const res = await axios.post('https://console.neon.tech/api/v2/projects',
      { project: { name: projectName, region_id: 'aws-eu-central-1', pg_version: 16 } },
      { headers: { 'Authorization': `Bearer ${neonKey}`, 'Content-Type': 'application/json', 'Accept': 'application/json' } }
    );
    const projectId = res.data.project.id;
    const connRes = await axios.get(
      `https://console.neon.tech/api/v2/projects/${projectId}/connection_uri?database_name=neondb&role_name=neondb_owner`,
      { headers: { 'Authorization': `Bearer ${neonKey}`, 'Accept': 'application/json' } }
    );
    return { success: true, project_id: projectId, connection_uri: connRes.data.uri };
  } catch (e) {
    return { success: false, error: e.response?.data?.message || e.message };
  }
}

async function creerServiceRender(name, repoUrl, userToken, ownerId, langage = 'web') {
  if (!userToken || !ownerId) return { success: false, skipped: true, reason: 'Token Render non configuré' };
  if (!repoUrl) return { success: false, skipped: true, reason: 'Repo GitHub indisponible' };
  try {
    const serviceName = 'kenny-' + name.toLowerCase().replace(/[^a-z0-9-]/g, '-').substring(0, 40) + '-' + Date.now().toString(36);

    const envConfig = langage === 'python'
      ? { buildCommand: 'pip install -r requirements.txt', startCommand: 'python run.py' }
      : { buildCommand: 'npm install', startCommand: 'node server.js' };

    const res = await axios.post('https://api.render.com/v1/services',
      {
        type: 'web_service',
        name: serviceName,
        ownerId,
        repo: repoUrl,
        branch: 'main',
        autoDeploy: 'yes',
        serviceDetails: {
          env: langage === 'python' ? 'python' : 'node',
          plan: 'free',
          region: 'frankfurt',
          envSpecificDetails: {
            buildCommand: envConfig.buildCommand,
            startCommand: envConfig.startCommand
          }
        }
      },
      { headers: { 'Authorization': `Bearer ${userToken}`, 'Content-Type': 'application/json', 'Accept': 'application/json' } }
    );
    return { success: true, service_id: res.data.service.id, service_url: res.data.service.serviceDetails?.url };
  } catch (e) {
    return { success: false, error: e.response?.data?.message || e.message };
  }
}

async function creerZoneCloudflare() {
  return { success: false, skipped: true, reason: 'Cloudflare désactivé temporairement' };
}

const workspaceLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Trop de créations de workspace, réessaie dans 1 minute.' }
});

app.post('/api/workspaces/create', workspaceLimiter, async (req, res) => {
  const { firebase_uid, project_id, project_name } = req.body;
  try {
    const workspaceId = await withPg(async (client) => {
      const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
      if (user.rows.length === 0) { const e = new Error('User non trouvé'); e.status = 404; throw e; }
      const userId = user.rows[0].id;

      const owned = await client.query('SELECT id FROM projects WHERE id = $1 AND user_id = $2', [project_id, userId]);
      if (owned.rows.length === 0) { const e = new Error('Ce projet ne t\'appartient pas'); e.status = 403; throw e; }

      const existing = await client.query(
  'SELECT id FROM workspaces WHERE project_id = $1',
  [project_id]
);
if (existing.rows.length > 0) {
  const e = new Error('Un workspace existe déjà pour ce projet');
  e.status = 409;
  throw e;
}

  const ws = await client.query(
    'INSERT INTO workspaces (project_id, user_id, status) VALUES ($1, $2, $3) RETURNING id',
    [project_id, userId, 'creating']
  );
  return ws.rows[0].id;
});
    const keys = await getKeysForUser(firebase_uid);

    console.log('📦 GitHub...');
    const githubResult = await creerRepoGitHub(project_name, keys.github);

    console.log('🗄️ Neon...');
    const neonResult = await creerProjetNeon(project_name, keys.neon);

    console.log('🚀 Render...');
    const renderResult = await creerServiceRender(
      project_name,
      githubResult.success ? githubResult.clone_url : '',
      keys.render,
      keys.renderOwner,
      'web'
    );

    console.log('🌐 Cloudflare (désactivé)');
    const cloudflareResult = await creerZoneCloudflare();

    await withPg(async (client) => {
      await client.query(`
        UPDATE workspaces SET
          github_repo = $1, github_clone_url = $2,
          neon_project_id = $3, neon_connection_string = $4,
          render_service_id = $5, render_service_url = $6,
          cloudflare_zone_id = $7, cloudflare_domain = $8,
          status = $9
        WHERE id = $10
      `, [
        githubResult.repo || null, githubResult.clone_url || null,
        neonResult.project_id || null, neonResult.connection_uri || null,
        renderResult.service_id || null, renderResult.service_url || null,
        null, null, 'ready', workspaceId
      ]);
    });

    res.json({ success: true, workspace: { github: githubResult, neon: neonResult, render: renderResult, cloudflare: cloudflareResult } });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});

function extraireBlocs(text) {
  const regex = /```([a-zA-Z0-9_+\-]*)(?:[:\s]+([^\s\n`]+))?\s*\n([\s\S]*?)```/g;
  const blocs = [];
  let match;
  while ((match = regex.exec(text)) !== null) {
    const langage = (match[1] || 'code').toLowerCase();
    let nomFichier = match[2] ? match[2].trim() : null;
    const contenu = match[3].trim();
    if (!contenu) continue;

    let nom = nomFichier;
    if (!nom) {
      if (contenu.includes('from flask import') || contenu.includes('import flask')) {
        nom = 'app.py';
      } else if (contenu.includes('if __name__ ==')) {
        nom = 'run.py';
      } else {
        const ext = langage === 'html' ? 'html'
          : ['javascript', 'js'].includes(langage) ? 'js'
          : langage === 'css' ? 'css'
          : langage === 'json' ? 'json'
          : ['python', 'py'].includes(langage) ? 'py'
          : ['markdown', 'md'].includes(langage) ? 'md'
          : ['bash', 'sh'].includes(langage) ? 'sh'
          : 'txt';
        nom = `fichier${blocs.length + 1}.${ext}`;
      }
    }

    nom = nom.replace(/^[\s:]+|[\s:]+$/g, '').replace(/\s+/g, '_');

    let finalNom = nom;
    let counter = 1;
    while (blocs.some(b => b.nom === finalNom)) {
      const dot = nom.lastIndexOf('.');
      finalNom = dot > 0
        ? `${nom.substring(0, dot)}_${counter}${nom.substring(dot)}`
        : `${nom}_${counter}`;
      counter++;
    }

    blocs.push({ langage, nom: finalNom, contenu });
  }
  return blocs;
}

function tailTruncate(s, n) {
  if (!s) return '';
  return s.length > n ? '...' + s.slice(-n) : s;
}

app.post('/api/build/full', iaLimiter, async (req, res) => {
  const { firebase_uid, project_id, prompt } = req.body;
  if (!firebase_uid || !project_id || !prompt) return res.status(400).json({ error: 'Champs requis' });

  const owns = await verifierProprietaireProjet(firebase_uid, project_id);
  if (!owns) return res.status(403).json({ error: 'Accès refusé à ce projet' });

  const quota = await verifierQuota(firebase_uid);
  if (!quota.allowed) return res.status(429).json({ error: quota.error, plan: quota.plan });

  const keys = await getKeysForUser(firebase_uid);
  if (!keys.gemini) return res.status(500).json({ error: 'Clé Gemini manquante' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  let closed = false;
  req.on('close', () => { closed = true; });
  const envoyer = (type, data) => {
    if (closed || res.writableEnded) return;
    try { res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`); } catch (e) {}
  };

  try {
    envoyer('status', { message: '🧠 Analyse de la demande...' });

    const systemPrompt = `Tu es un développeur senior expert. Tu vas générer une application COMPLÈTE (Full Build) avec frontend, backend, et base de données.

RÈGLES ABSOLUES :
1. STRUCTURE OBLIGATOIRE :
   - \`\`\`html:index.html\`\`\` → Le frontend principal
   - \`\`\`css:style.css\`\`\` → Le CSS
   - \`\`\`javascript:script.js\`\`\` → Le JS frontend
   - \`\`\`javascript:server.js\`\`\` → Le backend Express
   - \`\`\`json:package.json\`\`\` → Les dépendances
   - \`\`\`markdown:README.md\`\`\` → Documentation

2. BACKEND (server.js) : Express, routes /api/*, PostgreSQL via pg, port process.env.PORT || 3000.
3. PACKAGE.JSON : name, version, main, scripts.start, dependencies (express, cors, pg, dotenv).
4. FRONTEND : HTML complet, CSS moderne, JS avec fetch vers /api, pas d'emojis dans le code.
5. Toutes les fonctionnalités marchent (recherche, CRUD, gestion d'erreurs).
6. Format de sortie : explication courte puis TOUS les fichiers avec \`\`\`langage:nom_fichier.
7. Ne t'arrête PAS au milieu.`;

    envoyer('status', { message: '🔨 Génération du code complet...' });

    const response = await axios.post(
      GEMINI_URL(keys.gemini),
      {
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 8000 }
      },
      { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
    );

    if (closed) return res.end();

    const reponse = response.data.candidates[0].content.parts[0].text;
    const blocks = extraireBlocs(reponse);

    envoyer('status', { message: `📦 ${blocks.length} fichiers générés, sauvegarde...` });

    await withPg(async (client) => {
      await client.query('DELETE FROM files WHERE project_id = $1', [project_id]);
      for (const file of blocks) {
        await client.query(
          'INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
          [project_id, file.nom, file.langage, file.contenu]
        );
        envoyer('file', { name: file.nom, language: file.langage, content: file.contenu });
      }
    });

    const ws = await withPg(async (client) => {
      const r = await client.query('SELECT * FROM workspaces WHERE project_id = $1', [project_id]);
      return r.rows[0] || null;
    });

    if (ws?.github_repo) {
      envoyer('status', { message: '🐙 Push sur GitHub...' });
      const pushResults = await pushGitHubMultiDossiers(ws.github_repo, blocks, keys.github);
      const reussis = pushResults.filter(r => r.success).length;
      if (reussis === 0) {
        envoyer('status', { message: `⚠️ 0/${pushResults.length} fichiers pushés — vérifie le token GitHub` });
      } else {
        envoyer('status', { message: `✅ ${reussis}/${pushResults.length} fichiers pushés sur GitHub` });
      }
    }

    const finalUrl = ws?.render_service_url || ws?.github_repo || 'En cours...';
    envoyer('done', { message: '✅ Full Build terminé !', url: finalUrl, files_count: blocks.length, tested: true });
    
    if (!closed && !res.writableEnded) { res.write('event: end\ndata: {}\n\n'); res.end(); }
  } catch (error) {
    console.error('Erreur full build:', error.message);
    envoyer('error', { message: error.response?.data?.error?.message || error.message });
    if (!closed && !res.writableEnded) { res.write('event: end\ndata: {}\n\n'); res.end(); }
  }
});

async function uploaderDansSandbox(blocks) {
  const sb = await sandbox.creerSandbox();
  for (const block of blocks) {
    try {
      const parts = block.nom.split('/');
      if (parts.length > 1) {
        const dirPath = parts.slice(0, -1).join('/');
        await sb.commands.run(`mkdir -p "${dirPath}"`, { timeoutMs: 5000 });
      }
      await sb.filesystem.write(block.nom, block.contenu);
    } catch (e) {
      console.log(`Erreur upload ${block.nom}:`, e.message);
    }
  }
  return sb;
}

async function testerCodePython(blocks) {
  let sb = null;
  try {
    sb = await uploaderDansSandbox(blocks);

    const mainFile = blocks.find(b => b.nom === 'run.py')
                  || blocks.find(b => b.nom === 'main.py')
                  || blocks.find(b => b.nom === 'app.py');

    if (!mainFile) {
      return { success: false, stderr: 'Aucun fichier principal trouvé (run.py, main.py, app.py)', stdout: '', exitCode: 1, sandbox: sb };
    }

    const reqFile = blocks.find(b => b.nom === 'requirements.txt');
    if (reqFile) {
      const installResult = await sb.commands.run('pip install -r requirements.txt 2>&1', { timeoutMs: 180000 });
      if (installResult.exitCode !== 0) {
        const installLog = (installResult.stdout || '') + '\n' + (installResult.stderr || '');
        return {
          success: false,
          stdout: installLog.substring(0, 3000),
          stderr: `ÉCHEC PIP INSTALL (exit ${installResult.exitCode}) :\n${tailTruncate(installLog, 2000)}`,
          exitCode: installResult.exitCode,
          sandbox: sb
        };
      }
    }

    const allPyFiles = blocks.filter(b => b.nom.endsWith('.py')).map(b => b.nom);
    if (allPyFiles.length > 0) {
      const pyCompile = await sb.commands.run(
        `python3 -m py_compile ${allPyFiles.join(' ')} 2>&1`,
        { timeoutMs: 20000 }
      );
      if (pyCompile.exitCode !== 0) {
        const compileLog = (pyCompile.stdout || '') + '\n' + (pyCompile.stderr || '');
        return {
          success: false,
          stdout: compileLog.substring(0, 3000),
          stderr: `ERREUR DE SYNTAXE PYTHON :\n${tailTruncate(compileLog, 2000)}`,
          exitCode: pyCompile.exitCode,
          sandbox: sb
        };
      }
    }

    const importTestScript = `import sys, os, traceback
sys.path.insert(0, os.getcwd())
target = "${mainFile.nom}"
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("__test_main__", target)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    print("IMPORT_OK")
except SystemExit:
    print("IMPORT_OK")
except Exception as e:
    print("IMPORT_ERROR_START")
    traceback.print_exc()
    print("IMPORT_ERROR_END")
    sys.exit(1)`.trim();

    await sb.filesystem.write('_kenny_import_test.py', importTestScript);

    const importResult = await sb.commands.run('python3 _kenny_import_test.py 2>&1', { timeoutMs: 30000 });
    const importLog = (importResult.stdout || '') + '\n' + (importResult.stderr || '');

    if (importLog.includes('IMPORT_ERROR_START')) {
      const start = importLog.indexOf('IMPORT_ERROR_START') + 'IMPORT_ERROR_START'.length;
      const end = importLog.indexOf('IMPORT_ERROR_END');
      const traceback = importLog.substring(start, end > 0 ? end : undefined).trim();
      return {
        success: false,
        stdout: importLog.substring(0, 3000),
        stderr: `ERREUR D'IMPORT DANS ${mainFile.nom} :\n\`\`\`\n${tailTruncate(traceback, 2000)}\n\`\`\``,
        exitCode: 1,
        sandbox: sb
      };
    }

    const runTest = await sb.commands.run(
  `timeout 10 python3 ${mainFile.nom} > /tmp/run_out.log 2> /tmp/run_err.log; EXIT=$?; echo "---EXITCODE---"; echo $EXIT; echo "---STDOUT---"; cat /tmp/run_out.log; echo "---STDERR---"; cat /tmp/run_err.log`,
  { timeoutMs: 15000 }
);
const runLog = (runTest.stdout || '') + '\n' + (runTest.stderr || '');

// Parser robuste : tolère CRLF et espaces variés
const exitMatch = runLog.match(/---EXITCODE---\s*[\r\n]+(\d+)/);
const scriptExit = exitMatch ? parseInt(exitMatch[1]) : -1;

const stdoutMatch = runLog.match(/---STDOUT---\s*[\r\n]+([\s\S]*?)(?:[\r\n]+---STDERR---|$)/);
const stderrMatch = runLog.match(/---STDERR---\s*[\r\n]+([\s\S]*?)$/);
const scriptStdout = stdoutMatch ? stdoutMatch[1].trim() : '';
const scriptStderr = stderrMatch ? stderrMatch[1].trim() : '';

// Si le parsing a échoué, essayer un fallback : considérer exit 0 si pas de marqueur d'erreur
if (scriptExit === -1) {
  // Fallback : si runLog contient "Hello" ou du texte sans "Traceback" ni "Error"
  const hasError = /traceback|error|exception/i.test(runLog);
  if (!hasError && runLog.length > 0) {
    return {
      success: true,
      stdout: `✅ Script exécuté (parsing fallback).\n${runLog.substring(0, 500)}`,
      stderr: '',
      exitCode: 0,
      sandbox: sb
    };
  }
}
    if (scriptExit === 0 && !scriptStderr.includes('Traceback')) {
      return {
        success: true,
        stdout: `✅ Script exécuté avec succès (exit 0).\n${scriptStdout.substring(0, 500) || '(pas de sortie)'}`,
        stderr: '', exitCode: 0, sandbox: sb
      };
    }

    if (scriptExit === 124) {
      const serveurPattern = /(running on|serving|listening|http:\/\/|localhost|127\.0\.0\.1|debugger|werkzeug|flask|uvicorn|gunicorn)/i;
      const ressembleServeur = serveurPattern.test(scriptStdout) || serveurPattern.test(scriptStderr);
      if (ressembleServeur) {
        return {
          success: true,
          stdout: `✅ Serveur lancé et stable (timeout atteint).\n${scriptStdout.substring(0, 500)}`,
          stderr: '', exitCode: 0, sandbox: sb
        };
      }
      return {
        success: false,
        stdout: runLog.substring(0, 3000),
        stderr: `⚠️ Le script a bloqué 10s sans afficher de serveur (timeout).\nSortie : ${scriptStdout.substring(0, 1000)}\n${tailTruncate(scriptStderr, 1000)}`,
        exitCode: 124, sandbox: sb
      };
    }

    return {
      success: false,
      stdout: runLog.substring(0, 3000),
      stderr: `CRASH DE ${mainFile.nom} (exit${scriptExit}) :\n\`\`\`\n${tailTruncate(scriptStderr, 2500)}\n\`\`\``,
      exitCode: scriptExit, sandbox: sb
    };
  } catch (e) {
    if (sb && typeof sb.kill === 'function') await sb.kill().catch(() => {});
    return { success: false, stderr: `Erreur interne sandbox :\n${e.message}`, stdout: '', exitCode: 1 };
  }
}

async function corrigerAvecAgent(blocks, testResult, keys, sandboxInstance) {
  const agentSystemPrompt = `Tu es un développeur senior qui CORRIGE un projet Python cassé.

Tu as accès à un TERMINAL LINUX via des balises [CMD: commande].

DÉROULEMENT :
1. Tu reçois le projet + l'erreur détectée
2. Tu EXÉCUTES des commandes pour INVESTIGUER
3. Tu observes les résultats
4. Tu continues jusqu'à comprendre la cause EXACTE
5. Puis tu renvoies [FIX] + les fichiers corrigés

COMMANDES AUTORISÉES : ls, cat, head, tail, find, tree, pwd, which, stat, wc, grep, python3 -c, py_compile, pip list, pip show, pip freeze, timeout 30 python3 run.py 2>&1, pip install

COMMANDES INTERDITES : rm, sudo, chmod, curl, wget, apt-get, eval, exec, > /dev/, ../

FORMAT :
- [CMD: <commande>] pour exécuter
- [FIX] + explication FR + fichiers corrigés pour corriger

RÈGLES :
- N'invente JAMAIS une erreur. Base-toi UNIQUEMENT sur les logs réels.
- Vérifie chaque hypothèse avant de corriger.
- Format fichiers : \`\`\`python:nom_fichier
- Ne renomme PAS les fichiers.

MAX 5 TOURS.`;

  const conversationHistory = [{
    role: 'user',
    parts: [{
      text: `Voici le projet Python qui plante.

=== FICHIERS ===
${blocks.map(b => `\n--- ${b.nom} ---\n${b.contenu}`).join('\n')}

=== ERREUR DÉTECTÉE ===
${testResult.stderr}

=== SORTIE ===
${(testResult.stdout || '').substring(0, 1000)}

Investigue avec [CMD:], puis corrige avec [FIX].`
    }]
  }];

  const logsExecution = [];
  const MAX_TOURS = 5;

  for (let tour = 1; tour <= MAX_TOURS; tour++) {
    console.log(`🤖 Agent Gemini - tour ${tour}/${MAX_TOURS}`);

    let response;
    let tentativesGemini = 0;
    const MAX_TENTATIVES_GEMINI = 3;
    while (tentativesGemini < MAX_TENTATIVES_GEMINI) {
      tentativesGemini++;
      try {
        response = await axios.post(
          GEMINI_URL(keys.gemini),
          {
            systemInstruction: { parts: [{ text: agentSystemPrompt }] },
            contents: conversationHistory,
            generationConfig: { temperature: 0.3, maxOutputTokens: 8000 }
          },
          { headers: { 'Content-Type': 'application/json' }, timeout: 120000 }
        );
        break;
      } catch (err) {
        const status = err.response?.status;
        if (status === 503 || status === 429) {
          console.log(`⏳ Gemini ${status} au tour${tour} - retry ${tentativesGemini}/${MAX_TENTATIVES_GEMINI}...`);
          if (tentativesGemini < MAX_TENTATIVES_GEMINI) {
            await new Promise(r => setTimeout(r, 3000));
            continue;
          }
        }
        console.log(`❌ Agent Gemini erreur tour ${tour}:`, err.message);
        return { success: false, error: `Gemini API : ${err.message}`, logsExecution };
      }
    }

    const reponse = response.data.candidates[0].content.parts[0].text;

    if (reponse.includes('[FIX]')) {
      const fixIndex = reponse.indexOf('[FIX]');
      const explication = reponse.substring(0, fixIndex).trim();
      const blocFix = reponse.substring(fixIndex);
      const blocksCorriges = extraireBlocs(blocFix);

      if (blocksCorriges.length === 0) {
        conversationHistory.push({ role: 'model', parts: [{ text: reponse }] });
        conversationHistory.push({ role: 'user', parts: [{ text: 'Tu as dit [FIX] mais tu n\'as envoyé aucun fichier. Envoie TOUS les fichiers corrigés au format ```python:nom_fichier' }] });
        continue;
      }

      return { success: true, explication, blocks: blocksCorriges, logsExecution, tours: tour };
    }

    const cmdRegex = /\[CMD:\s*(.+?)\]/g;
    const commandes = [];
    let match;
    while ((match = cmdRegex.exec(reponse)) !== null) {
      commandes.push(match[1].trim());
    }

    if (commandes.length === 0) {
      conversationHistory.push({ role: 'model', parts: [{ text: reponse }] });
      conversationHistory.push({ role: 'user', parts: [{ text: 'Tu dois envoyer soit [CMD: commande], soit [FIX]. Recommence.' }] });
      continue;
    }

    const resultats = [];
    for (const cmd of commandes) {
      const verif = verifierCommandeAgent(cmd);
      if (!verif.allowed) {
        console.log(`  🚫 [CMD bloquée] ${cmd} →${verif.reason}`);
        resultats.push({ cmd, success: false, blocked: true, stdout: '', stderr: `❌ COMMANDE BLOQUÉE : ${verif.reason}`, exitCode: 1 });
        logsExecution.push({ tour, cmd, blocked: true, reason: verif.reason });
        continue;
      }

      console.log(`  💻 [CMD] ${cmd}`);
      try {
        const result = await sandboxInstance.commands.run(cmd, { timeoutMs: 45000 });
        const r = {
          cmd,
          success: result.exitCode === 0,
          stdout: (result.stdout || '').substring(0, 3000),
          stderr: tailTruncate(result.stderr || '', 1500),
          exitCode: result.exitCode
        };
        resultats.push(r);
        logsExecution.push({ tour, ...r });
      } catch (err) {
        // [FIX] Erreur correctement fermée ici
        resultats.push({ cmd, success: false, stdout: '', stderr: `Erreur exécution : ${err.message}`, exitCode: 1 });
        logsExecution.push({ tour, cmd, success: false, error: err.message });
      }
    }

    conversationHistory.push({ role: 'model', parts: [{ text: reponse }] });
    conversationHistory.push({
      role: 'user',
      parts: [{
        text: `RÉSULTATS :\n\n${resultats.map(r =>
          `[CMD: ${r.cmd}]${r.blocked ? ' (BLOQUÉE)' : ''}\nEXIT: ${r.exitCode}\n--- stdout ---\n${r.stdout || '(vide)'}\n--- stderr ---\n${r.stderr || '(vide)'}`
        ).join('\n\n')}\n\nContinue l'investigation OU renvoie [FIX] avec les fichiers corrigés.`
      }]
    });
  }

  return {
    success: false,
    error: 'Agent Gemini n\'a pas trouvé de correction après 5 tours',
    logsExecution
  };
}

async function pushGitHubMultiDossiers(repoFullName, blocks, githubToken) {
  if (!githubToken || !repoFullName) {
    return blocks.map(b => ({ file: b.nom, success: false, error: 'Token ou repo manquant' }));
  }
  const results = [];
  const CONCURRENCY = 5;
  for (let i = 0; i < blocks.length; i += CONCURRENCY) {
    const batch = blocks.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(batch.map(async (file) => {
      try {
        let sha = null;
        try {
          const checkRes = await axios.get(
  `https://api.github.com/repos/${repoFullName}/contents/${file.nom}`,
  { headers: { 'Authorization': `token ${githubToken}`, 'Accept': 'application/vnd.github.v3+json' } }
);
          sha = checkRes.data.sha;
        } catch (e) {}

        await axios.put(
  `https://api.github.com/repos/${repoFullName}/contents/${file.nom}`,
  {
            message: `Ajout ${file.nom}`,
            content: Buffer.from(file.contenu).toString('base64'),
            ...(sha && { sha })
          },
          { headers: { 'Authorization': `token ${githubToken}`, 'Accept': 'application/vnd.github.v3+json' } }
        );
        return { file: file.nom, success: true };
      } catch (e) {
        return { file: file.nom, success: false, error: e.response?.data?.message || e.message };
      }
    }));
    results.push(...batchResults);
  }
  return results;
}

app.post('/api/build/python', iaLimiter, async (req, res) => {
  const { firebase_uid, project_id, prompt } = req.body;
  if (!firebase_uid || !project_id || !prompt) return res.status(400).json({ error: 'Champs requis' });

  const owns = await verifierProprietaireProjet(firebase_uid, project_id);
  if (!owns) return res.status(403).json({ error: 'Accès refusé à ce projet' });

  const quota = await verifierQuota(firebase_uid);
  if (!quota.allowed) return res.status(429).json({ error: quota.error, plan: quota.plan });

  const keys = await getKeysForUser(firebase_uid);
  if (!keys.gemini) return res.status(500).json({ error: 'Clé Gemini manquante' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  let closed = false;
  req.on('close', () => { closed = true; });
  const envoyer = (type, data) => {
    if (closed || res.writableEnded) return;
    try { res.write(`event: ${type}\ndata:${JSON.stringify(data)}\n\n`); } catch (e) {}
  };

  let sandboxFinale = null;

  try {
    envoyer('status', { message: '🧠 Génération du code Python...' });

    const systemPrompt = `Tu es un développeur expert en Python, Flask et data science.

Génère une application COMPLÈTE et FONCTIONNELLE avec cette structure :
- \`\`\`python:moteur/config.py\`\`\`
- \`\`\`python:moteur/moteur.py\`\`\`
- \`\`\`python:interface/serveur.py\`\`\`
- \`\`\`html:templates/index.html\`\`\`
- \`\`\`json:data/donnees.json\`\`\`
- \`\`\`txt:requirements.txt\`\`\`
- \`\`\`python:run.py\`\`\`

RÈGLES ABSOLUES :
1. Code complet et fonctionnel, pas de "..." ni "TODO"
2. requirements.txt avec toutes les dépendances
3. run.py lance l'app Flask sur port process.env.PORT || 3000
4. Pas d'emojis dans le code`;

    const response = await axios.post(
      GEMINI_URL(keys.gemini),
      {
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 8000 }
      },
      { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
    );

    if (closed) return res.end();

    let blocks = extraireBlocs(response.data.candidates[0].content.parts[0].text);
    envoyer('status', { message: `📦 ${blocks.length} fichiers générés` });

    await withPg(async (client) => {
      await client.query('DELETE FROM files WHERE project_id = $1', [project_id]);
      for (const file of blocks) {
        await client.query(
          'INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
          [project_id, file.nom, file.langage, file.contenu]
        );
        envoyer('file', { name: file.nom, language: file.langage, content: file.contenu });
      }
    });

    envoyer('status', { message: '🧪 Test du code dans la sandbox...' });
    let testResult = await testerCodePython(blocks);
    sandboxFinale = testResult.sandbox;
    let essais = 0;
    const MAX_ESSAIS = 3;

    while (!testResult.success && essais < MAX_ESSAIS && !closed) {
      essais++;
      envoyer('status', { message: `🤖 Agent Gemini - tentative ${essais}/${MAX_ESSAIS}...` });

      try {
        const agentResult = await corrigerAvecAgent(blocks, testResult, keys, testResult.sandbox);

        for (const log of (agentResult.logsExecution || [])) {
          envoyer('agent_log', {
            tour: log.tour, cmd: log.cmd, success: log.success,
            blocked: log.blocked || false, stdout: log.stdout || '',
            stderr: log.stderr || '', exitCode: log.exitCode,
            reason: log.reason || null
          });
        }

        if (!agentResult.success) {
          envoyer('message', {
            role: 'ia',
            content: `⚠️ Agent Gemini n'a pas trouvé de correction au tour ${essais}.${agentResult.error || ''}`
          });
          break;
        }

        if (agentResult.explication) {
          envoyer('message', {
            role: 'ia',
            content: `Tentative ${essais}/${MAX_ESSAIS} :${agentResult.explication.substring(0, 800)}`
          });
        }

        blocks = agentResult.blocks;

        await withPg(async (client) => {
          await client.query('DELETE FROM files WHERE project_id = $1', [project_id]);
          for (const file of blocks) {
            await client.query(
              'INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
              [project_id, file.nom, file.langage, file.contenu]
            );
            envoyer('file', { name: file.nom, language: file.langage, content: file.contenu });
          }
        });

        const newTestResult = await testerCodePython(blocks);

        if (testResult.sandbox && testResult.sandbox !== newTestResult.sandbox) {
          if (typeof testResult.sandbox.kill === 'function') {
            await testResult.sandbox.kill().catch(() => {});
          }
        }
        testResult = newTestResult;
        sandboxFinale = testResult.sandbox;
      } catch (e) {
        console.log('Erreur agent:', e.message);
        envoyer('message', { role: 'ia', content: `Erreur agent : ${e.message}` });
        break;
      }
    }

    if (testResult.success) {
      envoyer('message', {
        role: 'ia',
        content: `✅ Code testé avec succès${essais > 0 ? ` (après ${essais} correction${essais > 1 ? 's' : ''})` : ''} !\n\nSortie :\n\`\`\`\n${testResult.stdout.substring(0, 500)}\n\`\`\``
      });
    } else {
      envoyer('message', {
        role: 'ia',
        content: `⚠️ Le code a été généré mais n'a pas pu être corrigé après ${essais} tentative(s).`
      });
    }

    const ws = await withPg(async (client) => {
      const r = await client.query('SELECT * FROM workspaces WHERE project_id = $1', [project_id]);
      return r.rows[0] || null;
    });

    if (ws?.github_repo) {
      envoyer('status', { message: '🐙 Push sur GitHub...' });
      const pushResults = await pushGitHubMultiDossiers(ws.github_repo, blocks, keys.github);
      const reussis = pushResults.filter(r => r.success).length;
      envoyer('status', { message: `✅ ${reussis}/${pushResults.length} fichiers pushés sur GitHub` });
    }

    const finalUrl = ws?.render_service_url || ws?.github_repo || 'En cours...';
    envoyer('done', {
      message: '✅ Build Python terminé !',
      url: finalUrl,
      files_count: blocks.length,
      tested: testResult.success
    });

    if (!closed && !res.writableEnded) { res.write('event: end\ndata: {}\n\n'); res.end(); }
  } catch (error) {
    console.error('Erreur build python:', error.message);
    envoyer('error', { message: error.response?.data?.error?.message || error.message });
    if (!closed && !res.writableEnded) { res.write('event: end\ndata: {}\n\n'); res.end(); }
  } finally {
    if (sandboxFinale && typeof sandboxFinale.kill === 'function') {
      sandboxFinale.kill().catch(() => {});
    }
  }
});

app.post('/api/chat/stream', iaLimiter, async (req, res) => {
  const { message, history, firebase_uid, project_id, terminal_history } = req.body;

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'Message (string) requis' });
  }
  if (!firebase_uid) return res.status(400).json({ error: 'firebase_uid requis' });
  if (!project_id) return res.json({ error: 'Crée un projet d\'abord', need_project: true });

  const owns = await verifierProprietaireProjet(firebase_uid, project_id);
  if (!owns) return res.status(403).json({ error: 'Accès refusé à ce projet' });

  const quota = await verifierQuota(firebase_uid);
  if (!quota.allowed) return res.status(429).json({ error: quota.error, plan: quota.plan });

  const keys = await getKeysForUser(firebase_uid);
  if (!keys.gemini) return res.status(500).json({ error: 'Clé Gemini manquante' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  let closed = false;
  req.on('close', () => { closed = true; });
  const envoyer = (type, data) => {
    if (closed || res.writableEnded) return;
    try { res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`); } catch (e) {}
  };

  try {
    const contents = [];
    if (Array.isArray(history)) {
      const recent = history.slice(-MAX_HISTORY);
      recent.forEach(msg => {
        if (!msg || typeof msg.content !== 'string') return;
        contents.push({ role: msg.role === 'user' ? 'user' : 'model', parts: [{ text: msg.content }] });
      });
    }

    let terminalContext = '';
    if (Array.isArray(terminal_history) && terminal_history.length > 0) {
      const lines = terminal_history
        .slice(-MAX_TERMINAL_HISTORY)
        .map(t => typeof t === 'string' ? t : JSON.stringify(t));
      terminalContext = `\n\nCOMMANDES RÉCENTES :\n${lines.join('\n')}`;
    }
    contents.push({ role: 'user', parts: [{ text: message }] });

    let iteration = 0;
    const MAX_ITERATIONS = 3;
    let memoire = [];
    const dejaAffiche = new Set();

    while (iteration < MAX_ITERATIONS && !closed) {
      iteration++;
      envoyer('status', { message: `Étape ${iteration}/${MAX_ITERATIONS}...` });

      const systemPrompt = `Tu es un développeur senior expert. Ton caractère est comme ChatGPT.
- Tu PARLES et tu CODES EN MÊME TEMPS.
- Tu ne te présentes JAMAIS.
- Tu réponds en français.

1. AUTO-INSTALLATION :
   - [INSTALL: pip install flask] / [INSTALL: npm install react]
2. CODE : HTML/CSS/JS complet
3. IMAGES : [IMAGE: description en anglais]

${terminalContext}
MÉMOIRE :
${memoire.join('\n')}`;

      const response = await axios.post(
        GEMINI_URL(keys.gemini),
        {
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents,
          generationConfig: { temperature: 0.8, maxOutputTokens: 8000 }
        },
        { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
      );

      if (closed) break;

      let reponse = response.data.candidates[0].content.parts[0].text;

      const installations = [];
      let match;
      const installRegex = /\[INSTALL:\s*(.+?)\]/gi;
      while ((match = installRegex.exec(reponse)) !== null) installations.push(match[1].trim());
      reponse = reponse.replace(/\[INSTALL:\s*.+?\]/gi, '').trim();

      const commands = [];
      const cmdRegex = /\[COMMAND:\s*(.+?)\]/gi;
      while ((match = cmdRegex.exec(reponse)) !== null) commands.push(match[1].trim());
      reponse = reponse.replace(/\[COMMAND:\s*.+?\]/gi, '').trim();

      const blocks = extraireBlocs(reponse);
      const texteChat = reponse.replace(/```[\s\S]*?```/g, '').trim();

      if (texteChat && !dejaAffiche.has(texteChat)) {
        dejaAffiche.add(texteChat);
        envoyer('message', { role: 'ia', content: texteChat });
      }

      for (const block of blocks) {
        const fileHash = block.nom + '_' + block.contenu.length;
        if (!dejaAffiche.has(fileHash)) {
          dejaAffiche.add(fileHash);
          envoyer('file', { name: block.nom, language: block.langage, content: block.contenu });
        }
      }

      let installEchouee = false;
      for (const cmd of installations) {
        if (closed) break;
        envoyer('terminal', { command: cmd, type: 'install' });
        const result = await executerSecurise(cmd);
        envoyer('terminal_result', { command: cmd, ...result });
        if (!result.success) { memoire.push(`Erreur install ${cmd}`); installEchouee = true; }
      }

      for (const cmd of commands) {
        if (closed) break;
        envoyer('terminal', { command: cmd, type: 'command' });
        const result = await executerSecurise(cmd);
        envoyer('terminal_result', { command: cmd, ...result });
        if (!result.success && result.stderr) memoire.push(`Erreur ${cmd}: ${result.stderr}`);
      }

      if (installEchouee) memoire = memoire.filter(m => !m.includes('Erreur install'));

      // N'insérer qu'à la dernière itération (quand on va sortir de la boucle)
const isLastIteration = (memoire.length === 0) || (iteration >= MAX_ITERATIONS);
if (isLastIteration) {
  try {
    await withPg(async (client) => {
      const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
      if (user.rows.length === 0) return;
      const uid = user.rows[0].id;
      await client.query(
        `INSERT INTO conversation_memory (user_id, project_id, role, content) VALUES ($1, $2, 'user', $3)`,
        [uid, project_id, message]
      );
      await client.query(
        `INSERT INTO conversation_memory (user_id, project_id, role, content) VALUES ($1, $2, 'model', $3)`,
        [uid, project_id, reponse]
      );
    });
  } catch (e) { console.error('mémoire persist:', e.message); }
}
      if (blocks.length > 0) {
        try {
          await withPg(async (client) => {
            const oldFiles = await client.query(
              'SELECT name, language, content FROM files WHERE project_id = $1',
              [project_id]
            );
            const fileMap = new Map();
            for (const f of oldFiles.rows) fileMap.set(f.name, { nom: f.name, langage: f.language, contenu: f.content });
            for (const file of blocks) fileMap.set(file.nom, { nom: file.nom, langage: file.langage, contenu: file.contenu });
            await client.query('DELETE FROM files WHERE project_id = $1', [project_id]);
            for (const f of fileMap.values()) {
              await client.query(
                'INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
                [project_id, f.nom, f.langage, f.contenu]
              );
            }
          });
        } catch (e) { console.error('files persist:', e.message); }
      }

      if (memoire.length === 0) {
        envoyer('done', { message: 'Terminé ✅' });
        break;
      }

      if (iteration < MAX_ITERATIONS) {
        envoyer('status', { message: `Correction (${iteration}/${MAX_ITERATIONS})...` });
        contents.push({ role: 'model', parts: [{ text: reponse }] });
        contents.push({ role: 'user', parts: [{ text: `Erreurs :\n${memoire.join('\n')}\n\nCorrige.` }] });
      } else {
        envoyer('message', { role: 'ia', content: `J'ai essayé ${MAX_ITERATIONS} fois. Précise ce que tu attends.` });
        envoyer('done', { message: 'Abandon' });
      }
    }

    if (closed) envoyer('cancelled', { message: 'Arrêté' });
    if (!closed && !res.writableEnded) { res.write('event: end\ndata: {}\n\n'); res.end(); }
  } catch (error) {
    envoyer('error', { message: error.response?.data?.error?.message || error.message });
    if (!closed && !res.writableEnded) { res.write('event: end\ndata: {}\n\n'); res.end(); }
  }
});

async function executerSecurise(cmd) {
  try {
    const verif = antivirus.verifierCommande(cmd, 'libre') || {};
    if (verif.allowed !== true) return { success: false, blocked: true, reason: verif.reason || 'Commande bloquée' };
    const result = await sandbox.executerCommande(cmd);
    return { success: result.success, stdout: result.stdout || '', stderr: result.stderr || '', exitCode: result.exitCode };
  } catch (e) {
    return { success: false, error: e.message };
  }
}
app.post('/api/terminal/exec', iaLimiter, async (req, res) => {
  const { commande, firebase_uid } = req.body;
  if (!commande || typeof commande !== 'string') return res.status(400).json({ error: 'Commande vide' });

  if (!firebase_uid) {
    return res.status(400).json({ error: 'firebase_uid requis', blocked: true, reason: 'firebase_uid requis' });
  }

  const quota = await verifierQuota(firebase_uid);
  if (!quota.allowed) {
    return res.json({ blocked: true, reason: quota.error, quota_exceeded: true, plan: quota.plan, used: quota.used, limit: quota.limit });
  }

  const result = await executerSecurise(commande);
  return res.json({ ...result, commande });
});

app.post('/api/terminal/close', async (req, res) => {
  const { firebase_uid } = req.body;
  if (!firebase_uid) return res.status(400).json({ error: 'firebase_uid requis' });
  await sandbox.fermerSandbox();
  res.json({ success: true });
});
app.get('/api/quota/:firebase_uid', async (req, res) => {
  try {
    const data = await withPg(async (client) => {
      const user = await client.query(
        'SELECT plan, commands_today, last_command_reset FROM users WHERE firebase_uid = $1',
        [req.params.firebase_uid]
      );
      return user.rows[0] || null;
    });
    if (!data) return res.json({ success: false });
    const today = new Date().toISOString().split('T')[0];
    
    let lastReset = null;
    if (data.last_command_reset) {
      lastReset = typeof data.last_command_reset.toISOString === 'function'
        ? data.last_command_reset.toISOString().split('T')[0]
        : new Date(data.last_command_reset).toISOString().split('T')[0];
    }

    const commandsToday = lastReset === today ? (data.commands_today || 0) : 0;
    res.json({
      success: true,
      plan: data.plan || 'free',
      used: commandsToday,
      limit: LIMITE_FREE,
      remaining: Math.max(0, LIMITE_FREE - commandsToday)
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const server = app.listen(PORT, () => {
  console.log('Kenny serveur sur le port ' + PORT);
  console.log(`Modèle Gemini : ${GEMINI_MODEL}`);
});
server.on('error', (err) => {
  console.error('❌ Listen error:', err.message);
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM reçu, arrêt propre...');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 25000).unref();
});
