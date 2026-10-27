const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { Client } = require('pg');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const antivirus = require('./agents/antivirus');
const sandbox = require('./agents/sandbox');
const tester = require('./agents/tester');
const pgvector = require('pgvector/pg');
const memoire = require('./agents/memoire');

process.on('unhandledRejection', (err) => {
  console.error('UnhandledRejection:', err);
  process.exit(1);
});
process.on('uncaughtException', (err) => {
  console.error('UncaughtException:', err);
  process.exit(1);
});

const app = express();
const PORT = process.env.PORT || 3000;

const LIMITE_FREE = 50;
const MAX_HISTORY = 30;
const MAX_TERMINAL_HISTORY = 10;

const CORS_ORIGINS_RAW = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const CORS_WILDCARD = CORS_ORIGINS_RAW.length === 0 || CORS_ORIGINS_RAW.includes('*');
const ALLOWED_ORIGINS = CORS_WILDCARD ? ['*'] : CORS_ORIGINS_RAW;

app.use(cors({
  origin: CORS_WILDCARD ? true : ALLOWED_ORIGINS,
  credentials: !CORS_WILDCARD
}));
app.use(express.json({ limit: '2mb' }));

const iaLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Trop de requetes IA, reessaie dans 1 minute.' },
  standardHeaders: true,
  legacyHeaders: false
});

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
  e2b: process.env.E2B_API_KEY,
  groq: process.env.GROQ_API_KEY,
  openrouter: process.env.OPENROUTER_API_KEY,
  // 🆕 Nouveaux providers
  mistral: process.env.MISTRAL_API_KEY,
  githubModels: process.env.GITHUB_TOKEN
};

const buildsEnCours = new Map();

const ENCRYPTION_KEY_RAW = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY_RAW) {
  if (process.env.NODE_ENV !== 'development') {
    throw new Error('ENCRYPTION_KEY obligatoire (hors NODE_ENV=development).');
  }
  console.warn('ENCRYPTION_KEY absente - fallback DEV utilise.');
}
const ENCRYPTION_KEY = crypto.scryptSync(
  ENCRYPTION_KEY_RAW || 'kenny_default_secret_key_2026',
  'kenny_salt_v1',
  32
);

const GEMINI_MODEL = 'gemini-3.8-flash';
const GEMINI_URL = (key) => `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${key}`;

function chiffrer(text) {
  if (text === null || text === undefined) return null;
  const str = String(text);
  if (str === '') return '';
  const iv = crypto.randomBytes(16);
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

async function withPg(fn, connString = null) {
  const client = await getNeonClient(connString);
  try {
    return await fn(client);
  } finally {
    await client.end().catch(() => {});
  }
}

async function verifierProprietaireProjet(firebase_uid, project_id) {
  if (!firebase_uid || !project_id) return false;
  try {
    return await withPg(async (client) => {
      const r = await client.query(
        `SELECT p.id FROM projects p JOIN users u ON u.id = p.user_id WHERE p.id = $1 AND u.firebase_uid = $2`,
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
      const user = await client.query('SELECT id, plan FROM users WHERE firebase_uid = $1', [firebase_uid]);
      if (user.rows.length === 0) return { allowed: false, error: 'User non trouve' };
      const u = user.rows[0];
      if (u.plan === 'pro' || u.plan === 'premium') {
        return { allowed: true, remaining: 'infini', plan: u.plan };
      }
      const today = new Date().toISOString().split('T')[0];
      const updated = await client.query(
        `UPDATE users SET commands_today = CASE WHEN last_command_reset IS NULL OR last_command_reset::date <> $2::date THEN 1 ELSE commands_today + 1 END, last_command_reset = $2::date WHERE id = $1 AND (last_command_reset IS NULL OR last_command_reset::date <> $2::date OR commands_today < $3) RETURNING commands_today`,
        [u.id, today, LIMITE_FREE]
      );
      if (updated.rowCount === 0) {
        return { allowed: false, error: `Limite atteinte (${LIMITE_FREE}/jour).`, plan: u.plan, used: LIMITE_FREE, limit: LIMITE_FREE };
      }
      const used = updated.rows[0].commands_today;
      return { allowed: true, plan: u.plan, used, limit: LIMITE_FREE, remaining: LIMITE_FREE - used };
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

  // 🔧 Vérifier que le repo contient du code avant de créer le service
  try {
    const repoPath = repoUrl.replace('https://github.com/', '').replace(/\.git$/, '');
    const checkRes = await axios.get(
      `https://api.github.com/repos/${repoPath}/contents`,
      { headers: { 'Authorization': `token ${userToken}`, 'Accept': 'application/vnd.github.v3+json' } }
    );
    const files = checkRes.data || [];
    const hasCode = files.some(f =>
      ['run.py', 'app.py', 'main.py', 'server.js', 'package.json', 'requirements.txt'].includes(f.name)
    );
    if (!hasCode) {
      console.log(`⏭️ Render skip : repo ${repoPath} vide (${files.length} fichiers)`);
      return { success: false, skipped: true, reason: 'Repo vide — déploiement différé jusqu\'au premier build' };
    }
  } catch (e) {
    console.log(`⏭️ Render skip : vérif repo échouée (${e.message})`);
    return { success: false, skipped: true, reason: `Vérification repo échouée : ${e.message}` };
  }

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

const workspaceLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Trop de créations de workspace, réessaie dans 1 minute.' }
});

async function creerZoneCloudflare() {
  return { success: false, skipped: true, reason: 'Cloudflare non implémenté' };
}



app.post('/api/workspaces/create', workspaceLimiter, async (req, res) => {
  const { firebase_uid, project_id, project_name } = req.body;
  if (!firebase_uid || !project_id || !project_name) {
    return res.status(400).json({ error: 'Champs requis' });
  }
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
  const blocs = [];

  // Regex 1 : format standard ```langage:nom_fichier\n contenu ```
  const regexStandard = /```([a-zA-Z0-9_+\-]*)(?:[:\s]+([^\s\n`]+))?\s*\n([\s\S]*?)```/g;
  let match;
  while ((match = regexStandard.exec(text)) !== null) {
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

// [FUSION] Fusionner les blocs markdown/txt sans nom en README.md
const blocsSansNom = blocs.filter(b => /^fichier\d+\.(txt|md)$/.test(b.nom));
const blocsNommes = blocs.filter(b => !/^fichier\d+\.(txt|md)$/.test(b.nom));

if (blocsSansNom.length > 0) {
  const contenuFusionne = blocsSansNom.map(b => b.contenu).join('\n\n');
  const dejaReadme = blocsNommes.find(b => b.nom.toLowerCase() === 'readme.md');
  
  if (dejaReadme) {
    // Fusionner dans le README existant
    dejaReadme.contenu = dejaReadme.contenu + '\n\n' + contenuFusionne;
  } else {
    // Créer un README.md
    blocsNommes.push({ langage: 'markdown', nom: 'README.md', contenu: contenuFusionne });
  }
  
  blocs.length = 0;
  blocs.push(...blocsNommes);
  console.log(`⚠️ Fusion de ${blocsSansNom.length} blocs sans nom dans README.md`);
}

  

  // [FALLBACK] Si regex standard ne trouve rien, essayer de détecter les fichiers par heuristique
  if (blocs.length === 0) {
    console.log('⚠️ extraireBlocs: aucun bloc avec regex standard, essai fallback heuristique');

    // Chercher des patterns comme "**moteur/config.py**" ou "### moteur/config.py" suivis de code
    const regexFallback = /(?:^|\n)(?:#{1,3}\s*|\*\*|`)?([a-zA-Z0-9_\/\-]+\.(py|html|js|css|json|txt|md|yml|yaml))(?:\*\*|`)?\s*\n+([\s\S]*?)(?=\n(?:#{1,3}\s*|\*\*|`)?[a-zA-Z0-9_\/\-]+\.(?:py|html|js|css|json|txt|md|yml|yaml)|$)/g;
    let matchFb;
    while ((matchFb = regexFallback.exec(text)) !== null) {
      const nomFichier = matchFb[1].trim();
      const ext = matchFb[2].toLowerCase();
      const contenu = matchFb[3].trim();
      if (!contenu || contenu.length < 5) continue;

      const langage = ext === 'py' ? 'python'
        : ext === 'js' ? 'javascript'
        : ext === 'html' ? 'html'
        : ext === 'css' ? 'css'
        : ext === 'json' ? 'json'
        : ext === 'md' ? 'markdown'
        : ext === 'yml' || ext === 'yaml' ? 'yaml'
        : 'txt';

      let finalNom = nomFichier;
      let counter = 1;
      while (blocs.some(b => b.nom === finalNom)) {
        const dot = nomFichier.lastIndexOf('.');
        finalNom = dot > 0
          ? `${nomFichier.substring(0, dot)}_${counter}${nomFichier.substring(dot)}`
          : `${nomFichier}_${counter}`;
        counter++;
      }

      blocs.push({ langage, nom: finalNom, contenu });
    }

    if (blocs.length > 0) {
      console.log(`⚠️ Fallback heuristique: ${blocs.length} fichiers extraits`);
    }
  }

  // [FALLBACK 2] Si toujours rien, chercher si c'est une réponse non structurée
  if (blocs.length === 0) {
    console.log('⚠️ Fallback 2: recherche de code Python brut sans nom de fichier');

    // Chercher un bloc ```python ou ```py sans nom
    const regexSansNom = /```(python|py)\s*\n([\s\S]*?)```/g;
    let matchSN;
    let count = 1;
    while ((matchSN = regexSansNom.exec(text)) !== null) {
      const contenu = matchSN[2].trim();
      if (!contenu || contenu.length < 5) continue;

      let nom = 'run.py';
      if (contenu.includes('from flask') || contenu.includes('import flask')) {
        nom = 'app.py';
      } else if (!contenu.includes('if __name__ ==')) {
        nom = `fichier${count}.py`;
        count++;
      }

      if (blocs.some(b => b.nom === nom)) {
        nom = nom.replace('.py', `_${count}.py`);
        count++;
      }

      blocs.push({ langage: 'python', nom, contenu });
    }

    if (blocs.length > 0) {
      console.log(`⚠️ Fallback 2: ${blocs.length} fichiers extraits sans nom`);
    }
  }

    // [SANITIZER] Filtrer les blocs qui contiennent du XML halluciné
  const blocsValides = blocs.filter(b => {
    const contenu = b.contenu || '';
    const patternsXML = [
      /<\/?parameter[= >]/i,
      /<\/?function[= >]/i,
      /<\/?tool_call[= >]/i,
      /<\/?invoke[= >]/i,
      /<\|.*?\|>/,
      /<tool>/i,
    ];
    const estHallucination = patternsXML.some(re => re.test(contenu));
    if (estHallucination) {
      console.log(`⚠️ Bloc "${b.nom}" rejeté (XML halluciné détecté)`);
      return false;
    }
    if (contenu.length < 10) {
      console.log(`⚠️ Bloc "${b.nom}" rejeté (trop court: ${contenu.length} car.)`);
      return false;
    }
    return true;
  });

  if (blocsValides.length === 0 && blocs.length > 0) {
    console.error(`❌ TOUS les blocs rejetés (${blocs.length} hallucinations XML)`);
    console.error(`   Premier bloc rejeté: "${blocs[0].nom}" → "${(blocs[0].contenu || '').substring(0, 100)}"`);
    return [];
  }

  return blocsValides;
}

function tailTruncate(s, n) {
  if (!s) return '';
  return s.length > n ? '...' + s.slice(-n) : s;
}
// ============================================
// 🔥 PROVIDERS IA SPÉCIALISÉS PAR RÔLE
// ============================================

// --- Groq : GÉNÉRATION DE CODE (rapide, 1000 req/jour) ---
async function appelGroqCode(messages, systemPrompt) {
  if (!GLOBAL_KEYS.groq) throw new Error('Clé Groq manquante');
  
  const response = await axios.post(
    'https://api.groq.com/openai/v1/chat/completions',
    {
      model: 'qwen/qwen3.8-27b',
      messages: [
        { role: 'system', content: systemPrompt },
        ...messages
      ],
      temperature: 0.3,
      max_tokens: 8000
    },
    {
      headers: {
        'Authorization': `Bearer ${GLOBAL_KEYS.groq}`,
        'Content-Type': 'application/json'
      },
      timeout: 120000
    }
  );
  
  return response.data.choices[0].message.content;
}

// ============================================
// 🆕 Mistral — GÉNÉRATION DE CODE PROPRE
// ============================================

async function appelMistralCode(messages, systemPrompt) {
  if (!GLOBAL_KEYS.mistral) throw new Error('Clé Mistral manquante');
  
  console.log('🚀 Génération via Mistral...');
  
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await axios.post(
        'https://api.mistral.ai/v1/chat/completions',
        {
          model: 'mistral-small-latest',
          messages: [
            { role: 'system', content: systemPrompt },
            ...messages
          ],
          temperature: 0.2,
          max_tokens: 32000
        },
        {
          headers: {
            'Authorization': `Bearer ${GLOBAL_KEYS.mistral}`,
            'Content-Type': 'application/json'
          },
          timeout: 180000
        }
      );
      console.log('✅ Mistral OK');
      return response.data.choices[0].message.content;
    } catch (e) {
      if (e.response?.status === 429 && attempt < 3) {
        const wait = attempt * 2000;
        console.log(`⏳ Mistral 429, attente ${wait}ms puis retry ${attempt}/3...`);
        await new Promise(r => setTimeout(r, wait));
        continue;
      }
      throw e;
    }
  }
}

// ============================================
// 🆕 GitHub Models — FALLBACK GPT-4o / Claude
// ============================================
async function appelGitHubModels(messages, systemPrompt, model = 'gpt-4o') {
  if (!GLOBAL_KEYS.githubModels) throw new Error('Token GitHub Models manquant');
  
  console.log(`🔄 Fallback GitHub Models ${model}...`);
  
  const response = await axios.post(
    'https://models.inference.ai.azure.com/chat/completions',
    {
      model: model,
      messages: [
        { role: 'system', content: systemPrompt },
        ...messages
      ],
      temperature: 0.2,
      max_tokens: 16000
    },
    {
      headers: {
        'Authorization': `Bearer ${GLOBAL_KEYS.githubModels}`,
        'Content-Type': 'application/json'
      },
      timeout: 120000
    }
  );
  
  console.log('✅ GitHub Models OK');
  return response.data.choices[0].message.content;
}


// ============================================
// 🆕 RECHERCHE WEB — DuckDuckGo HTML direct
// ============================================
async function rechercherWeb(query, maxResults = 3) {
  try {
    console.log(`🔍 Recherche web : "${query}"`);
    
    const res = await axios.get('https://html.duckduckgo.com/html/', {
      params: { q: query },
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; KennyBot/1.0)',
        'Accept': 'text/html'
      },
      timeout: 15000
    });
    
    const results = [];
    const html = res.data;
    
    // Parse les résultats : chaque résultat est dans un <div class="result">
    const regex = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?<a[^>]+class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g;
    let match;
    while ((match = regex.exec(html)) !== null && results.length < maxResults) {
      let url = match[1];
      // DuckDuckGo encapsule parfois les URLs
      if (url.startsWith('//duckduckgo.com/l/?uddg=')) {
        try {
          url = decodeURIComponent(url.split('uddg=')[1].split('&')[0]);
        } catch {}
      }
      
      results.push({
        titre: match[2].replace(/<[^>]+>/g, '').trim(),
        url: url,
        contenu: match[3].replace(/<[^>]+>/g, '').trim()
      });
    }
    
    // Fallback : si le regex ne marche pas, essaie un parse plus simple
    if (results.length === 0) {
      const simpleRegex = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)<\/a>/g;
      let m;
      while ((m = simpleRegex.exec(html)) !== null && results.length < maxResults) {
        let url = m[1];
        if (url.startsWith('//duckduckgo.com/l/?uddg=')) {
          try { url = decodeURIComponent(url.split('uddg=')[1].split('&')[0]); } catch {}
        }
        results.push({
          titre: m[2].replace(/<[^>]+>/g, '').trim(),
          url: url,
          contenu: ''
        });
      }
    }
    
    console.log(`✅ ${results.length} résultats trouvés`);
    return results;
  } catch (e) {
    console.log('⚠️ Recherche échec (non bloquant):', e.message);
    return [];
  }
}

// ============================================
// 🆕 DÉTECTION + CONTEXTE WEB
// ============================================
function besoinRechercheWeb(prompt) {
  const motsCles = [
    'flask', 'fastapi', 'django', 'sqlalchemy', 'react', 'vue', 'nextjs',
    'numpy', 'pandas', 'xgboost', 'scikit-learn', 'tensorflow', 'pytorch',
    'version', 'dernière', 'latest', 'documentation', 'doc'
  ];
  return motsCles.some(m => prompt.toLowerCase().includes(m));
}

async function chercherContexteWeb(prompt) {
  if (!besoinRechercheWeb(prompt)) return '';
  const match = prompt.toLowerCase().match(
    /\b(flask|fastapi|django|sqlalchemy|react|vue|nextjs|numpy|pandas|xgboost|scikit-learn|tensorflow|pytorch)\b/
  );
  if (!match) return '';
  const lib = match[1];
  const resultats = await rechercherWeb(`${lib} python latest version 2026`);
  if (resultats.length === 0) return '';
  return `
INFORMATIONS WEB RÉCENTES (${lib}) :
${resultats.map((r, i) => `${i + 1}. ${r.titre}\n   ${r.url}\n   ${r.contenu.substring(0, 300)}`).join('\n\n')}

Utilise ces informations pour connaître la dernière version et les bonnes pratiques actuelles.
`;
}
// ============================================
// 🎯 ROUTEUR INTELLIGENT
// ============================================
async function genererAvecRouteur(prompt, systemPrompt, options = {}) {
  const { estSimple = false } = options;
  const routeur = [];
  
  // Prompt simple → Groq (ultra-rapide)
  if (estSimple && GLOBAL_KEYS.groq) {
    routeur.push({ 
      nom: 'Groq', 
      fn: () => appelGroqCode([{ role: 'user', content: prompt }], systemPrompt)
    });
  }
  
  // Code standard → Mistral (propre)
  if (GLOBAL_KEYS.mistral) {
    routeur.push({ 
      nom: 'Mistral', 
      fn: () => appelMistralCode([{ role: 'user', content: prompt }], systemPrompt)
    });
  }
  
  // Fallback → Gemini
  if (GLOBAL_KEYS.gemini) {
    routeur.push({ 
      nom: 'Gemini', 
      fn: async () => {
        const response = await axios.post(
          GEMINI_URL(GLOBAL_KEYS.gemini),
          {
            systemInstruction: { parts: [{ text: systemPrompt }] },
            contents: [{ role: 'user', parts: [{ text: prompt }] }],
            generationConfig: { temperature: 0.2, maxOutputTokens: 32000 }
          },
          { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
        );
        return response.data.candidates[0].content.parts[0].text;
      }
    });
  }
  
    // Fallback ultime → Groq (toujours en dernier)
if (GLOBAL_KEYS.groq) {
    routeur.push({ 
      nom: 'Groq (final)', 
      fn: () => appelGroqCode([{ role: 'user', content: prompt }], systemPrompt)
    });
  }
  
  let derniereErreur;
  for (const provider of routeur) {
    try {
      const reponse = await provider.fn();
      if (reponse && reponse.length > 50) {
        console.log(`✅ ${provider.nom} a répondu (${reponse.length} car.)`);
        return { success: true, reponse, provider: provider.nom };
      }
    } catch (e) {
      console.log(`❌ ${provider.nom} échoue : ${e.message}`);
      derniereErreur = e;
    }
  }
  
  return { success: false, error: derniereErreur?.message || 'Tous les providers ont échoué' };
}

// --- OpenRouter : CORRECTION (agent, 50 req/jour gratuit) ---
async function appelOpenRouterCorrection(messages, systemPrompt) {
  if (!GLOBAL_KEYS.openrouter) throw new Error('Clé OpenRouter manquante');
  
  const response = await axios.post(
    'https://openrouter.ai/api/v1/chat/completions',
    {
      model: 'nvidia/nemotron-3-ultra-550b-a55b:free',
      messages: [
        { role: 'system', content: systemPrompt },
        ...messages
      ],
      temperature: 0.3,
      max_tokens: 8000
    },
    {
      headers: {
        'Authorization': `Bearer ${GLOBAL_KEYS.openrouter}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://kenny.dev',
        'X-Title': 'Kenny'
      },
      timeout: 120000
    }
  );
  
  return response.data.choices[0].message.content;
}

// --- Gemini : TESTS + CHAT (stable, gratuit) ---
async function appelGeminiTest(messages, systemPrompt) {
  if (!GLOBAL_KEYS.gemini) throw new Error('Clé Gemini manquante');

  const contents = messages.map(m => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }]
  }));

  const response = await axios.post(
    GEMINI_URL(GLOBAL_KEYS.gemini),
    {
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents: contents,
      generationConfig: { temperature: 0.7, maxOutputTokens: 8000 }
    },
    {
      headers: { 'Content-Type': 'application/json' },
      timeout: 180000
    }
  );

    return response.data.candidates[0].content.parts[0].text;
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

buildsEnCours.set(project_id, {
  active: true,
  etape: 'analyse',
  message: '🧠 Analyse de la demande...',
  startedAt: new Date().toISOString()
});

const systemPrompt = `Tu es un développeur senior expert...
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

    let reponse;
try {
  envoyer('status', { message: '🤖 Génération via Groq...' });
  reponse = await appelGroqCode(
    [{ role: 'user', content: prompt }],
    systemPrompt
  );
  envoyer('status', { message: '✅ Généré par Groq' });
} catch (err) {
  console.log('Groq échec, fallback Gemini:', err.message);
  envoyer('status', { message: '⚠️ Groq échec, fallback Gemini...' });
  const response = await axios.post(
    GEMINI_URL(keys.gemini),
    {
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.7, maxOutputTokens: 8000 }
    },
    { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
  );
  reponse = response.data.candidates[0].content.parts[0].text;
  envoyer('status', { message: '✅ Généré par Gemini (fallback)' });
}

if (closed) return res.end();

const blocks = extraireBlocs(reponse);

buildsEnCours.set(project_id, {
  active: true,
  etape: 'generation',
  message: `📦 ${blocks.length} fichiers générés`,
  startedAt: buildsEnCours.get(project_id)?.startedAt,
  updatedAt: new Date().toISOString()
});
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

    const ws = await withPg(async (client) => {
      const r = await client.query('SELECT * FROM workspaces WHERE project_id = $1', [project_id]);
      return r.rows[0] || null;
    });

    if (ws?.github_repo) {
      buildsEnCours.set(project_id, {
  active: true,
  etape: 'push',
  message: '🐙 Push sur GitHub...',
  startedAt: buildsEnCours.get(project_id)?.startedAt,
  updatedAt: new Date().toISOString()
});
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
    envoyer('done', { message: '✅ Full Build terminé !', url: finalUrl, files_count: blocks.length, tested: false });
    
    if (!closed && !res.writableEnded) { res.write('event: end\ndata: {}\n\n'); res.end(); }
  } catch (error) {
    console.error('Erreur full build:', error.message);
    envoyer('error', { message: error.response?.data?.error?.message || error.message });
    if (!closed && !res.writableEnded) { res.write('event: end\ndata: {}\n\n'); res.end(); }
  } finally {
    // [FIX #13] Marquer le build comme terminé + nettoyer après 5 min
    const current = buildsEnCours.get(project_id) || {};
    buildsEnCours.set(project_id, {
      ...current,
      active: false,
      etape: 'termine',
      endedAt: new Date().toISOString()
    });
    setTimeout(() => buildsEnCours.delete(project_id), 5 * 60 * 1000);
  }
});
	
// ============================================
// 🔧 CORRECTION CIBLÉE (une seule passe, contexte préservé)
// ============================================
async function corrigerFichierCible(promptOriginal, fichier, erreur, keys, project_id = null, user_id = null) {
  // 🧠 Détecte le contexte du fichier
  const contexte = memoire.detecterContexte(fichier, fichier.contenu, promptOriginal);
  contexte.fichier = fichier.nom;
  contexte.erreur = erreur;

  // 🧠 Cherche des corrections similaires dans la mémoire
  let correctionsSimilaires = [];
  if (user_id) {
    try {
      correctionsSimilaires = await memoire.chercherCorrectionsSimilaires(
        erreur, fichier, contexte, user_id, project_id, keys.gemini, 3, withPg
      );
      if (correctionsSimilaires.length > 0) {
        console.log(`🧠 Mémoire : ${correctionsSimilaires.length} correction(s) similaire(s)`);
      }
    } catch (e) {
      console.log('⚠️ Recherche mémoire échec:', e.message);
    }
  }

  // Construit le contexte mémoire pour le prompt
  let memoireContext = '';
  if (correctionsSimilaires.length > 0) {
    memoireContext = `\n\n📚 CORRECTIONS SIMILAIRES QUI ONT FONCTIONNÉ DANS LE PASSÉ :\n`;
    for (const c of correctionsSimilaires) {
      memoireContext += `\n---\n`;
      memoireContext += `Erreur : ${c.erreur_message.substring(0, 200)}\n`;
      memoireContext += `Fichier : ${c.fichier_coupable}\n`;
      memoireContext += `Type : ${c.erreur_type}\n`;
      memoireContext += `Correction : ${c.explication || 'voir code'}\n`;
      if (c.code_avant) memoireContext += `Code avant (extrait) : ${c.code_avant.substring(0, 300)}...\n`;
      if (c.code_apres) memoireContext += `Code après (extrait) : ${c.code_apres.substring(0, 300)}...\n`;
    }
    memoireContext += `\n---\n⚠️ Ces corrections sont des INSPIRATIONS. Adapte-les au contexte actuel. Ne copie pas aveuglément.\n`;
  }

  const systemPrompt = `Tu es un développeur senior qui CORRIGE UN SEUL FICHIER Python.

CONTEXTE DU PROJET (demande originale de l'utilisateur) :
"""${promptOriginal}"""

FICHIER À CORRIGER : ${fichier.nom}

CONTENU ACTUEL :
\`\`\`${fichier.langage}
${fichier.contenu}
\`\`\`

ERREUR DÉTECTÉE :
\`\`\`
${erreur}
\`\`\`

TA MISSION :
1. Analyse l'erreur (1-2 phrases max)
2. Corrige UNIQUEMENT ce fichier
3. Renvoie le contenu COMPLET corrigé du fichier (pas un diff, le fichier entier)

FORMAT DE SORTIE OBLIGATOIRE :
D'abord l'explication, puis :

\`\`\`${fichier.langage}:${fichier.nom}
<contenu complet corrigé>
\`\`\`

RÈGLES STRICTES :
- Ne renvoie QUE ce fichier (pas les autres)
- Ne renomme PAS le fichier
- Ne change PAS la structure du projet
- Garde le style de code existant
- Si l'erreur n'est pas dans ce fichier, renvoie le fichier tel quel

⚠️ SI L'ERREUR EST "ModuleNotFoundError: No module named 'X'" :
  → Le code est probablement CORRECT, c'est juste une dépendance manquante
  → Vérifie que requirements.txt existe et contient "X"
  → Si requirements.txt n'existe pas, ce n'est PAS ton problème ici
  → Renvoie le fichier tel quel${memoireContext}`;

  // Essai 1 : OpenRouter
  try {
    console.log(`🔧 Correction OpenRouter pour ${fichier.nom}...`);
    const response = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: 'nvidia/nemotron-3-ultra-550b-a55b:free',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: `Corrige ${fichier.nom}` }
        ],
        temperature: 0.2,
        max_tokens: 4000
      },
      {
        headers: {
          'Authorization': `Bearer ${keys.openrouter}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://kenny.dev',
          'X-Title': 'Kenny'
        },
        timeout: 180000
      }
    );

    const reponse = response.data.choices[0].message.content;
    const blocs = extraireBlocs(reponse);
    const fichierCorrige = blocs.find(b => b.nom === fichier.nom);

    if (fichierCorrige) {
      console.log(`✅ ${fichier.nom} corrigé par OpenRouter`);

      // 🧠 Enregistre dans la mémoire
      if (user_id) {
        await memoire.enregistrerCorrection({
          project_id, user_id,
          fichier: fichier.nom,
          contexte,
          erreur,
          codeAvant: fichier.contenu,
          codeApres: fichierCorrige.contenu,
          explication: reponse.replace(/```[\s\S]*?```/g, '').trim(),
          provider: 'openrouter',
          succes: true,
          tentatives: 1
        }, keys.gemini, withPg);
      }

      return {
        success: true,
        fichierCorrige: { ...fichier, contenu: fichierCorrige.contenu },
        explication: reponse.replace(/```[\s\S]*?```/g, '').trim(),
        provider: 'openrouter',
        correctionsUtilisees: correctionsSimilaires.map(c => c.id)
      };
    }
    throw new Error('OpenRouter n\'a pas renvoyé le fichier');
  } catch (err) {
    console.log(`❌ OpenRouter échec pour ${fichier.nom}:`, err.message);
  }

  // Essai 2 : Gemini
  try {
    console.log(`🔧 Fallback Gemini pour ${fichier.nom}...`);
    const response = await axios.post(
      GEMINI_URL(keys.gemini),
      {
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ role: 'user', parts: [{ text: `Corrige ${fichier.nom}` }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 8000 }
      },
      { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
    );

    const reponse = response.data.candidates[0].content.parts[0].text;
    const blocs = extraireBlocs(reponse);
    const fichierCorrige = blocs.find(b => b.nom === fichier.nom);

    if (fichierCorrige) {
      console.log(`✅ ${fichier.nom} corrigé par Gemini`);

      if (user_id) {
        await memoire.enregistrerCorrection({
          project_id, user_id,
          fichier: fichier.nom,
          contexte,
          erreur,
          codeAvant: fichier.contenu,
          codeApres: fichierCorrige.contenu,
          explication: reponse.replace(/```[\s\S]*?```/g, '').trim(),
          provider: 'gemini',
          succes: true,
          tentatives: 1
        }, keys.gemini, withPg);
      }

      return {
        success: true,
        fichierCorrige: { ...fichier, contenu: fichierCorrige.contenu },
        explication: reponse.replace(/```[\s\S]*?```/g, '').trim(),
        provider: 'gemini',
        correctionsUtilisees: correctionsSimilaires.map(c => c.id)
      };
    }
    throw new Error('Gemini n\'a pas renvoyé le fichier');
  } catch (err) {
    console.log(`❌ Gemini échec pour ${fichier.nom}:`, err.message);
  }

  // Essai 3 : Groq
  try {
    console.log(`🔧 Fallback Groq pour ${fichier.nom}...`);
    const response = await axios.post(
      'https://api.groq.com/openai/v1/chat/completions',
      {
        model: 'qwen/qwen3.8-27b',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: `Corrige ${fichier.nom}` }
        ],
        temperature: 0.2,
        max_tokens: 8000
      },
      {
        headers: {
          'Authorization': `Bearer ${keys.groq}`,
          'Content-Type': 'application/json'
        },
        timeout: 120000
      }
    );

    const reponse = response.data.choices[0].message.content;
    const blocs = extraireBlocs(reponse);
    const fichierCorrige = blocs.find(b => b.nom === fichier.nom);

    if (fichierCorrige) {
      console.log(`✅ ${fichier.nom} corrigé par Groq`);

      if (user_id) {
        await memoire.enregistrerCorrection({
          project_id, user_id,
          fichier: fichier.nom,
          contexte,
          erreur,
          codeAvant: fichier.contenu,
          codeApres: fichierCorrige.contenu,
          explication: reponse.replace(/```[\s\S]*?```/g, '').trim(),
          provider: 'groq',
          succes: true,
          tentatives: 1
        }, keys.gemini, withPg);
      }

      return {
        success: true,
        fichierCorrige: { ...fichier, contenu: fichierCorrige.contenu },
        explication: reponse.replace(/```[\s\S]*?```/g, '').trim(),
        provider: 'groq',
        correctionsUtilisees: correctionsSimilaires.map(c => c.id)
      };
    }
    throw new Error('Groq n\'a pas renvoyé le fichier');
  } catch (err) {
    console.log(`❌ Groq échec pour ${fichier.nom}:`, err.message);
  }

  // 🧠 Aucun provider n'a réussi → pénalise les corrections utilisées
  if (correctionsSimilaires.length > 0 && user_id) {
    await memoire.penaliserCorrection(
      correctionsSimilaires.map(c => c.id),
      withPg
    );
  }

  return {
    success: false,
    error: 'Ni Gemini ni OpenRouter ni Groq n\'ont pu corriger'
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
  try { res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`); } catch (e) {}
};

  let sandboxFinale = null;

// Init suivi
try {
buildsEnCours.set(project_id, {
  active: true,
  etape: 'generation',
  message: '🧠 Génération du code Python...',
  startedAt: new Date().toISOString()
});

    // 🎯 Détection de la complexité du prompt
    const promptLower = prompt.toLowerCase();
    const estSimple = (
      /^[^a-z]*$/.test(promptLower) === false &&
      (
        /(print|affiche|hello|bonjour|console|terminal)\s+(simple|basique)?/.test(promptLower) ||
        /^(affiche|crée|écris|fais)\s+(un|une)?\s*(script|print|affichage)/.test(promptLower) ||
        prompt.length < 80
      ) &&
        !/(flask|api|web|interface|serveur|server|http|route|base de données|database|sql|csv|scrap|calcul|algorithm)/.test(promptLower)
);
      
    const systemPrompt = estSimple ? `Tu es un développeur Python qui génère UNIQUEMENT ce qui est demandé, sans sur-ingénierie.

DEMANDE : "${prompt}"

STRUCTURE OBLIGATOIRE — MAXIMUM 2 FICHIERS :
1. run.py — le script qui fait exactement ce qui est demandé
2. requirements.txt — dépendances (vide si aucune)

INTERDICTIONS ABSOLUES :
- PAS de Flask, Django, FastAPI sauf si explicitement demandé
- PAS de serveur web
- PAS de templates HTML
- PAS de structure moteur/interface/templates sauf si demandé
- PAS de dossiers inutiles

FORMAT DE SORTIE — RÈGLE ABSOLUE :

\`\`\`python:run.py
print("Hello Kenny")
\`\`\`

\`\`\`txt:requirements.txt
# Aucune dépendance externe
\`\`\`

RÈGLES CRITIQUES :
1. TOUJOURS 3 backticks + langue:nom_fichier + saut de ligne
2. Si la demande est "affiche Hello Kenny", run.py = print("Hello Kenny")
3. Ne pas inventer de fonctionnalités non demandées
4. requirements.txt vide = commentaire seulement
5. Direct les blocs, PAS d'explications avant/après
` : `Tu es un développeur expert en Python, Flask et data science.

Génère une application COMPLÈTE et FONCTIONNELLE avec cette structure OBLIGATOIRE :
1. moteur/__init__.py (vide)
2. moteur/config.py
3. moteur/moteur.py
4. interface/__init__.py (vide)
5. interface/serveur.py
6. templates/index.html
7. data/donnees.json
8. requirements.txt
9. run.py

FORMAT DE SORTIE — RÈGLE ABSOLUE (sinon ton travail est REJETÉ) :

Chaque fichier DOIT être dans un bloc avec 3 backticks, langue, deux-points, chemin, puis saut de ligne :

\`\`\`python:moteur/config.py
CONFIG = { ... }
\`\`\`

\`\`\`python:moteur/moteur.py
def ma_fonction():
    ...
\`\`\`

\`\`\`python:interface/serveur.py
from flask import Flask
...
\`\`\`

\`\`\`html:templates/index.html
<!DOCTYPE html>
...
\`\`\`

\`\`\`json:data/donnees.json
{ "key": "value" }
\`\`\`

\`\`\`txt:requirements.txt
flask>=2.0.0
\`\`\`

\`\`\`python:run.py
from interface.serveur import app
if __name__ == "__main__":
    app.run()
\`\`\`

RÈGLES CRITIQUES :
1. TOUJOURS 3 backticks AVANT et APRÈS chaque fichier
2. TOUJOURS le nom du fichier juste après la langue, séparé par : (pas d'espace)
3. Code complet et fonctionnel — JAMAIS de "..." ni "TODO"
4. requirements.txt avec TOUTES les dépendances (flask, etc.)
5. run.py doit lancer Flask sur process.env.PORT || 3000
6. Pour les bases de données, config.py DOIT utiliser SQLite en fallback :
   SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///kenny.db")
   (SQLite fonctionne partout, PostgreSQL sera utilisé en production via DATABASE_URL)
7. FICHIERS OBLIGATOIRES — TOUJOURS GÉNÉRER CES 7 FICHIERS :
   - moteur/config.py, moteur/moteur.py
   - interface/serveur.py (avec create_app())
   - templates/index.html
   - data/donnees.json (données d'exemple réelles)
   - requirements.txt (liste COMPLÈTE des dépendances)
   - run.py (même si create_app() est dans serveur.py, run.py DOIT exister et lancer Flask sur PORT)
   - __init__.py pour chaque dossier (moteur/__init__.py, interface/__init__.py)
8. Ne réponds PAS avec des explications avant/après les blocs — direct les blocs de code
`;

    // 🎯 Recherche web si la lib est mentionnée
envoyer('status', { message: '🔍 Analyse de la demande...' });
const contexteWeb = await chercherContexteWeb(prompt);
if (contexteWeb) {
  systemPrompt += `\n\n${contexteWeb}`;
  envoyer('status', { message: '✅ Contexte web ajouté' });
}

// 🎯 Routeur intelligent
envoyer('status', { message: '🤖 Génération multi-providers...' });
const genResult = await genererAvecRouteur(prompt, systemPrompt, { estSimple });

if (!genResult.success) {
  envoyer('error', { message: '❌ Aucun provider n\'a pu générer : ' + genResult.error });
  if (!closed && !res.writableEnded) { res.write('event: end\ndata: {}\n\n'); res.end(); }
  return;
}

let reponse = genResult.reponse;
envoyer('status', { message: `✅ Généré par ${genResult.provider}` });
    let blocks = extraireBlocs(reponse);

    // [DEBUG] Voir la réponse brute de Groq si 0 fichiers
    if (blocks.length === 0) {
      envoyer('debug_groq', {
        length: reponse.length,
        nbBackticks: (reponse.match(/```/g) || []).length,
        preview: reponse.substring(0, 800),
        previewFin: reponse.substring(Math.max(0, reponse.length - 400))
      });

      // 🚫 Refuser le build si le modèle a halluciné
      envoyer('error', {
        message: '⚠️ Le modèle IA a généré du contenu invalide. Réessaie avec un prompt plus simple.'
      });
      if (!closed && !res.writableEnded) { res.write('event: end\ndata: {}\n\n'); res.end(); }
      return;
    }

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

    buildsEnCours.set(project_id, {
  active: true,
  etape: 'test',
  message: '🧪 Test du code dans la sandbox...',
  startedAt: buildsEnCours.get(project_id)?.startedAt,
  updatedAt: new Date().toISOString()
});
envoyer('status', { message: '🧪 Test du code dans la sandbox...' }); 
  let testResult = await tester.testerCodePython(blocks);
  sandboxFinale = testResult.sandbox;

  envoyer('test_result', {
    tour: 0,
    success: testResult.success,
    exitCode: testResult.exitCode || null,
    fichierCoupable: testResult.fichierCoupable || null,
    stdout: (testResult.stdout || '').substring(0, 800),
    stderr: (testResult.stderr || '').substring(0, 800)
  });

  let essais = 0;
  const MAX_ESSAIS = 3;

  while (!testResult.success && essais < MAX_ESSAIS && !closed) {
    essais++;
    buildsEnCours.set(project_id, {
      active: true,
      etape: 'correction',
      tentative: essais,
      maxEssais: MAX_ESSAIS,
      message: `🔧 Correction ${essais}/${MAX_ESSAIS} — fichier : ${testResult.fichierCoupable || '?'}`,
      startedAt: buildsEnCours.get(project_id)?.startedAt,
      updatedAt: new Date().toISOString()
    });
    envoyer('status', { message: `🔧 Correction ${essais}/${MAX_ESSAIS} — fichier : ${testResult.fichierCoupable || '?'}` });

    try {
      const fichierCoupableNom = testResult.fichierCoupable
    || (blocks.find(b => b.nom === 'run.py')?.nom)
    || (blocks.find(b => b.nom === 'main.py')?.nom)
    || (blocks.find(b => b.nom === 'app.py')?.nom)
    || (blocks.find(b => b.nom === 'interface/serveur.py')?.nom)
    || (blocks.find(b => b.nom.endsWith('/serveur.py'))?.nom)
    || (blocks[0]?.nom);  // ← fallback final : le premier fichier
      const fichierCible = blocks.find(b => b.nom === fichierCoupableNom);

      if (!fichierCible) {
        envoyer('message', { role: 'ia', content: `⚠️ Fichier "${fichierCoupableNom}" introuvable, abandon.` });
        break;
      }

      const correctionResult = await corrigerFichierCible(
        prompt,
        fichierCible,
        testResult.stderr || testResult.stdout,
        keys,
        project_id,
        null 
  );

      if (!correctionResult.success) {
        envoyer('message', { role: 'ia', content: `⚠️ Correction impossible au tour ${essais} : ${correctionResult.error || ''}` });
        break;
      }

      if (correctionResult.explication) {
        envoyer('message', {
          role: 'ia',
          content: `Tentative ${essais}/${MAX_ESSAIS} (${correctionResult.provider}) :\n${correctionResult.explication.substring(0, 800)}`
        });
      }

      blocks = blocks.map(b => b.nom === fichierCible.nom ? correctionResult.fichierCorrige : b);

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

      if (testResult.sandbox && typeof testResult.sandbox.kill === 'function') {
        await testResult.sandbox.kill().catch(() => {});
      }

      testResult = await tester.testerCodePython(blocks);
      sandboxFinale = testResult.sandbox;

      envoyer('test_result', {
        tour: essais,
        success: testResult.success,
        exitCode: testResult.exitCode || null,
        fichierCoupable: testResult.fichierCoupable || null,
        stdout: (testResult.stdout || '').substring(0, 800),
        stderr: (testResult.stderr || '').substring(0, 800)
      });
    } catch (e) {
      console.log('Erreur correction:', e.message);
      envoyer('message', { role: 'ia', content: `Erreur correction : ${e.message}` });
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
  const current = buildsEnCours.get(project_id) || {};
  buildsEnCours.set(project_id, {
    ...current,
    active: false,
    etape: 'termine',
    endedAt: new Date().toISOString()
  });
  setTimeout(() => buildsEnCours.delete(project_id), 5 * 60 * 1000);

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
  // ============================================
// 📊 /api/build/status/:project_id — Progress du build
// ============================================
app.get('/api/build/status/:project_id', async (req, res) => {
  const firebase_uid = req.headers['x-firebase-uid'];
  if (!firebase_uid) {
    return res.status(400).json({ error: 'Header x-firebase-uid requis' });
  }
  const owns = await verifierProprietaireProjet(firebase_uid, req.params.project_id);
  if (!owns) {
    return res.status(403).json({ error: 'Accès refusé' });
  }
  const status = buildsEnCours.get(req.params.project_id);
  if (!status) {
    return res.json({
      active: false,
      etape: 'inconnu',
      message: 'Aucun build en cours pour ce projet'
    });
  }
  res.json(status);
});
// ============================================
// 📂 /api/projects/:project_id/files — Fichiers du projet
// ============================================
app.get('/api/projects/:project_id/files', async (req, res) => {
  const firebase_uid = req.headers['x-firebase-uid'];
  if (!firebase_uid) {
    return res.status(400).json({ error: 'Header x-firebase-uid requis' });
  }

  const owns = await verifierProprietaireProjet(firebase_uid, req.params.project_id);
  if (!owns) {
    return res.status(403).json({ error: 'Accès refusé à ce projet' });
  }

  try {
    const files = await withPg(async (client) => {
      const r = await client.query(
        'SELECT id, name, language, content, updated_at FROM files WHERE project_id = $1 ORDER BY name ASC',
        [req.params.project_id]
      );
      return r.rows;
    });
    res.json({ success: true, files });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// 💬 /api/projects/:project_id/messages — Historique chat
// ============================================
app.get('/api/projects/:project_id/messages', async (req, res) => {
  const firebase_uid = req.headers['x-firebase-uid'];
  if (!firebase_uid) {
    return res.status(400).json({ error: 'Header x-firebase-uid requis' });
  }

  const owns = await verifierProprietaireProjet(firebase_uid, req.params.project_id);
  if (!owns) {
    return res.status(403).json({ error: 'Accès refusé à ce projet' });
  }

  try {
    const messages = await withPg(async (client) => {
      const r = await client.query(
        'SELECT id, role, content, created_at FROM conversation_memory WHERE project_id = $1 ORDER BY created_at ASC',
        [req.params.project_id]
      );
      return r.rows;
    });
    res.json({ success: true, messages });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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
// ============================================
// 🚀 /api/deploy — Déploiement manuel (bouton "Déployer")
// ============================================
app.post('/api/deploy', iaLimiter, async (req, res) => {
  const { firebase_uid, project_id, project_name } = req.body;
  if (!firebase_uid || !project_id || !project_name) {
    return res.status(400).json({ error: 'Champs requis : firebase_uid, project_id, project_name' });
  }

  const owns = await verifierProprietaireProjet(firebase_uid, project_id);
  if (!owns) return res.status(403).json({ error: 'Accès refusé à ce projet' });

  const keys = await getKeysForUser(firebase_uid);
  if (!keys.render || !keys.renderOwner) {
    return res.status(400).json({ error: 'Token Render non configuré' });
  }

  try {
    // 1) Récupère le workspace
    const ws = await withPg(async (client) => {
      const r = await client.query('SELECT * FROM workspaces WHERE project_id = $1', [project_id]);
      return r.rows[0] || null;
    });
    if (!ws) return res.status(404).json({ error: 'Aucun workspace pour ce projet' });
    if (!ws.github_repo) return res.status(400).json({ error: 'Repo GitHub non créé' });

    // 2) Détermine le langage (python si run.py, sinon web)
    const files = await withPg(async (client) => {
      const r = await client.query('SELECT name FROM files WHERE project_id = $1', [project_id]);
      return r.rows;
    });
    const langage = files.some(f => f.name === 'run.py' || f.name.endsWith('.py')) ? 'python' : 'web';

    // 3) Crée le service Render s'il n'existe pas
    let renderResult;
    if (ws.render_service_id) {
      renderResult = { success: true, service_id: ws.render_service_id, service_url: ws.render_service_url, reused: true };
    } else {
      // push GitHub d'abord (au cas où pas fait)
      const allFiles = await withPg(async (client) => {
        const r = await client.query('SELECT name, language, content FROM files WHERE project_id = $1', [project_id]);
        return r.rows.map(f => ({ nom: f.name, langage: f.language, contenu: f.content }));
      });
      if (allFiles.length > 0) {
        await pushGitHubMultiDossiers(ws.github_repo, allFiles, keys.github);
      }
      renderResult = await creerServiceRender(project_name, ws.github_clone_url, keys.render, keys.renderOwner, langage);
    }

    if (!renderResult.success) {
      return res.status(500).json({
        error: renderResult.reason || renderResult.error || 'Déploiement Render échoué',
        skipped: renderResult.skipped || false
      });
    }

    // 4) Met à jour le workspace
    await withPg(async (client) => {
      await client.query(
        'UPDATE workspaces SET render_service_id = $1, render_service_url = $2 WHERE project_id = $3',
        [renderResult.service_id, renderResult.service_url, project_id]
      );
    });

    res.json({
      success: true,
      service_id: renderResult.service_id,
      service_url: renderResult.service_url,
      message: renderResult.reused ? 'Service existant réutilisé' : 'Service créé — build en cours (~3 min)'
    });
  } catch (e) {
    console.error('Erreur /api/deploy:', e.message);
    res.status(500).json({ error: e.message });
  }
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('Kenny serveur sur le port ' + PORT);
  console.log(`Modèle Gemini : ${GEMINI_MODEL}`);
});
server.on('error', (err) => {
  console.error('❌ Listen error:', err.message);
  process.exit(1);
});

// ============================================
// 🔒 FERMETURE PROPRE (Render envoie SIGTERM avant de tuer)
// ============================================
let _arretEnCours = false;

async function _arretPropre(signal) {
  if (_arretEnCours) return;
  _arretEnCours = true;
  console.log(`${signal} reçu — arrêt propre...`);

  // 1) Fermer la sandbox E2B EN PREMIER (sinon facturée 1h de plus)
  try {
    await sandbox.fermerSandbox();
    console.log('✅ Sandbox E2B fermée');
  } catch (e) {
    console.error('❌ Erreur fermeture sandbox:', e.message);
  }

  // 2) Fermer le serveur HTTP
  server.close(() => {
    console.log('✅ Serveur HTTP fermé');
    process.exit(0);
  });

  // 3) Forcer la sortie si le serveur ne se ferme pas en 5s
  setTimeout(() => {
    console.log('⏱️ Forçage sortie après 5s');
    process.exit(0);
  }, 5000).unref();
}

process.on('SIGTERM', () => _arretPropre('SIGTERM'));
process.on('SIGINT',  () => _arretPropre('SIGINT'));
