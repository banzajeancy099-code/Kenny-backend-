

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { Client } = require('pg');
const crypto = require('crypto');

const antivirus = require('./agents/antivirus');
const sandbox = require('./agents/sandbox');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

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

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'kenny_default_secret_key_2026';
const IV_LENGTH = 16;

function chiffrer(text) {
  if (!text) return null;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.padEnd(32).slice(0, 32)), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function dechiffrer(text) {
  if (!text) return null;
  try {
    const parts = text.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = Buffer.from(parts[1], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.padEnd(32).slice(0, 32)), iv);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (e) { return null; }
}

async function getNeonClient(connString = null) {
  const client = new Client({
    connectionString: connString || GLOBAL_KEYS.neonConn,
    ssl: { rejectUnauthorized: false }
  });
  await client.connect();
  return client;
}

// ============================================
// RÉCUPÉRER LES CLÉS D'UN USER
// ============================================
async function getKeysForUser(firebase_uid) {
  const keys = { ...GLOBAL_KEYS };
  if (!firebase_uid) return keys;
  try {
    const client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return keys; }
    const userId = user.rows[0].id;
    const envVars = await client.query('SELECT key, value FROM env_variables WHERE user_id = $1', [userId]);
    await client.end();
    for (const row of envVars.rows) {
      const k = row.key.toUpperCase().trim();
      const v = dechiffrer(row.value);
      if (!v) continue;
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
  } catch (e) {}
  return keys;
}

// ============================================
// VÉRIFIER LE QUOTA
// ============================================
async function verifierQuota(firebase_uid) {
  try {
    const client = await getNeonClient();
    const user = await client.query(
      'SELECT id, plan, commands_today, last_command_reset FROM users WHERE firebase_uid = $1',
      [firebase_uid]
    );
    if (user.rows.length === 0) { await client.end(); return { allowed: false, error: 'User non trouvé' }; }
    const u = user.rows[0];
    if (u.plan === 'pro' || u.plan === 'premium') { await client.end(); return { allowed: true, remaining: '∞', plan: u.plan }; }
    const today = new Date().toISOString().split('T')[0];
    const lastReset = u.last_command_reset ? u.last_command_reset.toISOString().split('T')[0] : null;
    let commandsToday = u.commands_today || 0;
    if (lastReset !== today) {
      commandsToday = 0;
      await client.query('UPDATE users SET commands_today = 0, last_command_reset = $1 WHERE id = $2', [today, u.id]);
    }
    const LIMITE_FREE = 50;
    if (commandsToday >= LIMITE_FREE) {
      await client.end();
      return { allowed: false, error: `Limite atteinte (${LIMITE_FREE}/jour). Passe au plan Pro.`, plan: u.plan, used: commandsToday, limit: LIMITE_FREE };
    }
    await client.query('UPDATE users SET commands_today = commands_today + 1 WHERE id = $1', [u.id]);
    await client.end();
    return { allowed: true, plan: u.plan, used: commandsToday + 1, limit: LIMITE_FREE, remaining: LIMITE_FREE - commandsToday - 1 };
  } catch (e) {
    return { allowed: false, error: e.message };
  }
}

// ============================================
// ROUTE DE TEST
// ============================================
app.get('/', (req, res) => {
  res.json({ message: 'Kenny OK', gemini: GLOBAL_KEYS.gemini ? '✅' : '❌' });
});

// ============================================
// SYNC USER
// ============================================
app.post('/api/user/sync', async (req, res) => {
  const { firebase_uid, email } = req.body;
  if (!firebase_uid || !email) return res.status(400).json({ error: 'Champs requis' });
  let client;
  try {
    client = await getNeonClient();
    const existing = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    let userId;
    if (existing.rows.length > 0) {
      userId = existing.rows[0].id;
      await client.query('UPDATE users SET last_login = NOW() WHERE id = $1', [userId]);
    } else {
      const inserted = await client.query(`INSERT INTO users (firebase_uid, email) VALUES ($1, $2) RETURNING id`, [firebase_uid, email]);
      userId = inserted.rows[0].id;
    }
    await client.end();
    res.json({ success: true, user_id: userId });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// ENVIRONNEMENT
// ============================================
app.get('/api/env/load/:firebase_uid', async (req, res) => {
  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [req.params.firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return res.json({ success: true, variables: [] }); }
    const result = await client.query('SELECT key, value FROM env_variables WHERE user_id = $1 ORDER BY created_at ASC', [user.rows[0].id]);
    await client.end();
    res.json({ success: true, variables: result.rows.map(r => ({ key: r.key, value: r.value ? '••••••••' : '' })) });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/env/save', async (req, res) => {
  const { firebase_uid, variables } = req.body;
  if (!firebase_uid || !Array.isArray(variables)) return res.status(400).json({ error: 'Champs requis' });
  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return res.status(404).json({ error: 'User non trouvé' }); }
    const userId = user.rows[0].id;
    const old = await client.query('SELECT key, value FROM env_variables WHERE user_id = $1', [userId]);
    const oldMap = new Map();
    for (const row of old.rows) oldMap.set(row.key, row.value);
    await client.query('DELETE FROM env_variables WHERE user_id = $1', [userId]);
    for (const v of variables) {
      if (!v.key || !v.key.trim()) continue;
      let finalValue = v.value;
      if (v.value === '••••••••' && oldMap.has(v.key)) finalValue = oldMap.get(v.key);
      let encrypted = (finalValue && finalValue !== '••••••••') ? chiffrer(finalValue) : finalValue;
      await client.query('INSERT INTO env_variables (user_id, key, value) VALUES ($1, $2, $3)', [userId, v.key.trim(), encrypted]);
    }
    await client.end();
    res.json({ success: true });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/env/test', async (req, res) => {
  const { key, value } = req.body;
  if (!key || !value) return res.status(400).json({ error: 'Champs requis' });
  const results = {};
  const keyUpper = key.toUpperCase();
  try {
    if (keyUpper.includes('GEMINI')) {
      await axios.post(`https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${value}`, { contents: [{ role: 'user', parts: [{ text: 'test' }] }] }, { timeout: 10000 });
      results[key] = '✅ OK';
    } else if (keyUpper.includes('NEON')) {
      await axios.get('https://console.neon.tech/api/v2/projects', { headers: { 'Authorization': `Bearer ${value}` }, timeout: 10000 });
      results[key] = '✅ OK';
    } else if (keyUpper.includes('GITHUB')) {
      await axios.get('https://api.github.com/user', { headers: { 'Authorization': `token ${value}` }, timeout: 10000 });
      results[key] = '✅ OK';
    } else if (keyUpper.includes('CLOUDFLARE')) {
      await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', { headers: { 'Authorization': `Bearer ${value}` }, timeout: 10000 });
      results[key] = '✅ OK';
    } else if (keyUpper.includes('RENDER')) {
      await axios.get('https://api.render.com/v1/services?limit=1', { headers: { 'Authorization': `Bearer ${value}` }, timeout: 10000 });
      results[key] = '✅ OK';
    } else {
      results[key] = '⚠️ Type inconnu';
    }
  } catch (e) {
    results[key] = '❌ ' + (e.response?.status || e.message);
  }
  res.json({ success: true, results });
});

// ============================================
// PROJETS
// ============================================
app.post('/api/projects/create', async (req, res) => {
  const { firebase_uid, name } = req.body;
  if (!firebase_uid || !name) return res.status(400).json({ error: 'Champs requis' });
  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return res.status(404).json({ error: 'User non trouvé' }); }
    const project = await client.query('INSERT INTO projects (user_id, name) VALUES ($1, $2) RETURNING *', [user.rows[0].id, name]);
    await client.end();
    res.json({ success: true, project: project.rows[0] });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/projects/list/:firebase_uid', async (req, res) => {
  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [req.params.firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return res.json({ success: true, projects: [] }); }
    const projects = await client.query('SELECT * FROM projects WHERE user_id = $1 ORDER BY created_at DESC', [user.rows[0].id]);
    await client.end();
    res.json({ success: true, projects: projects.rows });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/projects/:project_id/details', async (req, res) => {
  let client;
  try {
    client = await getNeonClient();
    const project = await client.query('SELECT * FROM projects WHERE id = $1', [req.params.project_id]);
    if (project.rows.length === 0) { await client.end(); return res.status(404).json({ error: 'Projet non trouvé' }); }
    const messages = await client.query('SELECT role, content FROM conversation_memory WHERE project_id = $1 ORDER BY created_at ASC', [req.params.project_id]);
    const files = await client.query('SELECT * FROM files WHERE project_id = $1 ORDER BY created_at ASC', [req.params.project_id]);
    const workspace = await client.query('SELECT * FROM workspaces WHERE project_id = $1', [req.params.project_id]);
    await client.end();
    res.json({ success: true, project: project.rows[0], messages: messages.rows, files: files.rows, workspace: workspace.rows[0] || null });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// WORKSPACE AUTO (Cloudflare désactivé)
// ============================================
async function creerRepoGitHub(name, userToken) {
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

async function creerProjetNeon(name) {
  try {
    const projectName = 'kenny-' + name.toLowerCase().replace(/[^a-z0-9-]/g, '-').substring(0, 40) + '-' + Date.now().toString(36);
    const res = await axios.post('https://console.neon.tech/api/v2/projects',
      { project: { name: projectName, region_id: 'aws-eu-central-1', pg_version: 16 } },
      { headers: { 'Authorization': `Bearer ${GLOBAL_KEYS.neon}`, 'Content-Type': 'application/json', 'Accept': 'application/json' } }
    );
    const projectId = res.data.project.id;
    const connRes = await axios.get(
      `https://console.neon.tech/api/v2/projects/${projectId}/connection_uri?database_name=neondb&role_name=neondb_owner`,
      { headers: { 'Authorization': `Bearer ${GLOBAL_KEYS.neon}`, 'Accept': 'application/json' } }
    );
    return { success: true, project_id: projectId, connection_uri: connRes.data.uri };
  } catch (e) {
    return { success: false, error: e.response?.data?.message || e.message };
  }
}

async function creerServiceRender(name, repoUrl, userToken, ownerId, langage = 'web') {
  if (!userToken || !ownerId) return { success: false, skipped: true, reason: 'Token Render non configuré' };
  try {
    const serviceName = 'kenny-' + name.toLowerCase().replace(/[^a-z0-9-]/g, '-').substring(0, 40) + '-' + Date.now().toString(36);
    
    let envConfig;
    if (langage === 'python') {
      envConfig = {
        env: 'python',
        buildCommand: 'pip install -r requirements.txt',
        startCommand: 'python run.py'
      };
    } else {
      envConfig = {
        env: 'node',
        buildCommand: 'npm install',
        startCommand: 'node server.js'
      };
    }
    
    const res = await axios.post('https://api.render.com/v1/services',
      {
        type: 'web_service', 
        name: serviceName, 
        ownerId: ownerId, 
        repo: repoUrl, 
        branch: 'main', 
        autoDeploy: 'yes',
        serviceDetails: { 
          ...envConfig, 
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
// 🔥 Cloudflare DÉSACTIVÉ
async function creerZoneCloudflare(name) {
  return { success: false, skipped: true, reason: 'Cloudflare désactivé temporairement' };
}

app.post('/api/workspaces/create', async (req, res) => {
  const { firebase_uid, project_id, project_name } = req.body;
  if (!firebase_uid || !project_id || !project_name) return res.status(400).json({ error: 'Champs requis' });

  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return res.status(404).json({ error: 'User non trouvé' }); }
    const userId = user.rows[0].id;

    const ws = await client.query('INSERT INTO workspaces (project_id, user_id, status) VALUES ($1, $2, $3) RETURNING id', [project_id, userId, 'creating']);
    const workspaceId = ws.rows[0].id;
    await client.end();

    const keys = await getKeysForUser(firebase_uid);

    console.log('📦 GitHub...');
    const githubResult = await creerRepoGitHub(project_name, keys.github);
    
    console.log('🗄️ Neon...');
    const neonResult = await creerProjetNeon(project_name);
    
    console.log('🚀 Render...');
    const renderResult = await creerServiceRender(project_name, githubResult.success ? githubResult.clone_url : '', keys.render, keys.renderOwner, 'web');
    
    console.log('🌐 Cloudflare (désactivé)');
    const cloudflareResult = await creerZoneCloudflare(project_name);

    const client2 = await getNeonClient();
    await client2.query(`
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
    await client2.end();

    res.json({ success: true, workspace: { github: githubResult, neon: neonResult, render: renderResult, cloudflare: cloudflareResult } });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// 🔥 FULL BUILD — Génération complète
// ============================================
app.post('/api/build/full', async (req, res) => {
  const { firebase_uid, project_id, prompt } = req.body;
  if (!firebase_uid || !project_id || !prompt) return res.status(400).json({ error: 'Champs requis' });

  const keys = await getKeysForUser(firebase_uid);
  if (!keys.gemini) return res.status(500).json({ error: 'Clé Gemini manquante' });

  // SSE
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const envoyer = (type, data) => res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);

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

2. BACKEND (server.js) :
   - Express.js
   - Routes API : /api/items, /api/users, etc.
   - Connexion à une base de données (PostgreSQL via pg)
   - Gestion d'erreurs
   - Port process.env.PORT || 3000

3. PACKAGE.JSON :
   - name, version, main, scripts.start, dependencies
   - Dépendances : express, cors, pg, dotenv

4. FRONTEND :
   - HTML complet avec toutes les pages (menu, accueil, ajout, etc.)
   - CSS moderne (Tailwind ou custom)
   - JS avec fetch vers /api
   - Pas d'emojis dans le code

5. CHOIX TECHNIQUE :
   - Si l'app est SIMPLE → Vanilla HTML/CSS/JS + Express
   - Si l'app est COMPLEXE → React + Express (mais code en HTML/CSS/JS pour compatibilité)

6. FONCTIONNALITÉS COMPLÈTES :
   - Toutes les pages du menu fonctionnent
   - Les boutons font de vraies actions
   - La recherche marche
   - La base de données est utilisée
   - Les erreurs sont gérées

7. FORMAT DE SORTIE :
   - D'abord, explique ce que tu vas construire (2-3 phrases)
   - Ensuite, génère TOUS les fichiers avec \`\`\`langage:nom_fichier
   - Ne t'arrête PAS au milieu

Génère une application complète et fonctionnelle.`;

    envoyer('status', { message: '🔨 Génération du code complet...' });

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${keys.gemini}`,
      {
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 8000 }
      },
      { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
    );

    let reponse = response.data.candidates[0].content.parts[0].text;
let blocks = extraireBlocs(reponse);
    
    envoyer('status', { message: `📦 ${blocks.length} fichiers générés, sauvegarde...` });

    // Sauvegarder dans Neon
    const client = await getNeonClient();
    const oldFiles = await client.query('SELECT name FROM files WHERE project_id = $1', [project_id]);
    await client.query('DELETE FROM files WHERE project_id = $1', [project_id]);
    for (const file of blocks) {
      await client.query('INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
        [project_id, file.nom, file.langage, file.contenu]);
      envoyer('file', { name: file.nom, language: file.langage, content: file.contenu });
    }
    await client.end();

    // Push sur GitHub si workspace existe
    const wsClient = await getNeonClient();
    const ws = await wsClient.query('SELECT * FROM workspaces WHERE project_id = $1', [project_id]);
    await wsClient.end();

    if (ws.rows.length > 0 && ws.rows[0].github_repo) {
      envoyer('status', { message: '🐙 Push sur GitHub...' });
      const githubToken = keys.github;
      const repoFullName = ws.rows[0].github_repo;
      
      for (const file of blocks) {
        try {
          // Vérifier si le fichier existe déjà
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
        } catch (e) {
          console.log(`Erreur push ${file.nom}:`, e.message);
        }
      }
      envoyer('status', { message: '✅ Push GitHub terminé' });
    }

    // Afficher l'URL finale
    const finalUrl = ws.rows[0]?.render_service_url || ws.rows[0]?.github_repo || 'En cours...';
    envoyer('done', { 
      message: '✅ Full Build terminé !',
      url: finalUrl,
      files_count: blocks.length
    });

    res.write('event: end\ndata: {}\n\n');
    res.end();

  } catch (error) {
    console.error('Erreur full build:', error.message);
    envoyer('error', { message: error.message });
    res.end();
  }
});

function extraireBlocs(text) {
  const regex = /```(\w+)(?::([^\n]+))?\n([\s\S]*?)```/g;
  const blocs = [];
  let match;
  while ((match = regex.exec(text)) !== null) {
    const langage = match[1] || 'code';
    const nomFichier = match[2] ? match[2].trim() : null;
    const contenu = match[3].trim();

    let nom = nomFichier;
    if (!nom) {
      if (contenu.includes('from flask import') || contenu.includes('import flask')) {
        nom = 'app.py';
      } else if (contenu.includes('if __name__ ==')) {
        nom = 'run.py';
      } else {
        const ext = langage === 'html' ? 'html'
          : langage === 'javascript' || langage === 'js' ? 'js'
          : langage === 'css' ? 'css'
          : langage === 'json' ? 'json'
          : langage === 'python' || langage === 'py' ? 'py'
          : langage === 'markdown' ? 'md'
          : langage === 'txt' ? 'txt'
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
// ============================================
// 🔥 FONCTIONS FULL BUILD PYTHON
// ============================================

// 1. Détecter si le code est Python ou Web
function detecterLangagePrincipal(blocks) {
  const pyFiles = blocks.filter(b => b.nom.endsWith('.py'));
  const htmlFiles = blocks.filter(b => b.nom.endsWith('.html'));
  if (pyFiles.length > 0 && pyFiles.length >= htmlFiles.length) return 'python';
  return 'web';
}

// 2. Uploader les fichiers dans la sandbox E2B
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

// 3. Tester le code Python dans la sandbox
async function testerCodePython(blocks) {
  try {
    const sb = await uploaderDansSandbox(blocks);

    const mainFile = blocks.find(b => b.nom === 'run.py')
                  || blocks.find(b => b.nom === 'main.py')
                  || blocks.find(b => b.nom === 'app.py');

    if (!mainFile) {
      return { success: false, stderr: 'Aucun fichier principal trouvé (run.py, main.py, app.py)' };
    }

    const reqFile = blocks.find(b => b.nom === 'requirements.txt');
    if (reqFile) {
      const installResult = await sb.commands.run('pip install -r requirements.txt 2>&1', { timeoutMs: 120000 });
      if (installResult.exitCode !== 0) {
        return {
          success: false,
          stdout: installResult.stdout || '',
          stderr: `Échec pip install :\n${(installResult.stderr || installResult.stdout || '').substring(0, 2000)}`,
          exitCode: installResult.exitCode
        };
      }
    }

    const syntaxCheck = await sb.commands.run(
      `python3 -m py_compile ${mainFile.nom} 2>&1`,
      { timeoutMs: 15000 }
    );
    if (syntaxCheck.exitCode !== 0) {
      return {
        success: false,
        stdout: syntaxCheck.stdout || '',
        stderr: `Erreur de syntaxe :\n${(syntaxCheck.stderr || syntaxCheck.stdout || '').substring(0, 2000)}`,
        exitCode: syntaxCheck.exitCode
      };
    }

    const allPyFiles = blocks.filter(b => b.nom.endsWith('.py')).map(b => b.nom);
    if (allPyFiles.length > 1) {
      const pyCompile = await sb.commands.run(
        `python3 -m py_compile ${allPyFiles.join(' ')} 2>&1`,
        { timeoutMs: 20000 }
      );
      if (pyCompile.exitCode !== 0) {
        return {
          success: false,
          stdout: pyCompile.stdout || '',
          stderr: `Erreur de syntaxe dans un fichier :\n${(pyCompile.stderr || pyCompile.stdout || '').substring(0, 2000)}`,
          exitCode: pyCompile.exitCode
        };
      }
    }

    const runTest = await sb.commands.run(
      `timeout 5 python3 ${mainFile.nom} > /tmp/run.log 2>&1; echo "EXIT:$?"; cat /tmp/run.log`,
      { timeoutMs: 15000 }
    );

    const log = runTest.stdout || '';
    const crashImmediat = log.includes('Traceback') && !log.includes('EXIT:124');

    if (crashImmediat && !log.includes('EXIT:124')) {
      return {
        success: false,
        stdout: log,
        stderr: `Crash au démarrage :\n${log.substring(0, 2000)}`,
        exitCode: runTest.exitCode
      };
    }

    return {
      success: true,
      stdout: `✅ Tous les tests passent.\n${log.substring(0, 500)}`,
      stderr: '',
      exitCode: 0
    };
  } catch (e) {
    return { success: false, stderr: e.message };
  }
}

// 4. Push GitHub multi-dossiers
async function pushGitHubMultiDossiers(repoFullName, blocks, githubToken) {
  const results = [];
  for (const file of blocks) {
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
      results.push({ file: file.nom, success: true });
    } catch (e) {
      results.push({ file: file.nom, success: false, error: e.message });
    }
  }
  return results;
}

// ============================================
// 🔥 ROUTE FULL BUILD PYTHON
// ============================================
app.post('/api/build/python', async (req, res) => {
  const { firebase_uid, project_id, prompt } = req.body;
  if (!firebase_uid || !project_id || !prompt) return res.status(400).json({ error: 'Champs requis' });

  // 🔥 Détecter la langue de la demande
  function detecterLangue(texte) {
    const t = texte.toLowerCase();
    if (/\b(créer|crée|calculatrice|application|ajouter|supprimer|modifier|je|tu|il|nous|vous|avec|pour|dans|sur|qui|que|est|sont|une|un|des|le|la|les)\b/.test(t)) return 'français';
    if (/\b(create|crear|bere|make|build|calculate|app|add|remove|edit|with|for|in|on|who|that|is|are|a|an|the)\b/.test(t)) return 'anglais';
    if (/\b(crear|calculadora|aplicación|agregar|eliminar|modificar|yo|tú|él|nosotros|con|para|en|sobre|que|es|son|una|un|los|las)\b/.test(t)) return 'espagnol';
    if (/\b(erstelle|rechner|anwendung|hinzufügen|entfernen|bearbeiten|mit|für|in|auf|wer|das|ist|sind|ein|eine|der|die|das)\b/.test(t)) return 'allemand';
    if (/\b(criar|calculadora|aplicativo|adicionar|remover|editar|com|para|em|sobre|quem|que|é|são|um|uma|os|as)\b/.test(t)) return 'portugais';
    if (/\b(creare|calcolatrice|applicazione|aggiungere|rimuovere|modificare|con|per|in|su|chi|che|è|sono|un|una|i|le)\b/.test(t)) return 'italien';
    if (/[\u0600-\u06FF]/.test(t)) return 'arabe';
    if (/[\u4E00-\u9FFF]/.test(t)) return 'chinois';
    if (/[\u3040-\u30FF]/.test(t)) return 'japonais';
    return 'français';
  }
  
  const langue = detecterLangue(prompt);
  console.log(`🌍 Langue détectée : ${langue}`);
  const keys = await getKeysForUser(firebase_uid);
  if (!keys.gemini) return res.status(500).json({ error: 'Clé Gemini manquante' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const envoyer = (type, data) => res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);

  try {
    envoyer('status', { message: '🧠 Génération du code Python...' });

    const systemPrompt = `Tu es un développeur expert en Python, Flask et data science.

Génère une application COMPLÈTE et FONCTIONNELLE avec cette structure :

- \`\`\`python:moteur/config.py\`\`\` (configuration, seuils)
- \`\`\`python:moteur/moteur.py\`\`\` (logique principale)
- \`\`\`python:interface/serveur.py\`\`\` (Flask avec routes API)
- \`\`\`html:templates/index.html\`\`\` (interface Flask avec {{ }})
- \`\`\`json:data/donnees.json\`\`\` (données de test)
- \`\`\`txt:requirements.txt\`\`\` (flask, numpy, scipy)
- \`\`\`python:run.py\`\`\` (lanceur qui démarre Flask)

RÈGLES ABSOLUES :
1. Le code doit être COMPLET et fonctionnel
2. Pas de "..." ni de "TODO"
3. requirements.txt doit contenir TOUTES les dépendances
4. run.py doit lancer l'app Flask
5. Utilise le port 3000 (process.env.PORT || 3000)
6. N'utilise JAMAIS d'emojis dans le code

Génère tout.`;

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${keys.gemini}`,
      {
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 8000 }
      },
      { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
    );

   let reponse = response.data.candidates[0].content.parts[0].text;
let blocks = extraireBlocs(reponse);
    envoyer('status', { message: `📦 ${blocks.length} fichiers générés` });

    const client = await getNeonClient();
    await client.query('DELETE FROM files WHERE project_id = $1', [project_id]);
    for (const file of blocks) {
      await client.query(
        'INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
        [project_id, file.nom, file.langage, file.contenu]
      );
      envoyer('file', { name: file.nom, language: file.langage, content: file.contenu });
    }
    await client.end();

       envoyer('status', { message: '🧪 Test du code dans la sandbox...' });
    let testResult = await testerCodePython(blocks);
    let essais = 0;
    const MAX_ESSAIS = 3;

    while (!testResult.success && essais < MAX_ESSAIS) {
      essais++;
      envoyer('status', { message: `🔧 Correction auto (${essais}/${MAX_ESSAIS})...` });

      try {
        let fichiersActuels = '';
        for (const file of blocks) {
          fichiersActuels += `\n=== ${file.nom} ===\n${file.contenu}\n`;
        }

        const correctionPrompt = `Voici le code Python actuel qui a une erreur :

${fichiersActuels}

ERREUR EXACTE (sortie de la sandbox) :
\`\`\`
${testResult.stderr}
\`\`\`

TA MISSION (dans cet ordre) :

1. EXPLIQUE D'ABORD L'ERREUR EN FRANÇAIS :
   - Quelle est la cause ?
   - Quelle ligne est concernée ?
   - Pourquoi ça ne marche pas ?

2. ENSUITE, CORRIGE LE CODE :
   - Renvoie TOUS les fichiers corrigés
   - Format : \`\`\`python:nom_fichier

3. VÉRIFIE :
   - Tous les imports sont corrects
   - requirements.txt contient TOUTES les dépendances
   - Le code est complet et fonctionnel

STRUCTURE À RESPECTER :
- python:moteur/config.py
- python:moteur/moteur.py
- python:interface/serveur.py
- html:templates/index.html
- json:data/donnees.json
- txt:requirements.txt
- python:run.py

IMPORTANT :
1. Ne change PAS la structure des dossiers
2. Vérifie que TOUS les imports sont corrects
3. Vérifie que requirements.txt contient TOUTES les dépendances
4. Le code doit être complet et fonctionnel
5. Si le code est cassé, réécris-le complètement`;

        const correctionResponse = await axios.post(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${keys.gemini}`,
          {
            systemInstruction: { parts: [{ text: systemPrompt }] },
            contents: [
              { role: 'user', parts: [{ text: prompt }] },
              { role: 'model', parts: [{ text: reponse }] },
              { role: 'user', parts: [{ text: correctionPrompt }] }
            ],
            generationConfig: { temperature: 0.5, maxOutputTokens: 8000 }
          },
          { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
        );

        reponse = correctionResponse.data.candidates[0].content.parts[0].text;
        blocks = extraireBlocs(reponse);

        const explication = reponse.replace(/```[\s\S]*?```/g, '').trim();
        if (explication) {
          envoyer('message', { role: 'ia', content: `Tentative ${essais}/${MAX_ESSAIS} : ${explication.substring(0, 800)}` });
        }

        const client2 = await getNeonClient();
        await client2.query('DELETE FROM files WHERE project_id = $1', [project_id]);
        for (const file of blocks) {
          await client2.query(
            'INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
            [project_id, file.nom, file.langage, file.contenu]
          );
          envoyer('file', { name: file.nom, language: file.langage, content: file.contenu });
        }
        await client2.end();

        testResult = await testerCodePython(blocks);
      } catch (e) {
        console.log('Erreur correction:', e.message);
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
        content: `⚠️ Le code a été généré mais il y a encore une erreur après ${essais} correction${essais > 1 ? 's' : ''}. Tu peux le corriger manuellement.`
      });
    }
    const wsClient = await getNeonClient();
const ws = await wsClient.query('SELECT * FROM workspaces WHERE project_id = $1', [project_id]);
await wsClient.end();

if (ws.rows.length > 0 && ws.rows[0].github_repo) {
  envoyer('status', { message: '🐙 Push sur GitHub...' });
  const pushResults = await pushGitHubMultiDossiers(ws.rows[0].github_repo, blocks, keys.github);
  const reussis = pushResults.filter(r => r.success).length;
  envoyer('status', { message: `✅ ${reussis}/${pushResults.length} fichiers pushés sur GitHub` });
}

// 🔥 Détection du langage et info Render
const langage = detecterLangagePrincipal(blocks);
envoyer('status', { message: `🔤 Langage détecté : ${langage}` });

    const finalUrl = ws.rows[0]?.render_service_url || ws.rows[0]?.github_repo || 'En cours...';
    envoyer('done', { 
      message: '✅ Build Python terminé !',
      url: finalUrl,
      files_count: blocks.length,
      tested: testResult.success
    });

    res.write('event: end\ndata: {}\n\n');
    res.end();

  } catch (error) {
    console.error('Erreur build python:', error.message);
    envoyer('error', { message: error.message });
    res.end();
  }
});
// ============================================
// CHAT STREAMING (normal)
// ============================================
app.post('/api/chat/stream', async (req, res) => {
  const { message, history, firebase_uid, project_id, terminal_history } = req.body;
  if (!message) return res.status(400).json({ error: 'Message requis' });

  const keys = await getKeysForUser(firebase_uid);
  if (!keys.gemini) return res.status(500).json({ error: 'Clé Gemini manquante' });
  if (!project_id) return res.json({ error: 'Crée un projet d\'abord', need_project: true });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const envoyer = (type, data) => res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);
  let annule = false;
  req.on('close', () => { annule = true; });

  try {
    const contents = [];
    if (history && Array.isArray(history)) {
      history.forEach(msg => {
        contents.push({ role: msg.role === 'user' ? 'user' : 'model', parts: [{ text: msg.content }] });
      });
    }
    let terminalContext = '';
    if (terminal_history && terminal_history.length > 0) {
      terminalContext = `\n\nCOMMANDES RÉCENTES :\n${terminal_history.slice(-10).join('\n')}`;
    }
    contents.push({ role: 'user', parts: [{ text: message }] });

    let iteration = 0;
    const MAX_ITERATIONS = 3;
    let memoire = [];
    let dejaAffiche = new Set();

    while (iteration < MAX_ITERATIONS && !annule) {
      iteration++;
      envoyer('status', { message: `Étape ${iteration}/${MAX_ITERATIONS}...` });

      const systemPrompt = `Tu es un développeur senior expert. Ton caractère est comme ChatGPT.

RÈGLES :
- Tu PARLES et tu CODES EN MÊME TEMPS.
- Tu ne te présentes JAMAIS.
- Tu réponds en français.
- Tu enchaînes SANS ATTENDRE.

1. AUTO-INSTALLATION :
   - NE FAIS JAMAIS "apt-get update" (bloqué)
   - La sandbox a DÉJÀ : Python 3.13, Node.js, npm, pip, git
   - [INSTALL: pip install flask] / [INSTALL: npm install react]

2. CODE : HTML/CSS/JS complet

3. IMAGES : [IMAGE: description en anglais]

${terminalContext}

MÉMOIRE :
${memoire.join('\n')}`;

      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${keys.gemini}`,
        {
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: contents,
          generationConfig: { temperature: 0.8, maxOutputTokens: 8000 }
        },
        { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
      );

      if (annule) break;

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
        if (annule) break;
        envoyer('terminal', { command: cmd, type: 'install' });
        const result = await executerSecurise(cmd);
        envoyer('terminal_result', { command: cmd, ...result });
        if (!result.success) { memoire.push(`Erreur install ${cmd}`); installEchouee = true; }
      }

      for (const cmd of commands) {
        if (annule) break;
        envoyer('terminal', { command: cmd, type: 'command' });
        const result = await executerSecurise(cmd);
        envoyer('terminal_result', { command: cmd, ...result });
        if (!result.success && result.stderr) memoire.push(`Erreur ${cmd}: ${result.stderr}`);
      }

      if (installEchouee) memoire = memoire.filter(m => !m.includes('Erreur install'));

      if (firebase_uid) {
        try {
          const client = await getNeonClient();
          const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
          if (user.rows.length > 0) {
            await client.query(`INSERT INTO conversation_memory (user_id, project_id, role, content) VALUES ($1, $2, 'user', $3)`, [user.rows[0].id, project_id, message]);
            await client.query(`INSERT INTO conversation_memory (user_id, project_id, role, content) VALUES ($1, $2, 'model', $3)`, [user.rows[0].id, project_id, reponse]);
          }
          await client.end();
        } catch (e) {}
      }

      if (blocks.length > 0) {
        try {
          const client = await getNeonClient();
          const oldFiles = await client.query('SELECT name, language, content FROM files WHERE project_id = $1', [project_id]);
          const fileMap = new Map();
          for (const f of oldFiles.rows) fileMap.set(f.name, { nom: f.name, langage: f.language, contenu: f.content });
          for (const file of blocks) fileMap.set(file.nom, { nom: file.nom, langage: file.langage, contenu: file.contenu });
          await client.query('DELETE FROM files WHERE project_id = $1', [project_id]);
          for (const f of fileMap.values()) {
            await client.query('INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)', [project_id, f.nom, f.langage, f.contenu]);
          }
          await client.end();
        } catch (e) {}
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

    if (annule) envoyer('cancelled', { message: 'Arrêté' });
    res.write('event: end\ndata: {}\n\n');
    res.end();
  } catch (error) {
    envoyer('error', { message: error.message });
    res.end();
  }
});

async function executerSecurise(cmd) {
  try {
    const verif = antivirus.verifierCommande(cmd, 'libre');
    if (!verif.allowed) return { success: false, blocked: true, reason: verif.reason };
    const result = await sandbox.executerCommande(cmd);
    return { success: result.success, stdout: result.stdout || '', stderr: result.stderr || '', exitCode: result.exitCode };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ============================================
// TERMINAL (avec quota)
// ============================================
app.post('/api/terminal/exec', async (req, res) => {
  const { commande, firebase_uid } = req.body;
  if (!commande) return res.status(400).json({ error: 'Commande vide' });
  
  if (firebase_uid) {
    const quota = await verifierQuota(firebase_uid);
    if (!quota.allowed) {
      return res.json({ blocked: true, reason: quota.error, quota_exceeded: true, plan: quota.plan, used: quota.used, limit: quota.limit });
    }
  }
  
  const result = await executerSecurise(commande);
  return res.json({ ...result, commande });
});

app.post('/api/terminal/close', async (req, res) => {
  await sandbox.fermerSandbox();
  res.json({ success: true });
});

// ============================================
// QUOTA
// ============================================
app.get('/api/quota/:firebase_uid', async (req, res) => {
  try {
    const client = await getNeonClient();
    const user = await client.query('SELECT plan, commands_today, last_command_reset FROM users WHERE firebase_uid = $1', [req.params.firebase_uid]);
    await client.end();
    if (user.rows.length === 0) return res.json({ success: false });
    const u = user.rows[0];
    const LIMITE_FREE = 50;
    const today = new Date().toISOString().split('T')[0];
    const lastReset = u.last_command_reset ? u.last_command_reset.toISOString().split('T')[0] : null;
    const commandsToday = lastReset === today ? (u.commands_today || 0) : 0;
    res.json({ success: true, plan: u.plan || 'free', used: commandsToday, limit: LIMITE_FREE, remaining: Math.max(0, LIMITE_FREE - commandsToday) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================
// DÉMARRAGE
// ============================================
app.listen(PORT, () => {
  console.log('Kenny serveur sur le port ' + PORT);
}); 
