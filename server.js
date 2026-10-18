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
// VARIABLES GLOBALES (fallback)
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
// 🔥 RÉCUPÉRER LES CLÉS D'UN USER DEPUIS env_variables
// ============================================
async function getKeysForUser(firebase_uid) {
  const keys = { ...GLOBAL_KEYS };
  if (!firebase_uid) return keys;
  try {
    const client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return keys; }
    const userId = user.rows[0].id;
    
    // 🔥 Lire depuis env_variables (clé/valeur libres)
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
  } catch (e) {
    console.log('Erreur getKeysForUser:', e.message);
  }
  return keys;
}

// ============================================
// 🔥 VÉRIFIER LE QUOTA
// ============================================
async function verifierQuota(firebase_uid) {
  try {
    const client = await getNeonClient();
    const user = await client.query(
      'SELECT id, plan, commands_today, last_command_reset FROM users WHERE firebase_uid = $1',
      [firebase_uid]
    );
    
    if (user.rows.length === 0) {
      await client.end();
      return { allowed: false, error: 'User non trouvé' };
    }
    
    const u = user.rows[0];
    
    if (u.plan === 'pro' || u.plan === 'premium') {
      await client.end();
      return { allowed: true, remaining: '∞', plan: u.plan };
    }
    
    const today = new Date().toISOString().split('T')[0];
    const lastReset = u.last_command_reset ? u.last_command_reset.toISOString().split('T')[0] : null;
    
    let commandsToday = u.commands_today || 0;
    
    if (lastReset !== today) {
      commandsToday = 0;
      await client.query(
        'UPDATE users SET commands_today = 0, last_command_reset = $1 WHERE id = $2',
        [today, u.id]
      );
    }
    
    const LIMITE_FREE = 50;
    
    if (commandsToday >= LIMITE_FREE) {
      await client.end();
      return { 
        allowed: false, 
        error: `Limite atteinte (${LIMITE_FREE} commandes/jour). Passe au plan Pro pour illimité.`,
        plan: u.plan,
        used: commandsToday,
        limit: LIMITE_FREE
      };
    }
    
    await client.query(
      'UPDATE users SET commands_today = commands_today + 1 WHERE id = $1',
      [u.id]
    );
    
    await client.end();
    return { 
      allowed: true, 
      plan: u.plan,
      used: commandsToday + 1, 
      limit: LIMITE_FREE,
      remaining: LIMITE_FREE - commandsToday - 1
    };
    
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
// ENVIRONNEMENT (env_variables - dynamique)
// ============================================
app.get('/api/env/load/:firebase_uid', async (req, res) => {
  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [req.params.firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return res.json({ success: true, variables: [] }); }
    const result = await client.query(
      'SELECT key, value FROM env_variables WHERE user_id = $1 ORDER BY created_at ASC',
      [user.rows[0].id]
    );
    await client.end();
    const variables = result.rows.map(r => ({
      key: r.key,
      value: r.value ? '••••••••' : ''
    }));
    res.json({ success: true, variables });
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
      if (v.value === '••••••••' && oldMap.has(v.key)) {
        finalValue = oldMap.get(v.key);
      }
      let encrypted = null;
      if (finalValue && finalValue !== '••••••••') {
        encrypted = chiffrer(finalValue);
      } else {
        encrypted = finalValue;
      }
      await client.query(
        'INSERT INTO env_variables (user_id, key, value) VALUES ($1, $2, $3)',
        [userId, v.key.trim(), encrypted]
      );
    }
    await client.end();
    res.json({ success: true, message: 'Variables sauvegardées' });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/env/test', async (req, res) => {
  const { firebase_uid, key, value } = req.body;
  if (!key || !value) return res.status(400).json({ error: 'key et value requis' });
  const results = {};
  const keyUpper = key.toUpperCase();
  try {
    if (keyUpper.includes('GEMINI')) {
      await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${value}`,
        { contents: [{ role: 'user', parts: [{ text: 'test' }] }] },
        { timeout: 10000 }
      );
      results[key] = '✅ OK';
    } else if (keyUpper.includes('NEON')) {
      await axios.get('https://console.neon.tech/api/v2/projects', {
        headers: { 'Authorization': `Bearer ${value}` }, timeout: 10000
      });
      results[key] = '✅ OK';
    } else if (keyUpper.includes('GITHUB')) {
      await axios.get('https://api.github.com/user', {
        headers: { 'Authorization': `token ${value}` }, timeout: 10000
      });
      results[key] = '✅ OK';
    } else if (keyUpper.includes('CLOUDFLARE')) {
      await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', {
        headers: { 'Authorization': `Bearer ${value}` }, timeout: 10000
      });
      results[key] = '✅ OK';
    } else if (keyUpper.includes('RENDER')) {
      await axios.get('https://api.render.com/v1/services?limit=1', {
        headers: { 'Authorization': `Bearer ${value}` }, timeout: 10000
      });
      results[key] = '✅ OK';
    } else {
      results[key] = '⚠️ Type de clé inconnu';
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
    res.json({ 
      success: true, 
      project: project.rows[0], 
      messages: messages.rows, 
      files: files.rows,
      workspace: workspace.rows[0] || null
    });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// 🔥 WORKSPACE AUTO
// ============================================
async function creerRepoGitHub(name, userToken) {
  try {
    const repoName = 'kenny-' + name.toLowerCase().replace(/[^a-z0-9-]/g, '-').substring(0, 40) + '-' + Date.now().toString(36);
    const res = await axios.post(
      'https://api.github.com/user/repos',
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
    const res = await axios.post(
      'https://console.neon.tech/api/v2/projects',
      { project: { name: projectName, region_id: 'aws-eu-central-1', pg_version: 16 } },
      { headers: { 'Authorization': `Bearer ${GLOBAL_KEYS.neon}`, 'Content-Type': 'application/json', 'Accept': 'application/json' } }
    );
    const projectId = res.data.project.id;
    const connRes = await axios.get(
      `https://console.neon.tech/api/v2/projects/${projectId}/connection_uri`,
      { headers: { 'Authorization': `Bearer ${GLOBAL_KEYS.neon}`, 'Accept': 'application/json' } }
    );
    return { success: true, project_id: projectId, connection_uri: connRes.data.uri };
  } catch (e) {
    return { success: false, error: e.response?.data?.message || e.message };
  }
}

async function creerServiceRender(name, repoUrl, userToken, ownerId) {
  if (!userToken || !ownerId) {
    return { success: false, skipped: true, reason: 'Token Render non configuré' };
  }
  try {
    const serviceName = 'kenny-' + name.toLowerCase().replace(/[^a-z0-9-]/g, '-').substring(0, 40) + '-' + Date.now().toString(36);
    const res = await axios.post(
      'https://api.render.com/v1/services',
      {
        type: 'web_service',
        name: serviceName,
        ownerId: ownerId,
        repo: repoUrl,
        branch: 'main',
        autoDeploy: 'yes',
        serviceDetails: {
          env: 'node',
          plan: 'free',
          region: 'frankfurt',
          envSpecificDetails: { buildCommand: 'npm install', startCommand: 'node server.js' }
        }
      },
      { headers: { 'Authorization': `Bearer ${userToken}`, 'Content-Type': 'application/json', 'Accept': 'application/json' } }
    );
    return { success: true, service_id: res.data.service.id, service_url: res.data.service.serviceDetails?.url };
  } catch (e) {
    return { success: false, error: e.response?.data?.message || e.message };
  }
}

async function creerZoneCloudflare(name) {
  try {
    const subdomain = name.toLowerCase().replace(/[^a-z0-9-]/g, '-').substring(0, 40) + '-' + Date.now().toString(36);
    const domain = subdomain + '.kenny.app';
    const zoneRes = await axios.post(
      'https://api.cloudflare.com/client/v4/zones',
      { name: domain, account: { id: GLOBAL_KEYS.cloudflareAccount }, jump_start: true },
      { headers: { 'Authorization': `Bearer ${GLOBAL_KEYS.cloudflare}`, 'Content-Type': 'application/json' } }
    );
    if (!zoneRes.data.success) return { success: false, error: JSON.stringify(zoneRes.data.errors) };
    return { success: true, zone_id: zoneRes.data.result.id, domain };
  } catch (e) {
    return { success: false, error: e.response?.data?.errors?.[0]?.message || e.message };
  }
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

    const ws = await client.query(
      'INSERT INTO workspaces (project_id, user_id, status) VALUES ($1, $2, $3) RETURNING id',
      [project_id, userId, 'creating']
    );
    const workspaceId = ws.rows[0].id;
    await client.end();

    const keys = await getKeysForUser(firebase_uid);

    console.log('📦 Création repo GitHub...');
    const githubResult = await creerRepoGitHub(project_name, keys.github);
    
    console.log('🗄️ Création projet Neon...');
    const neonResult = await creerProjetNeon(project_name);
    
    console.log('🚀 Création service Render...');
    const renderResult = await creerServiceRender(
      project_name,
      githubResult.success ? githubResult.clone_url : '',
      keys.render,
      keys.renderOwner
    );
    
    console.log('🌐 Création zone Cloudflare...');
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
      cloudflareResult.zone_id || null, cloudflareResult.domain || null,
      'ready',
      workspaceId
    ]);
    await client2.end();

    res.json({
      success: true,
      workspace: {
        github: githubResult,
        neon: neonResult,
        render: renderResult,
        cloudflare: cloudflareResult
      }
    });

  } catch (error) {
    if (client) await client.end();
    console.error('Erreur workspace:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/workspaces/:project_id', async (req, res) => {
  let client;
  try {
    client = await getNeonClient();
    const result = await client.query('SELECT * FROM workspaces WHERE project_id = $1', [req.params.project_id]);
    await client.end();
    res.json({ success: true, workspace: result.rows[0] || null });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// CHAT STREAMING
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

      const systemPrompt = `Tu es un développeur senior expert. Ton caractère est comme ChatGPT : poli, professionnel, clair, pédagogique.

COMPORTEMENT :
- Tu PARLES et tu CODES EN MÊME TEMPS.
- Tu annonces chaque étape avec des détails.
- Tu enchaînes SANS ATTENDRE.
- Tu ne te présentes JAMAIS.
- Tu réponds en français.

RÈGLES :

1. AUTO-INSTALLATION (ATTENTION) :
   - AVANT d'installer, VÉRIFIE si déjà présent avec [COMMAND: python3 --version]
   - NE FAIS JAMAIS "apt-get update" (bloqué)
   - La sandbox a DÉJÀ : Python 3.13, Node.js, npm, pip, git
   - Pour installer un paquet Python : [INSTALL: pip install flask]
   - Pour installer un paquet Node : [INSTALL: npm install react]

2. CODE COMPLET :
   \`\`\`html:index.html
   [code]
   \`\`\`
   \`\`\`css:style.css
   [code]
   \`\`\`
   \`\`\`javascript:script.js
   [code]
   \`\`\`

3. IMAGES :
   - JAMAIS d'emojis dans le code
   - [IMAGE: description en anglais]

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
        if (!result.success) {
          memoire.push(`Erreur install ${cmd}: ${result.stderr || result.reason}`);
          installEchouee = true;
        }
      }

      for (const cmd of commands) {
        if (annule) break;
        envoyer('terminal', { command: cmd, type: 'command' });
        const result = await executerSecurise(cmd);
        envoyer('terminal_result', { command: cmd, ...result });
        if (!result.success && result.stderr) memoire.push(`Erreur ${cmd}: ${result.stderr}`);
      }

      if (installEchouee) {
        memoire = memoire.filter(m => !m.includes('Erreur install'));
      }

      if (firebase_uid) {
        try {
          const client = await getNeonClient();
          const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
          if (user.rows.length > 0) {
            await client.query(
              `INSERT INTO conversation_memory (user_id, project_id, role, content) VALUES ($1, $2, 'user', $3)`,
              [user.rows[0].id, project_id, message]
            );
            await client.query(
              `INSERT INTO conversation_memory (user_id, project_id, role, content) VALUES ($1, $2, 'model', $3)`,
              [user.rows[0].id, project_id, reponse]
            );
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
            await client.query(
              'INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
              [project_id, f.nom, f.langage, f.contenu]
            );
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
        envoyer('message', { role: 'ia', content: `J'ai essayé ${MAX_ITERATIONS} fois mais je n'arrive pas à corriger. Peux-tu préciser ce que tu attends ?` });
        envoyer('done', { message: 'Abandon après 3 essais' });
      }
    }

    if (annule) envoyer('cancelled', { message: 'Arrêté' });
    res.write('event: end\ndata: {}\n\n');
    res.end();
  } catch (error) {
    console.error('Erreur stream:', error.message);
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

function extraireBlocs(text) {
  const regex = /```(\w+)(?::([^\n]+))?\n([\s\S]*?)```/g;
  const blocs = [];
  let match;
  while ((match = regex.exec(text)) !== null) {
    const langage = match[1] || 'code';
    const nomFichier = match[2] || null;
    const contenu = match[3].trim();
    let nom = nomFichier;
    if (!nom) {
      const ext = langage === 'html' ? 'html' : langage === 'javascript' || langage === 'js' ? 'js' : langage === 'css' ? 'css' : 'txt';
      nom = `fichier${blocs.length + 1}.${ext}`;
    }
    blocs.push({ langage, nom, contenu });
  }
  return blocs;
}

// ============================================
// TERMINAL (avec quota)
// ============================================
app.post('/api/terminal/exec', async (req, res) => {
  const { commande, firebase_uid } = req.body;
  if (!commande) return res.status(400).json({ error: 'Commande vide' });
  
  // Vérifier le quota
  if (firebase_uid) {
    const quota = await verifierQuota(firebase_uid);
    if (!quota.allowed) {
      return res.json({ 
        blocked: true, 
        reason: quota.error,
        quota_exceeded: true,
        plan: quota.plan,
        used: quota.used,
        limit: quota.limit
      });
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
    const user = await client.query(
      'SELECT plan, commands_today, last_command_reset FROM users WHERE firebase_uid = $1',
      [req.params.firebase_uid]
    );
    await client.end();
    
    if (user.rows.length === 0) {
      return res.json({ success: false, error: 'User non trouvé' });
    }
    
    const u = user.rows[0];
    const LIMITE_FREE = 50;
    const today = new Date().toISOString().split('T')[0];
    const lastReset = u.last_command_reset ? u.last_command_reset.toISOString().split('T')[0] : null;
    const commandsToday = lastReset === today ? (u.commands_today || 0) : 0;
    
    res.json({
      success: true,
      plan: u.plan || 'free',
      used: commandsToday,
      limit: LIMITE_FREE,
      remaining: Math.max(0, LIMITE_FREE - commandsToday)
    });
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
