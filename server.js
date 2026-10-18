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

async function getKeysForUser(firebase_uid) {
  const keys = { ...GLOBAL_KEYS };
  if (!firebase_uid) return keys;
  try {
    const client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return keys; }
    const userId = user.rows[0].id;
    const userKeys = await client.query('SELECT * FROM user_api_keys WHERE user_id = $1', [userId]);
    await client.end();
    if (userKeys.rows.length > 0) {
      const uk = userKeys.rows[0];
      const decrypted = {
        gemini: dechiffrer(uk.gemini_key),
        neon: dechiffrer(uk.neon_key),
        github: dechiffrer(uk.github_token),
        cloudflare: dechiffrer(uk.cloudflare_token),
        cloudflareAI: dechiffrer(uk.cloudflare_ai_token),
        render: dechiffrer(uk.render_token),
        renderOwner: uk.render_owner_id,
        cloudflareAccount: uk.cloudflare_account_id
      };
      Object.keys(decrypted).forEach(k => { if (decrypted[k]) keys[k] = decrypted[k]; });
    }
  } catch (e) {}
  return keys;
}

app.get('/', (req, res) => {
  res.json({ message: 'Kenny OK', gemini: GLOBAL_KEYS.gemini ? '✅' : '❌' });
});

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
    if (user.rows.length === 0) { await client.end(); return res.json({ success: true, keys: {} }); }
    const result = await client.query('SELECT * FROM user_api_keys WHERE user_id = $1', [user.rows[0].id]);
    await client.end();
    if (result.rows.length === 0) return res.json({ success: true, keys: {} });
    const uk = result.rows[0];
    res.json({
      success: true,
      keys: {
        gemini: uk.gemini_key ? '••••••••' : '',
        neon: uk.neon_key ? '••••••••' : '',
        github: uk.github_token ? '••••••••' : '',
        cloudflare: uk.cloudflare_token ? '••••••••' : '',
        cloudflareAI: uk.cloudflare_ai_token ? '••••••••' : '',
        render: uk.render_token ? '••••••••' : '',
        renderOwner: uk.render_owner_id || '',
        cloudflareAccount: uk.cloudflare_account_id || ''
      }
    });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/env/save', async (req, res) => {
  const { firebase_uid, keys } = req.body;
  if (!firebase_uid || !keys) return res.status(400).json({ error: 'Champs requis' });
  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return res.status(404).json({ error: 'User non trouvé' }); }
    const userId = user.rows[0].id;
    const existing = await client.query('SELECT * FROM user_api_keys WHERE user_id = $1', [userId]);
    const current = existing.rows.length > 0 ? existing.rows[0] : {};
    const values = {
      gemini_key: keys.gemini && keys.gemini !== '••••••••' ? chiffrer(keys.gemini) : current.gemini_key,
      neon_key: keys.neon && keys.neon !== '••••••••' ? chiffrer(keys.neon) : current.neon_key,
      github_token: keys.github && keys.github !== '••••••••' ? chiffrer(keys.github) : current.github_token,
      cloudflare_token: keys.cloudflare && keys.cloudflare !== '••••••••' ? chiffrer(keys.cloudflare) : current.cloudflare_token,
      cloudflare_ai_token: keys.cloudflareAI && keys.cloudflareAI !== '••••••••' ? chiffrer(keys.cloudflareAI) : current.cloudflare_ai_token,
      render_token: keys.render && keys.render !== '••••••••' ? chiffrer(keys.render) : current.render_token,
      render_owner_id: keys.renderOwner || current.render_owner_id,
      cloudflare_account_id: keys.cloudflareAccount || current.cloudflare_account_id
    };
    if (existing.rows.length > 0) {
      await client.query(`
        UPDATE user_api_keys SET
          gemini_key = $1, neon_key = $2, github_token = $3,
          cloudflare_token = $4, cloudflare_ai_token = $5,
          render_token = $6, render_owner_id = $7, cloudflare_account_id = $8,
          updated_at = NOW()
        WHERE user_id = $9
      `, [values.gemini_key, values.neon_key, values.github_token,
          values.cloudflare_token, values.cloudflare_ai_token,
          values.render_token, values.render_owner_id, values.cloudflare_account_id, userId]);
    } else {
      await client.query(`
        INSERT INTO user_api_keys
        (user_id, gemini_key, neon_key, github_token, cloudflare_token, cloudflare_ai_token, render_token, render_owner_id, cloudflare_account_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [userId, values.gemini_key, values.neon_key, values.github_token,
          values.cloudflare_token, values.cloudflare_ai_token,
          values.render_token, values.render_owner_id, values.cloudflare_account_id]);
    }
    await client.end();
    res.json({ success: true, message: 'Clés sauvegardées' });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/env/test', async (req, res) => {
  const { firebase_uid } = req.body;
  const keys = await getKeysForUser(firebase_uid);
  const results = {};
  try {
    await axios.post(`https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${keys.gemini}`,
      { contents: [{ role: 'user', parts: [{ text: 'test' }] }] }, { timeout: 10000 });
    results.gemini = '✅ OK';
  } catch (e) { results.gemini = '❌ ' + (e.response?.status || e.message); }
  try {
    await axios.get('https://console.neon.tech/api/v2/projects', { headers: { 'Authorization': `Bearer ${keys.neon}` }, timeout: 10000 });
    results.neon = '✅ OK';
  } catch (e) { results.neon = '❌ ' + (e.response?.status || e.message); }
  try {
    await axios.get('https://api.github.com/user', { headers: { 'Authorization': `token ${keys.github}` }, timeout: 10000 });
    results.github = '✅ OK';
  } catch (e) { results.github = '❌ ' + (e.response?.status || e.message); }
  try {
    await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', { headers: { 'Authorization': `Bearer ${keys.cloudflare}` }, timeout: 10000 });
    results.cloudflare = '✅ OK';
  } catch (e) { results.cloudflare = '❌ ' + (e.response?.status || e.message); }
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
    await client.end();
    res.json({ success: true, project: project.rows[0], messages: messages.rows, files: files.rows });
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
   - AVANT d'installer, VÉRIFIE si déjà présent avec [COMMAND: python3 --version] ou [COMMAND: node --version]
   - NE FAIS JAMAIS "apt-get update" (bloqué dans la sandbox E2B)
   - NE FAIS JAMAIS "apt-get install python3" (déjà installé par défaut)
   - La sandbox E2B a DÉJÀ : Python 3.13, Node.js, npm, pip, git, curl, wget
   - Si l'user demande Python/Node : PAS BESOIN d'installer, c'est déjà là.
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

4. TESTS :
   - [COMMAND: node script.js] pour tester
   - Si erreur → corriger.

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

      // Anti-répétition
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

      // 🔥 Si installation échouée, on continue quand même (peut-être déjà installé)
      if (installEchouee) {
        console.log('⚠️ Installation échouée mais on continue');
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

app.post('/api/terminal/exec', async (req, res) => {
  const { commande } = req.body;
  if (!commande) return res.status(400).json({ error: 'Commande vide' });
  const result = await executerSecurise(commande);
  return res.json({ ...result, commande });
});

app.post('/api/terminal/close', async (req, res) => {
  await sandbox.fermerSandbox();
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log('Kenny serveur sur le port ' + PORT);
});
