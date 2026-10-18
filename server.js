const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { Client } = require('pg');

const antivirus = require('./agents/antivirus');
const sandbox = require('./agents/sandbox');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ============================================
// VARIABLES D'ENVIRONNEMENT
// ============================================
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const RENDER_TOKEN = process.env.RENDER_TOKEN;
const CLOUDFLARE_TOKEN = process.env.CLOUDFLARE_TOKEN;
const CLOUDFLARE_AI_TOKEN = process.env.CLOUDFLARE_AI_TOKEN;
const RENDER_OWNER_ID = process.env.RENDER_OWNER_ID;
const CLOUDFLARE_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
const NEON_API_KEY = process.env.NEON_API_KEY;
const NEON_CONNECTION_STRING = process.env.NEON_CONNECTION_STRING;

// ============================================
// NEON CLIENT
// ============================================
async function getNeonClient() {
  const client = new Client({
    connectionString: NEON_CONNECTION_STRING,
    ssl: { rejectUnauthorized: false }
  });
  await client.connect();
  return client;
}

// ============================================
// ROUTE DE TEST
// ============================================
app.get('/', (req, res) => {
  res.json({
    message: 'Backend Kenny opérationnel !',
    neon: NEON_API_KEY ? '✅' : '❌',
    github: GITHUB_TOKEN ? '✅' : '❌',
    render: RENDER_TOKEN ? '✅' : '❌',
    cloudflare: CLOUDFLARE_TOKEN ? '✅' : '❌',
    gemini: GEMINI_API_KEY ? '✅' : '❌'
  });
});

app.get('/api/neon/test', async (req, res) => {
  const resultats = { api_key: null, connection_string: null };
  try {
    const response = await axios.get('https://console.neon.tech/api/v2/projects', {
      headers: { 'Authorization': `Bearer ${NEON_API_KEY}`, 'Accept': 'application/json' }
    });
    resultats.api_key = { success: true, message: `✅ API Key valide (${response.data.projects.length} projets)` };
  } catch (error) {
    resultats.api_key = { success: false, message: `❌ ${error.response?.data?.message || error.message}` };
  }
  try {
    const client = await getNeonClient();
    const result = await client.query('SELECT NOW() as now, version() as version');
    await client.end();
    resultats.connection_string = {
      success: true,
      message: '✅ Connexion valide',
      version: result.rows[0].version.split(' ').slice(0, 2).join(' ')
    };
  } catch (error) {
    resultats.connection_string = { success: false, message: `❌ ${error.message}` };
  }
  resultats.success = resultats.api_key.success && resultats.connection_string.success;
  res.json(resultats);
});

// ============================================
// SYNC USER (Firebase → Neon)
// ============================================
app.post('/api/user/sync', async (req, res) => {
  const { firebase_uid, email, photo_url } = req.body;
  if (!firebase_uid || !email) return res.status(400).json({ error: 'firebase_uid et email requis' });

  let client;
  try {
    client = await getNeonClient();
    const existing = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    let userId;
    if (existing.rows.length > 0) {
      userId = existing.rows[0].id;
      await client.query(
        'UPDATE users SET last_login = NOW(), email = $1, photo_url = $2 WHERE id = $3',
        [email, photo_url || null, userId]
      );
    } else {
      const inserted = await client.query(
        `INSERT INTO users (firebase_uid, email, photo_url) VALUES ($1, $2, $3) RETURNING id`,
        [firebase_uid, email, photo_url || null]
      );
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
// GET USER PROFILE
// ============================================
app.get('/api/user/:firebase_uid', async (req, res) => {
  let client;
  try {
    client = await getNeonClient();
    const result = await client.query('SELECT * FROM users WHERE firebase_uid = $1', [req.params.firebase_uid]);
    await client.end();
    if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// PROJETS : CRÉER
// ============================================
app.post('/api/projects/create', async (req, res) => {
  const { firebase_uid, name } = req.body;
  if (!firebase_uid || !name) return res.status(400).json({ error: 'firebase_uid et name requis' });

  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) {
      await client.end();
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    const project = await client.query(
      'INSERT INTO projects (user_id, name) VALUES ($1, $2) RETURNING *',
      [user.rows[0].id, name]
    );
    await client.end();
    res.json({ success: true, project: project.rows[0] });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// PROJETS : LISTER
// ============================================
app.get('/api/projects/list/:firebase_uid', async (req, res) => {
  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [req.params.firebase_uid]);
    if (user.rows.length === 0) {
      await client.end();
      return res.json({ success: true, projects: [] });
    }
    const projects = await client.query(
      'SELECT * FROM projects WHERE user_id = $1 ORDER BY created_at DESC',
      [user.rows[0].id]
    );
    await client.end();
    res.json({ success: true, projects: projects.rows });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// PROJETS : DÉTAILS + MESSAGES + FICHIERS
// ============================================
app.get('/api/projects/:project_id/details', async (req, res) => {
  let client;
  try {
    client = await getNeonClient();
    const project = await client.query('SELECT * FROM projects WHERE id = $1', [req.params.project_id]);
    if (project.rows.length === 0) {
      await client.end();
      return res.status(404).json({ error: 'Projet non trouvé' });
    }
    const messages = await client.query(
      'SELECT role, content, created_at FROM conversation_memory WHERE project_id = $1 ORDER BY created_at ASC',
      [req.params.project_id]
    );
    const files = await client.query(
      'SELECT * FROM files WHERE project_id = $1 ORDER BY created_at ASC',
      [req.params.project_id]
    );
    await client.end();
    res.json({
      success: true,
      project: project.rows[0],
      messages: messages.rows,
      files: files.rows
    });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// FICHIERS : SAUVEGARDER
// ============================================
app.post('/api/files/save', async (req, res) => {
  const { project_id, files } = req.body;
  if (!project_id || !files || !Array.isArray(files)) {
    return res.status(400).json({ error: 'project_id et files (array) requis' });
  }

  let client;
  try {
    client = await getNeonClient();
    // Supprimer les anciens fichiers du projet pour les remplacer
    await client.query('DELETE FROM files WHERE project_id = $1', [project_id]);
    
    for (const file of files) {
      await client.query(
        'INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
        [project_id, file.nom, file.langage, file.contenu]
      );
    }
    await client.end();
    res.json({ success: true, count: files.length });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// AGENT GITHUB
// ============================================
async function githubAgent(projectName, files) {
  try {
    const repoName = projectName.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase();
    const repoRes = await axios.post(
      'https://api.github.com/user/repos',
      { name: repoName, private: true, auto_init: false, description: 'App générée par Kenny' },
      { headers: { 'Authorization': `token ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github.v3+json' } }
    );
    const repo = repoRes.data;
    for (const file of files) {
      try {
        await axios.put(
          `https://api.github.com/repos/${repo.full_name}/contents/${file.nom}`,
          { message: `Ajout ${file.nom}`, content: Buffer.from(file.contenu).toString('base64') },
          { headers: { 'Authorization': `token ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github.v3+json' } }
        );
      } catch (e) { console.log('Fichier déjà existant ou erreur:', file.nom); }
    }
    return { success: true, repo_url: repo.html_url, repo_full_name: repo.full_name, clone_url: repo.clone_url };
  } catch (error) {
    return { success: false, error: error.response?.data?.message || error.message };
  }
}

// ============================================
// AGENT IMAGE
// ============================================
async function imageAgent(prompt) {
  try {
    const response = await axios.post(
      `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/ai/run/@cf/black-forest-labs/flux-1-schnell`,
      { prompt: prompt, steps: 4 },
      { headers: { 'Authorization': `Bearer ${CLOUDFLARE_AI_TOKEN}`, 'Content-Type': 'application/json' }, responseType: 'arraybuffer', timeout: 60000 }
    );
    const base64 = Buffer.from(response.data).toString('base64');
    return { success: true, image_url: `data:image/png;base64,${base64}`, prompt: prompt };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// ============================================
// ROUTE IMAGE
// ============================================
app.post('/api/image', async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'prompt requis' });
  const result = await imageAgent(prompt);
  if (!result.success) return res.status(500).json({ error: result.error });
  res.json(result);
});

// ============================================
// CHAT IA (avec sauvegarde Neon + GitHub)
// ============================================
app.post('/api/chat', async (req, res) => {
  const { message, history, firebase_uid, project_id } = req.body;
  if (!message) return res.status(400).json({ error: 'Message requis' });
  if (!GEMINI_API_KEY) return res.json({ response: '⚠️ Clé API manquante.', simulated: true });

  if (!project_id) {
    return res.json({ 
      response: '⚠️ Tu dois d\'abord créer un projet avant de commencer. Clique sur "Nouveau projet" en bas.',
      image_prompt: null,
      need_project: true
    });
  }

  try {
    const contents = [];
    if (history && Array.isArray(history)) {
      history.forEach(msg => {
        contents.push({ role: msg.role === 'user' ? 'user' : 'model', parts: [{ text: msg.content }] });
      });
    }
    contents.push({ role: 'user', parts: [{ text: message }] });

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${GEMINI_API_KEY}`,
      {
        systemInstruction: {
          parts: [{
            text: `Tu es un développeur senior expert en création d'applications web.

RÈGLES ABSOLUES :
- N'utilise JAMAIS d'emojis dans le code que tu génères.
- À la place, écris TOUJOURS : [IMAGE: description précise]
- Ne te présente JAMAIS.
- Réponds en français.

CODE :
- Génère des applications COMPLÈTES avec HTML, CSS, et JS.
- Format de sortie :
\`\`\`html:index.html
[le code HTML complet]
\`\`\`
\`\`\`css:style.css
[le code CSS complet]
\`\`\`
\`\`\`javascript:script.js
[le code JS complet]
\`\`\`

IMAGES :
- Pour chaque visuel nécessaire, ajoute : [IMAGE: description en anglais]`
          }]
        },
        contents: contents,
        generationConfig: { temperature: 0.8, maxOutputTokens: 8000 }
      },
      { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
    );

    let reponse = response.data.candidates[0].content.parts[0].text;
    let imagePrompt = null;
    const imageMatch = reponse.match(/\[IMAGE:\s*(.+?)\]/i);
    if (imageMatch) {
      imagePrompt = imageMatch[1].trim();
      reponse = reponse.replace(/\[IMAGE:\s*.+?\]/gi, '').trim();
    }

    // Sauvegarder la conversation dans Neon
    if (firebase_uid && project_id) {
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
      } catch (e) { console.log('Mémoire non sauvée:', e.message); }
    }

    // Extraire et sauvegarder les fichiers si générés
    const blocks = extraireBlocs(reponse);
    if (blocks.length > 0 && project_id) {
      try {
        const client = await getNeonClient();
        await client.query('DELETE FROM files WHERE project_id = $1', [project_id]);
        for (const file of blocks) {
          await client.query(
            'INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
            [project_id, file.nom, file.langage, file.contenu]
          );
        }
        await client.end();
        console.log(`✅ ${blocks.length} fichiers sauvegardés dans Neon`);
      } catch (e) { console.log('Fichiers non sauvés:', e.message); }
    }

    res.json({ response: reponse, image_prompt: imagePrompt, files_count: blocks.length });
  } catch (error) {
    console.error('Erreur Gemini:', error.response?.data || error.message);
    res.status(500).json({ error: 'Erreur IA', response: `Erreur : ${error.response?.data?.error?.message || error.message}` });
  }
});

// ============================================
// EXTRAIRE BLOCS DE CODE
// ============================================
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
      const ext = langage === 'html' ? 'html' :
                  langage === 'javascript' || langage === 'js' ? 'js' :
                  langage === 'css' ? 'css' :
                  langage === 'json' ? 'json' : 'txt';
      nom = `fichier${blocs.length + 1}.${ext}`;
    }
    blocs.push({ langage, nom, contenu });
  }
  return blocs;
}

// ============================================
// ROUTES TERMINAL
// ============================================
app.post('/api/terminal/exec', async (req, res) => {
  const { commande, mode = 'normal' } = req.body;
  if (!commande) return res.status(400).json({ error: 'Commande vide' });
  const cmd = antivirus.nettoyerCommande(commande);
  const verif = antivirus.verifierCommande(cmd, mode);
  if (!verif.allowed) return res.json({ blocked: true, reason: verif.reason, level: verif.level, commande: cmd });
  if (verif.needsConfirmation) return res.json({ needsConfirmation: true, reason: verif.reason, commande: cmd });
  const result = await sandbox.executerCommande(cmd);
  return res.json({ blocked: false, commande: cmd, ...result });
});

app.post('/api/terminal/close', async (req, res) => {
  await sandbox.fermerSandbox();
  res.json({ success: true, message: 'Sandbox fermée' });
});

app.get('/api/terminal/status', (req, res) => {
  res.json({ active: !!sandbox.creerSandbox, message: 'Agent antivirus : ACTIF' });
});

// ============================================
// DÉMARRAGE
// ============================================
app.listen(PORT, () => {
  console.log('Serveur sur le port ' + PORT);
});
