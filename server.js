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
// CACHE GLOBAL D'IMAGES
// ============================================
const imageCache = new Map();
const CACHE_MAX_SIZE = 500;

async function getNeonClient() {
  const client = new Client({
    connectionString: NEON_CONNECTION_STRING,
    ssl: { rejectUnauthorized: false }
  });
  await client.connect();
  return client;
}

async function initCacheTable() {
  try {
    const client = await getNeonClient();
    await client.query(`
      CREATE TABLE IF NOT EXISTS image_cache (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        prompt_key TEXT UNIQUE NOT NULL,
        prompt_original TEXT NOT NULL,
        image_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        used_count INTEGER DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_cache_prompt ON image_cache(prompt_key);
    `);
    await client.end();
    console.log('✅ Table image_cache prête');
  } catch (e) {
    console.log('⚠️ Init cache:', e.message);
  }
}
initCacheTable();

function normaliserPrompt(prompt) {
  return prompt.toLowerCase().trim().replace(/[^\w\s]/g, '').replace(/\s+/g, ' ')
    .replace(/\b(une|un|le|la|les|des|de|du|image|picture|photo|illustration|logo|icon|emoji)\b/g, '').trim();
}

async function chercherDansCache(prompt) {
  const key = normaliserPrompt(prompt);
  if (imageCache.has(key)) {
    try {
      const client = await getNeonClient();
      await client.query('UPDATE image_cache SET used_count = used_count + 1 WHERE prompt_key = $1', [key]);
      await client.end();
    } catch (e) {}
    return imageCache.get(key);
  }
  try {
    const client = await getNeonClient();
    const result = await client.query('SELECT image_url, prompt_original FROM image_cache WHERE prompt_key = $1', [key]);
    if (result.rows.length > 0) {
      const cached = { image_url: result.rows[0].image_url, prompt_original: result.rows[0].prompt_original };
      imageCache.set(key, cached);
      await client.query('UPDATE image_cache SET used_count = used_count + 1 WHERE prompt_key = $1', [key]);
      await client.end();
      return cached;
    }
    await client.end();
  } catch (e) {}
  return null;
}

async function sauvegarderDansCache(prompt, imageUrl) {
  const key = normaliserPrompt(prompt);
  const cached = { image_url: imageUrl, prompt_original: prompt };
  if (imageCache.size >= CACHE_MAX_SIZE) imageCache.delete(imageCache.keys().next().value);
  imageCache.set(key, cached);
  try {
    const client = await getNeonClient();
    await client.query(
      `INSERT INTO image_cache (prompt_key, prompt_original, image_url) VALUES ($1, $2, $3)
       ON CONFLICT (prompt_key) DO UPDATE SET image_url = $3`,
      [key, prompt, imageUrl]
    );
    await client.end();
  } catch (e) {}
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
    gemini: GEMINI_API_KEY ? '✅' : '❌',
    cache_size: imageCache.size
  });
});

// ============================================
// GÉNÉRATION D'IMAGE 3D
// ============================================
async function imageAgent(prompt) {
  const cached = await chercherDansCache(prompt);
  if (cached) return { success: true, image_url: cached.image_url, prompt: cached.prompt_original, from_cache: true };

  try {
    const enrichedPrompt = `3D render, ${prompt}, isolated on pure white background, transparent background, PNG cutout style, no shadow, high quality 3D icon, octane render, cinematic lighting, detailed, clean edges, centered, no text, no emoji`;
    const response = await axios.post(
      `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/ai/run/@cf/bytedance/stable-diffusion-xl-lightning`,
      { prompt: enrichedPrompt, num_steps: 4, width: 768, height: 768 },
      { headers: { 'Authorization': `Bearer ${CLOUDFLARE_AI_TOKEN}`, 'Content-Type': 'application/json' }, responseType: 'arraybuffer', timeout: 30000 }
    );
    const base64 = Buffer.from(response.data).toString('base64');
    const imageUrl = `data:image/png;base64,${base64}`;
    await sauvegarderDansCache(prompt, imageUrl);
    return { success: true, image_url: imageUrl, prompt: prompt, from_cache: false };
  } catch (error) {
    let errorMsg = error.message;
    if (error.response?.data) { try { errorMsg = new TextDecoder().decode(error.response.data); } catch (e) {} }
    return { success: false, error: errorMsg };
  }
}

app.post('/api/image', async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'prompt requis' });
  const result = await imageAgent(prompt);
  if (!result.success) return res.status(500).json({ error: result.error });
  res.json(result);
});

// ============================================
// SYNC USER
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
      await client.query('UPDATE users SET last_login = NOW(), email = $1, photo_url = $2 WHERE id = $3', [email, photo_url || null, userId]);
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
// PROJETS
// ============================================
app.post('/api/projects/create', async (req, res) => {
  const { firebase_uid, name } = req.body;
  if (!firebase_uid || !name) return res.status(400).json({ error: 'firebase_uid et name requis' });
  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) { await client.end(); return res.status(404).json({ error: 'Utilisateur non trouvé' }); }
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
    const messages = await client.query(
      'SELECT role, content, created_at FROM conversation_memory WHERE project_id = $1 ORDER BY created_at ASC',
      [req.params.project_id]
    );
    const files = await client.query(
      'SELECT * FROM files WHERE project_id = $1 ORDER BY created_at ASC',
      [req.params.project_id]
    );
    await client.end();
    res.json({ success: true, project: project.rows[0], messages: messages.rows, files: files.rows });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// FICHIERS
// ============================================
app.post('/api/files/save', async (req, res) => {
  const { project_id, files } = req.body;
  if (!project_id || !files || !Array.isArray(files)) {
    return res.status(400).json({ error: 'project_id et files (array) requis' });
  }
  let client;
  try {
    client = await getNeonClient();
    await client.query('DELETE FROM files WHERE project_id = $1', [project_id]);
    for (const file of files) {
      await client.query(
        'INSERT INTO files (project_id, name, language, content) VALUES ($1, $2, $3, $4)',
        [project_id, file.nom || file.name, file.langage || file.language, file.contenu || file.content]
      );
    }
    await client.end();
    console.log(`💾 ${files.length} fichiers sauvés pour projet ${project_id}`);
    res.json({ success: true, count: files.length });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// CHAT IA
// ============================================
app.post('/api/chat', async (req, res) => {
  const { message, history, firebase_uid, project_id } = req.body;
  if (!message) return res.status(400).json({ error: 'Message requis' });
  if (!GEMINI_API_KEY) return res.json({ response: '⚠️ Clé API manquante.' });

  if (!project_id) {
    return res.json({
      response: '⚠️ Tu dois d\'abord créer un projet avant de commencer. Clique sur "Nouveau projet" en bas.',
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
1. Ne te présente JAMAIS.
2. Réponds TOUJOURS en français.
3. Le chat sert UNIQUEMENT à la conversation. Réponds avec du texte simple.
4. Dans le CODE généré, n'utilise JAMAIS d'emojis. À la place : [IMAGE: description en anglais].

CODE :
- Génère des applications COMPLÈTES avec HTML, CSS, et JS.
- Format OBLIGATOIRE (ne change jamais les noms) :
\`\`\`html:index.html
[code HTML complet]
\`\`\`
\`\`\`css:style.css
[code CSS complet]
\`\`\`
\`\`\`javascript:script.js
[code JS complet]
\`\`\`

IMAGES DANS LE CODE :
- Emoji 🐺 → [IMAGE: 3D wolf head icon, transparent background]
- Emoji 🍔 → [IMAGE: 3D burger icon, transparent background]`
          }]
        },
        contents: contents,
        generationConfig: { temperature: 0.8, maxOutputTokens: 8000 }
      },
      { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
    );

    let reponse = response.data.candidates[0].content.parts[0].text;

    // Sauvegarder la conversation
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
      } catch (e) { console.log('Erreur save conv:', e.message); }
    }

    // Extraire les fichiers
    const blocks = extraireBlocs(reponse);

    // Traiter les images
    const imagesTrouvees = [];
    for (const file of blocks) {
      const matches = [...file.contenu.matchAll(/\[IMAGE:\s*(.+?)\]/gi)];
      for (const m of matches) imagesTrouvees.push(m[1].trim());
    }

    if (imagesTrouvees.length > 0) {
      const imageMap = new Map();
      for (const promptImg of imagesTrouvees) {
        const result = await imageAgent(promptImg);
        if (result.success) imageMap.set(promptImg, result.image_url);
      }
      for (const file of blocks) {
        file.contenu = file.contenu.replace(/\[IMAGE:\s*(.+?)\]/gi, (match, p) => {
          const url = imageMap.get(p.trim());
          return url ? url : match;
        });
      }
    }

    // 🔥 SAUVEGARDER LES FICHIERS (fusion intelligente)
    if (blocks.length > 0 && project_id) {
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
        console.log(`💾 ${fileMap.size} fichiers sauvés`);
      } catch (e) { console.log('Erreur save fichiers:', e.message); }
    }

    const texteChat = reponse.replace(/```[\s\S]*?```/g, '').trim();

    res.json({
      response: texteChat,
      files_count: blocks.length,
      images_generated: imagesTrouvees.length
    });
  } catch (error) {
    console.error('Erreur Gemini:', error.response?.data || error.message);
    res.status(500).json({ error: 'Erreur IA', response: `Erreur : ${error.response?.data?.error?.message || error.message}` });
  }
});

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
// TERMINAL
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
