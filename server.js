const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { Client } = require('pg'); // PostgreSQL (Neon)

// IMPORTS POUR LE TERMINAL
const antivirus = require('./agents/antivirus');
const sandbox = require('./agents/sandbox');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

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

// NEON
const NEON_API_KEY = process.env.NEON_API_KEY;
const NEON_CONNECTION_STRING = process.env.NEON_CONNECTION_STRING;

// ============================================
// FONCTION : Connexion à Neon
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
    neon: NEON_API_KEY ? '✅ Configuré' : '❌ Manquant',
    github: GITHUB_TOKEN ? '✅' : '❌',
    render: RENDER_TOKEN ? '✅' : '❌',
    cloudflare: CLOUDFLARE_TOKEN ? '✅' : '❌',
    gemini: GEMINI_API_KEY ? '✅' : '❌'
  });
});

// ============================================
// TEST NEON (garde l'ancienne route)
// ============================================
app.get('/api/neon/test', async (req, res) => {
  const resultats = { api_key: null, connection_string: null };

  try {
    const response = await axios.get('https://console.neon.tech/api/v2/projects', {
      headers: { 'Authorization': `Bearer ${NEON_API_KEY}`, 'Accept': 'application/json' }
    });
    resultats.api_key = {
      success: true,
      message: `✅ API Key valide (${response.data.projects.length} projets)`,
      projects: response.data.projects.map(p => ({ id: p.id, name: p.name }))
    };
  } catch (error) {
    resultats.api_key = { success: false, message: `❌ ${error.response?.data?.message || error.message}` };
  }

  try {
    const client = await getNeonClient();
    const result = await client.query('SELECT NOW() as now, version() as version');
    await client.end();
    resultats.connection_string = {
      success: true,
      message: '✅ Connexion PostgreSQL valide',
      now: result.rows[0].now,
      version: result.rows[0].version.split(' ').slice(0, 2).join(' ')
    };
  } catch (error) {
    resultats.connection_string = { success: false, message: `❌ ${error.message}` };
  }

  resultats.success = resultats.api_key.success && resultats.connection_string.success;
  resultats.message = resultats.success ? '🎉 Neon est prêt !' : '⚠️ Problèmes';
  res.json(resultats);
});

// ============================================
// NOUVELLE ROUTE : SYNC USER (Firebase → Neon)
// Appelée après inscription/connexion Firebase
// ============================================
app.post('/api/user/sync', async (req, res) => {
  const { firebase_uid, email, photo_url } = req.body;

  if (!firebase_uid || !email) {
    return res.status(400).json({ error: 'firebase_uid et email requis' });
  }

  let client;
  try {
    client = await getNeonClient();

    const existing = await client.query(
      'SELECT id FROM users WHERE firebase_uid = $1',
      [firebase_uid]
    );

    let userId;
    if (existing.rows.length > 0) {
      userId = existing.rows[0].id;
      await client.query(
        'UPDATE users SET last_login = NOW(), email = $1, photo_url = $2 WHERE id = $3',
        [email, photo_url || null, userId]
      );
    } else {
      const inserted = await client.query(
        `INSERT INTO users (firebase_uid, email, photo_url) 
         VALUES ($1, $2, $3) RETURNING id`,
        [firebase_uid, email, photo_url || null]
      );
      userId = inserted.rows[0].id;
      console.log(`✅ Nouvel utilisateur créé dans Neon : ${email}`);
    }

    await client.end();
    res.json({ success: true, user_id: userId, message: '✅ Synchronisé avec Neon' });

  } catch (error) {
    if (client) await client.end();
    console.error('Erreur sync user:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// NOUVELLE ROUTE : GET USER PROFILE
// ============================================
app.get('/api/user/:firebase_uid', async (req, res) => {
  const { firebase_uid } = req.params;
  let client;
  try {
    client = await getNeonClient();
    const result = await client.query(
      'SELECT * FROM users WHERE firebase_uid = $1',
      [firebase_uid]
    );
    await client.end();
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// NOUVELLE ROUTE : MÉMOIRE CONVERSATION
// ============================================
app.post('/api/memory/save', async (req, res) => {
  const { firebase_uid, project_id, role, content } = req.body;

  if (!firebase_uid || !role || !content) {
    return res.status(400).json({ error: 'firebase_uid, role et content requis' });
  }

  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) {
      await client.end();
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    await client.query(
      `INSERT INTO conversation_memory (user_id, project_id, role, content) 
       VALUES ($1, $2, $3, $4)`,
      [user.rows[0].id, project_id || null, role, content]
    );
    await client.end();
    res.json({ success: true });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/memory/:firebase_uid', async (req, res) => {
  const { firebase_uid } = req.params;
  const { project_id, limit = 50 } = req.query;
  let client;
  try {
    client = await getNeonClient();
    const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
    if (user.rows.length === 0) {
      await client.end();
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    let query = 'SELECT * FROM conversation_memory WHERE user_id = $1';
    const params = [user.rows[0].id];
    if (project_id) {
      query += ' AND project_id = $2';
      params.push(project_id);
    }
    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1}`;
    params.push(parseInt(limit));
    const result = await client.query(query, params);
    await client.end();
    res.json({ success: true, messages: result.rows.reverse() });
  } catch (error) {
    if (client) await client.end();
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// AGENT 1 : GITHUB
// ============================================
async function githubAgent(projectName, files) {
  console.log('🤖 GitHub Agent : début');
  try {
    const repoRes = await axios.post(
      'https://api.github.com/user/repos',
      { name: projectName, private: true, auto_init: false, description: 'App générée par Kenny' },
      { headers: { 'Authorization': `token ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github.v3+json' } }
    );
    const repo = repoRes.data;
    console.log('✅ Repo créé :', repo.full_name);
    for (const file of files) {
      await axios.put(
        `https://api.github.com/repos/${repo.full_name}/contents/${file.nom}`,
        { message: `Ajout ${file.nom}`, content: Buffer.from(file.contenu).toString('base64') },
        { headers: { 'Authorization': `token ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github.v3+json' } }
      );
      console.log('✅ Fichier push :', file.nom);
    }
    return { success: true, repo_url: repo.html_url, repo_full_name: repo.full_name, clone_url: repo.clone_url };
  } catch (error) {
    console.error('❌ GitHub Agent:', error.response?.data || error.message);
    return { success: false, error: error.response?.data?.message || error.message };
  }
}

// ============================================
// AGENT 2 : NEON (remplace Supabase)
// ============================================
async function neonAgent(projectName, firebaseUid) {
  console.log('🤖 Neon Agent : début');
  try {
    // Crée un nouveau projet Neon pour l'user
    const projectRes = await axios.post(
      'https://console.neon.tech/api/v2/projects',
      {
        project: {
          name: `kenny-${projectName}-${firebaseUid.slice(0, 8)}`,
          region_id: 'aws-eu-central-1',
          pg_version: 16
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${NEON_API_KEY}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      }
    );

    const project = projectRes.data.project;
    console.log('✅ Projet Neon créé :', project.id);

    // Récupérer les connection details
    const connRes = await axios.get(
      `https://console.neon.tech/api/v2/projects/${project.id}/connection_uri`,
      {
        headers: { 'Authorization': `Bearer ${NEON_API_KEY}`, 'Accept': 'application/json' }
      }
    );

    return {
      success: true,
      project_id: project.id,
      connection_uri: connRes.data.uri,
      project_url: `https://console.neon.tech/app/projects/${project.id}`
    };
  } catch (error) {
    console.error('❌ Neon Agent:', error.response?.data || error.message);
    return { success: false, error: error.response?.data?.message || error.message };
  }
}

// ============================================
// AGENT 3 : RENDER
// ============================================
async function renderAgent(projectName, repoUrl) {
  console.log('🤖 Render Agent : début');
  try {
    const serviceRes = await axios.post(
      'https://api.render.com/v1/services',
      {
        type: 'web_service',
        name: projectName,
        ownerId: RENDER_OWNER_ID,
        repo: repoUrl,
        branch: 'main',
        autoDeploy: 'yes',
        serviceDetails: {
          env: 'node',
          plan: 'free',
          region: 'frankfurt',
          envSpecificDetails: { buildCommand: 'npm install', startCommand: 'npm start' }
        }
      },
      { headers: { 'Authorization': `Bearer ${RENDER_TOKEN}`, 'Content-Type': 'application/json' } }
    );
    const service = serviceRes.data;
    console.log('✅ Service Render créé :', service.id);
    return { success: true, service_id: service.id, service_url: service.serviceDetails?.url };
  } catch (error) {
    console.error('❌ Render Agent:', error.response?.data || error.message);
    return { success: false, error: error.response?.data?.message || error.message };
  }
}

// ============================================
// AGENT 4 : CLOUDFLARE
// ============================================
async function cloudflareAgent(domain, targetUrl) {
  console.log('🤖 Cloudflare Agent : début');
  try {
    const zoneRes = await axios.post(
      'https://api.cloudflare.com/client/v4/zones',
      { name: domain, account: { id: CLOUDFLARE_ACCOUNT_ID }, jump_start: true },
      { headers: { 'Authorization': `Bearer ${CLOUDFLARE_TOKEN}`, 'Content-Type': 'application/json' } }
    );
    const zone = zoneRes.data.result;
    console.log('✅ Zone créée :', zone.id);
    await axios.post(
      `https://api.cloudflare.com/client/v4/zones/${zone.id}/dns_records`,
      { type: 'CNAME', name: '@', content: targetUrl, proxied: true },
      { headers: { 'Authorization': `Bearer ${CLOUDFLARE_TOKEN}`, 'Content-Type': 'application/json' } }
    );
    console.log('✅ DNS configuré');
    return { success: true, zone_id: zone.id, domain: domain };
  } catch (error) {
    console.error('❌ Cloudflare Agent:', error.response?.data || error.message);
    return { success: false, error: error.response?.data?.message || error.message };
  }
}

// ============================================
// AGENT 5 : IMAGE
// ============================================
async function imageAgent(prompt) {
  console.log('🎨 Image Agent : début');
  try {
    const response = await axios.post(
      `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/ai/run/@cf/black-forest-labs/flux-1-schnell`,
      { prompt: prompt, steps: 4 },
      {
        headers: { 'Authorization': `Bearer ${CLOUDFLARE_AI_TOKEN}`, 'Content-Type': 'application/json' },
        responseType: 'arraybuffer',
        timeout: 60000
      }
    );
    const base64 = Buffer.from(response.data).toString('base64');
    return { success: true, image_url: `data:image/png;base64,${base64}`, prompt: prompt };
  } catch (error) {
    let errorMsg = error.message;
    if (error.response?.data) {
      try { errorMsg = new TextDecoder().decode(error.response.data); } catch(e) {}
    }
    console.error('❌ Image Agent:', errorMsg);
    return { success: false, error: errorMsg };
  }
}

// ============================================
// ORCHESTRATEUR
// ============================================
async function orchestratorDeploy(userId, projectId, projectName, files) {
  console.log('🎯 Orchestrateur : début');
  const resultats = { github: null, neon: null, render: null, cloudflare: null, success: false };

  resultats.github = await githubAgent(projectName, files);
  if (!resultats.github.success) return resultats;

  resultats.neon = await neonAgent(projectName, userId || 'anonymous');
  resultats.render = await renderAgent(projectName, resultats.github.clone_url);

  if (CLOUDFLARE_ACCOUNT_ID && resultats.render.service_url) {
    resultats.cloudflare = await cloudflareAgent(`${projectName}.com`, resultats.render.service_url);
  }

  resultats.success = true;
  console.log('🎉 Orchestrateur : terminé');
  return resultats;
}

// ============================================
// ROUTE : DÉPLOIEMENT
// ============================================
app.post('/api/deploy', async (req, res) => {
  const { userId, projectId, projectName, files } = req.body;
  if (!projectName || !files) return res.status(400).json({ error: 'projectName et files requis' });
  console.log('🚀 Déploiement :', projectName);
  try {
    const resultats = await orchestratorDeploy(userId, projectId, projectName, files);
    if (!resultats.success) return res.status(500).json({ error: 'Échec du déploiement', details: resultats });
    res.json({ success: true, message: 'App déployée', deployment: resultats });
  } catch (error) {
    console.error('Erreur deploy:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// ROUTE : IMAGE
// ============================================
app.post('/api/image', async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'prompt requis' });
  console.log('🎨 Génération image :', prompt);
  try {
    const result = await imageAgent(prompt);
    if (!result.success) return res.status(500).json({ error: result.error });
    res.json(result);
  } catch (error) {
    console.error('Erreur image:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// ROUTE : CHAT IA (avec mémoire)
// ============================================
app.post('/api/chat', async (req, res) => {
  const { message, history, firebase_uid, project_id } = req.body;
  if (!message) return res.status(400).json({ error: 'Message requis' });
  if (!GEMINI_API_KEY) return res.json({ response: '⚠️ Clé API manquante.', simulated: true });

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
            text: `Tu es un développeur senior expert en création d'applications.
COMPORTEMENT :
- Sois parfois gentil, parfois direct.
- Ne te présente JAMAIS.
- Réponds en français.
QUESTIONS :
- Pose 2-4 questions pour comprendre le besoin.
IMAGES :
- DÈS QUE l'utilisateur décrit une app à créer, ajoute à la FIN de ta réponse :
  [IMAGE: description précise en anglais de l'interface]
CODE :
- Ne code JAMAIS avant confirmation.
- Format : \`\`\`html:index.html`
          }]
        },
        contents: contents,
        generationConfig: { temperature: 0.8, maxOutputTokens: 4000 }
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

    // Sauvegarder dans la mémoire Neon (si user connecté)
    if (firebase_uid) {
      try {
        const client = await getNeonClient();
        const user = await client.query('SELECT id FROM users WHERE firebase_uid = $1', [firebase_uid]);
        if (user.rows.length > 0) {
          await client.query(
            `INSERT INTO conversation_memory (user_id, project_id, role, content) VALUES ($1, $2, 'user', $3)`,
            [user.rows[0].id, project_id || null, message]
          );
          await client.query(
            `INSERT INTO conversation_memory (user_id, project_id, role, content) VALUES ($1, $2, 'model', $3)`,
            [user.rows[0].id, project_id || null, reponse]
          );
        }
        await client.end();
      } catch (e) { console.log('Mémoire non sauvée:', e.message); }
    }

    res.json({ response: reponse, image_prompt: imagePrompt });
  } catch (error) {
    console.error('Erreur Gemini:', error.response?.data || error.message);
    res.status(500).json({ error: 'Erreur IA', response: `Erreur : ${error.response?.data?.error?.message || error.message}` });
  }
});

// ============================================
// ROUTES : TERMINAL & SANDBOX
// ============================================
app.post('/api/terminal/exec', async (req, res) => {
  const { commande, mode = 'normal' } = req.body;
  if (!commande) return res.status(400).json({ error: 'Commande vide' });
  const cmd = antivirus.nettoyerCommande(commande);
  const verif = antivirus.verifierCommande(cmd, mode);
  if (!verif.allowed) return res.json({ blocked: true, reason: verif.reason, level: verif.level, commande: cmd });
  if (verif.needsConfirmation) return res.json({ needsConfirmation: true, reason: verif.reason, commande: cmd });
  console.log(`✅ Exécution : ${cmd}`);
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
