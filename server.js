const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ============================================
// VARIABLES D'ENVIRONNEMENT
// ============================================
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const SUPABASE_TOKEN = process.env.SUPABASE_TOKEN;
const RENDER_TOKEN = process.env.RENDER_TOKEN;
const CLOUDFLARE_TOKEN = process.env.CLOUDFLARE_TOKEN;
const SUPABASE_ORG_ID = process.env.SUPABASE_ORG_ID;
const RENDER_OWNER_ID = process.env.RENDER_OWNER_ID;
const CLOUDFLARE_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;

// Client Supabase (pour auth)
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ============================================
// ROUTE DE TEST
// ============================================
app.get('/', (req, res) => {
  res.json({ 
    message: 'Backend Kenny opérationnel !',
    supabase: SUPABASE_URL ? '✅ Connecté' : '❌ Manquant'
  });
});

// ============================================
// AGENT 1 : GITHUB (Créer un repo + push)
// ============================================
async function githubAgent(projectName, files) {
  console.log('🤖 GitHub Agent : début');
  
  try {
    const repoRes = await axios.post(
      'https://api.github.com/user/repos',
      {
        name: projectName,
        private: true,
        auto_init: false,
        description: 'App générée par Kenny'
      },
      {
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      }
    );
    
    const repo = repoRes.data;
    console.log('✅ Repo créé :', repo.full_name);
    
    for (const file of files) {
      await axios.put(
        `https://api.github.com/repos/${repo.full_name}/contents/${file.nom}`,
        {
          message: `Ajout ${file.nom}`,
          content: Buffer.from(file.contenu).toString('base64')
        },
        {
          headers: {
            'Authorization': `token ${GITHUB_TOKEN}`,
            'Accept': 'application/vnd.github.v3+json'
          }
        }
      );
      console.log('✅ Fichier push :', file.nom);
    }
    
    return {
      success: true,
      repo_url: repo.html_url,
      repo_full_name: repo.full_name,
      clone_url: repo.clone_url
    };
    
  } catch (error) {
    console.error('❌ GitHub Agent erreur:', error.response?.data || error.message);
    return {
      success: false,
      error: error.response?.data?.message || error.message
    };
  }
}

// ============================================
// AGENT 2 : SUPABASE (Créer une DB)
// ============================================
async function supabaseAgent(projectName) {
  console.log('🤖 Supabase Agent : début');
  
  try {
    const projectRes = await axios.post(
      'https://api.supabase.com/v1/projects',
      {
        name: projectName,
        organization_id: SUPABASE_ORG_ID,
        region: 'eu-west-1',
        plan: 'free'
      },
      {
        headers: {
          'Authorization': `Bearer ${SUPABASE_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    const project = projectRes.data;
    console.log('✅ Projet Supabase créé :', project.id);
    
    return {
      success: true,
      project_id: project.id,
      project_url: `https://${project.id}.supabase.co`,
      api_key: project.anon_key
    };
    
  } catch (error) {
    console.error('❌ Supabase Agent erreur:', error.response?.data || error.message);
    return {
      success: false,
      error: error.response?.data?.message || error.message
    };
  }
}

// ============================================
// AGENT 3 : RENDER (Créer un serveur)
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
          envSpecificDetails: {
            buildCommand: 'npm install',
            startCommand: 'npm start'
          }
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${RENDER_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    const service = serviceRes.data;
    console.log('✅ Service Render créé :', service.id);
    
    return {
      success: true,
      service_id: service.id,
      service_url: service.serviceDetails?.url
    };
    
  } catch (error) {
    console.error('❌ Render Agent erreur:', error.response?.data || error.message);
    return {
      success: false,
      error: error.response?.data?.message || error.message
    };
  }
}

// ============================================
// AGENT 4 : CLOUDFLARE (Domaine + DNS)
// ============================================
async function cloudflareAgent(domain, targetUrl) {
  console.log('🤖 Cloudflare Agent : début');
  
  try {
    const zoneRes = await axios.post(
      'https://api.cloudflare.com/client/v4/zones',
      {
        name: domain,
        account: { id: CLOUDFLARE_ACCOUNT_ID },
        jump_start: true
      },
      {
        headers: {
          'Authorization': `Bearer ${CLOUDFLARE_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    const zone = zoneRes.data.result;
    console.log('✅ Zone créée :', zone.id);
    
    await axios.post(
      `https://api.cloudflare.com/client/v4/zones/${zone.id}/dns_records`,
      {
        type: 'CNAME',
        name: '@',
        content: targetUrl,
        proxied: true
      },
      {
        headers: {
          'Authorization': `Bearer ${CLOUDFLARE_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log('✅ DNS configuré');
    
    return {
      success: true,
      zone_id: zone.id,
      domain: domain
    };
    
  } catch (error) {
    console.error('❌ Cloudflare Agent erreur:', error.response?.data || error.message);
    return {
      success: false,
      error: error.response?.data?.message || error.message
    };
  }
}

// ============================================
// ORCHESTRATEUR
// ============================================
async function orchestratorDeploy(userId, projectId, projectName, files) {
  console.log('🎯 Orchestrateur : début');
  
  const resultats = {
    github: null,
    supabase: null,
    render: null,
    cloudflare: null,
    success: false
  };
  
  resultats.github = await githubAgent(projectName, files);
  if (!resultats.github.success) return resultats;
  
  resultats.supabase = await supabaseAgent(projectName);
  resultats.render = await renderAgent(projectName, resultats.github.clone_url);
  
  if (CLOUDFLARE_ACCOUNT_ID) {
    resultats.cloudflare = await cloudflareAgent(
      `${projectName}.com`,
      resultats.render.service_url
    );
  }
  
  resultats.success = true;
  console.log('🎉 Orchestrateur : terminé');
  
  return resultats;
}

// ============================================
// ROUTES
// ============================================

// Test des agents
app.get('/api/agents/test', (req, res) => {
  res.json({
    github: GITHUB_TOKEN ? '✅ Configuré' : '❌ Manquant',
    supabase: SUPABASE_TOKEN ? '✅ Configuré' : '❌ Manquant',
    render: RENDER_TOKEN ? '✅ Configuré' : '❌ Manquant',
    cloudflare: CLOUDFLARE_TOKEN ? '✅ Configuré' : '❌ Manquant'
  });
});

// Déploiement
app.post('/api/deploy', async (req, res) => {
  const { userId, projectId, projectName, files } = req.body;
  
  if (!projectName || !files) {
    return res.status(400).json({ error: 'projectName et files requis' });
  }
  
  console.log('🚀 Déploiement :', projectName);
  
  try {
    const resultats = await orchestratorDeploy(userId, projectId, projectName, files);
    
    if (!resultats.success) {
      return res.status(500).json({
        error: 'Échec du déploiement',
        details: resultats
      });
    }
    
    res.json({
      success: true,
      message: 'App déployée',
      deployment: resultats
    });
    
  } catch (error) {
    console.error('Erreur deploy:', error);
    res.status(500).json({ error: error.message });
  }
});

// Auth
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Champs requis' });
  if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court' });

  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) return res.status(400).json({ error: error.message });

  res.json({ 
    success: true, 
    user: { id: data.user.id, email: data.user.email }
  });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Champs requis' });

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

  res.json({ 
    success: true, 
    user: { id: data.user.id, email: data.user.email }
  });
});

// Chat IA
app.post('/api/chat', async (req, res) => {
  const { message, history } = req.body;
  if (!message) return res.status(400).json({ error: 'Message requis' });

  if (!GEMINI_API_KEY) {
    return res.json({ response: '⚠️ Clé API manquante.', simulated: true });
  }

  try {
    const contents = [];
    
    if (history && Array.isArray(history)) {
      history.forEach(msg => {
        contents.push({
          role: msg.role === 'user' ? 'user' : 'model',
          parts: [{ text: msg.content }]
        });
      });
    }
    
    contents.push({ role: 'user', parts: [{ text: message }] });

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${GEMINI_API_KEY}`,
      {
        systemInstruction: {
          parts: [{
            text: `Tu es un développeur senior qui aide à créer des applications.

COMPORTEMENT :
- Sois parfois gentil, parfois direct.
- Ne te présente JAMAIS.
- Réponds en français.

CODE :
- Ne code JAMAIS avant confirmation.
- Format : \`\`\`html:index.html
- Chaque langage va dans SON fichier.`
          }]
        },
        contents: contents,
        generationConfig: {
          temperature: 0.8,
          maxOutputTokens: 4000
        }
      },
      {
        headers: { 'Content-Type': 'application/json' },
        timeout: 60000
      }
    );

    const reponse = response.data.candidates[0].content.parts[0].text;
    res.json({ response: reponse });

  } catch (error) {
    console.error('Erreur Gemini:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Erreur IA',
      response: `Erreur : ${error.response?.data?.error?.message || error.message}`
    });
  }
});

// ============================================
// DÉMARRAGE
// ============================================
app.listen(PORT, () => {
  console.log('Serveur sur le port ' + PORT);
});
