// ============================================
// AGENTS DE DÉPLOIEMENT
// ============================================

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const SUPABASE_TOKEN = process.env.SUPABASE_TOKEN;
const RENDER_TOKEN = process.env.RENDER_TOKEN;
const CLOUDFLARE_TOKEN = process.env.CLOUDFLARE_TOKEN;

// ============================================
// AGENT 1 : GITHUB (Créer un repo + push)
// ============================================
async function githubAgent(projectName, files) {
  console.log('🤖 GitHub Agent : début');
  
  try {
    // 1. Créer le repo
    const repoRes = await axios.post(
      'https://api.github.com/user/repos',
      {
        name: projectName,
        private: true,
        auto_init: false,
        description: `App générée par Kenny`
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
    
    // 2. Push chaque fichier
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
    // 1. Créer le projet
    const projectRes = await axios.post(
      'https://api.supabase.com/v1/projects',
      {
        name: projectName,
        organization_id: process.env.SUPABASE_ORG_ID,
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
        ownerId: process.env.RENDER_OWNER_ID,
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
    // 1. Créer la zone
    const zoneRes = await axios.post(
      'https://api.cloudflare.com/client/v4/zones',
      {
        name: domain,
        account: { id: process.env.CLOUDFLARE_ACCOUNT_ID },
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
    
    // 2. Créer le DNS
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
// ORCHESTRATEUR (Coordonne tout)
// ============================================
async function orchestratorDeploy(userId, projectId, projectName, files) {
  console.log('🎯 Orchestrateur : début du déploiement');
  
  const resultats = {
    github: null,
    supabase: null,
    render: null,
    cloudflare: null,
    success: false
  };
  
  // Étape 1 : GitHub
  resultats.github = await githubAgent(projectName, files);
  if (!resultats.github.success) {
    return resultats;
  }
  
  // Étape 2 : Supabase
  resultats.supabase = await supabaseAgent(projectName);
  
  // Étape 3 : Render
  resultats.render = await renderAgent(projectName, resultats.github.clone_url);
  
  // Étape 4 : Cloudflare (optionnel)
  if (process.env.CLOUDFLARE_ACCOUNT_ID) {
    resultats.cloudflare = await cloudflareAgent(
      `${projectName}.com`,
      resultats.render.service_url
    );
  }
  
  resultats.success = true;
  console.log('🎉 Orchestrateur : déploiement terminé');
  
  return resultats;
}

// ============================================
// ROUTE DE DÉPLOIEMENT
// ============================================
app.post('/api/deploy', async (req, res) => {
  const { userId, projectId, projectName, files } = req.body;
  
  if (!projectName || !files) {
    return res.status(400).json({ error: 'projectName et files requis' });
  }
  
  console.log('🚀 Déploiement demandé :', projectName);
  
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
      message: 'App déployée avec succès',
      deployment: resultats
    });
    
  } catch (error) {
    console.error('Erreur deploy:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// ROUTE DE TEST DES AGENTS
// ============================================
app.get('/api/agents/test', async (req, res) => {
  const resultats = {
    github: GITHUB_TOKEN ? '✅ Configuré' : '❌ Manquant',
    supabase: SUPABASE_TOKEN ? '✅ Configuré' : '❌ Manquant',
    render: RENDER_TOKEN ? '✅ Configuré' : '❌ Manquant',
    cloudflare: CLOUDFLARE_TOKEN ? '✅ Configuré' : '❌ Manquant'
  };
  
  res.json(resultats);
});
