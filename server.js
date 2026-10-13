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
const CLOUDFLARE_AI_TOKEN = process.env.CLOUDFLARE_AI_TOKEN;
const SUPABASE_ORG_ID = process.env.SUPABASE_ORG_ID;
const RENDER_OWNER_ID = process.env.RENDER_OWNER_ID;
const CLOUDFLARE_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;

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
// TEST DES AGENTS
// ============================================
app.get('/api/agents/test', (req, res) => {
  res.json({
    github: GITHUB_TOKEN ? '✅ Configuré' : '❌ Manquant',
    supabase: SUPABASE_TOKEN ? '✅ Configuré' : '❌ Manquant',
    render: RENDER_TOKEN ? '✅ Configuré' : '❌ Manquant',
    cloudflare: CLOUDFLARE_TOKEN ? '✅ Configuré' : '❌ Manquant',
    image: CLOUDFLARE_AI_TOKEN ? '✅ Configuré' : '❌ Manquant'
  });
});

// ============================================
// AGENT IMAGE
// ============================================
async function imageAgent(prompt) {
  console.log('🎨 Image Agent : début');
  
  try {
    const response = await axios.post(
      `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/ai/run/@cf/black-forest-labs/flux-1-schnell`,
      {
        prompt: prompt,
        steps: 4
      },
      {
        headers: {
          'Authorization': `Bearer ${CLOUDFLARE_AI_TOKEN}`,
          'Content-Type': 'application/json'
        },
        responseType: 'arraybuffer',
        timeout: 60000
      }
    );
    
    const base64 = Buffer.from(response.data).toString('base64');
    const imageUrl = `data:image/png;base64,${base64}`;
    
    console.log('✅ Image générée');
    
    return {
      success: true,
      image_url: imageUrl,
      prompt: prompt
    };
    
  } catch (error) {
    let errorMsg = error.message;
    if (error.response?.data) {
      try {
        const decoder = new TextDecoder();
        errorMsg = decoder.decode(error.response.data);
      } catch(e) {}
    }
    console.error('❌ Image Agent erreur:', errorMsg);
    return {
      success: false,
      error: errorMsg
    };
  }
}

// ============================================
// ROUTE GÉNÉRATION IMAGE
// ============================================
app.post('/api/image', async (req, res) => {
  const { prompt } = req.body;
  
  if (!prompt) {
    return res.status(400).json({ error: 'prompt requis' });
  }
  
  console.log('🎨 Génération image :', prompt);
  
  try {
    const result = await imageAgent(prompt);
    
    if (!result.success) {
      return res.status(500).json({ error: result.error });
    }
    
    res.json(result);
    
  } catch (error) {
    console.error('Erreur image:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// CHAT IA (texte d'abord, image après)
// ============================================
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
- Exemples :
  [IMAGE: modern delivery mobile app interface, purple colors, map view, order cards, clean design]
  [IMAGE: e-commerce website homepage, product grid, black and gold colors, luxury feel]
- Utilise [IMAGE: ...] UNIQUEMENT quand l'utilisateur décrit une app.

CODE :
- Ne code JAMAIS avant confirmation.
- Format : \`\`\`html:index.html`
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
        timeout: 180000
      }
    );

    let reponse = response.data.candidates[0].content.parts[0].text;
    
    // Détecter [IMAGE: ...]
    let imagePrompt = null;
    const imageMatch = reponse.match(/\[IMAGE:\s*(.+?)\]/i);
    
    if (imageMatch) {
      imagePrompt = imageMatch[1].trim();
      reponse = reponse.replace(/\[IMAGE:\s*.+?\]/gi, '').trim();
      console.log('🎨 Image demandée :', imagePrompt);
    }
    
    // Retourner le TEXTE immédiatement
    res.json({ 
      response: reponse,
      image_prompt: imagePrompt
    });

  } catch (error) {
    console.error('Erreur Gemini:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Erreur IA',
      response: `Erreur : ${error.response?.data?.error?.message || error.message}`
    });
  }
});

// ============================================
// AUTH
// ============================================
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

// ============================================
// DÉMARRAGE
// ============================================
app.listen(PORT, () => {
  console.log('Serveur sur le port ' + PORT);
});
