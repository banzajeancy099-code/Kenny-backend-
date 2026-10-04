const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Clés API
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

// Client Supabase
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Route de test
app.get('/', (req, res) => {
  res.json({ 
    message: 'Backend Kenny opérationnel !',
    supabase: SUPABASE_URL ? '✅ Connecté' : '❌ Manquant'
  });
});

// ============ AUTHENTIFICATION ============

// Inscription
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Mot de passe trop court (min 6)' });
  }

  try {
    // Vérifier si l'user existe
    const { data: existing } = await supabase
      .from('users')
      .select('email')
      .eq('email', email)
      .single();

    if (existing) {
      return res.status(400).json({ error: 'Cet email est déjà utilisé' });
    }

    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // Créer l'user
    const { data, error } = await supabase
      .from('users')
      .insert([{ email, password: hashedPassword }])
      .select()
      .single();

    if (error) throw error;

    res.json({ 
      success: true, 
      message: 'Compte créé',
      user: { id: data.id, email: data.email }
    });

  } catch (error) {
    console.error('Erreur register:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Connexion
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  }

  try {
    // Chercher l'user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    // Vérifier le mot de passe
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    res.json({ 
      success: true, 
      message: 'Connexion réussie',
      user: { id: user.id, email: user.email }
    });

  } catch (error) {
    console.error('Erreur login:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ PROJETS ============

// Sauvegarder un projet
app.post('/api/projects', async (req, res) => {
  const { user_id, name, code } = req.body;

  if (!user_id || !name) {
    return res.status(400).json({ error: 'user_id et name requis' });
  }

  try {
    const { data, error } = await supabase
      .from('projects')
      .insert([{ user_id, name, code }])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, project: data });

  } catch (error) {
    console.error('Erreur save project:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Récupérer les projets d'un user
app.get('/api/projects/:user_id', async (req, res) => {
  const { user_id } = req.params;

  try {
    const { data, error } = await supabase
      .from('projects')
      .select('*')
      .eq('user_id', user_id)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({ projects: data });

  } catch (error) {
    console.error('Erreur get projects:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ CHAT IA ============

app.post('/api/chat', async (req, res) => {
  const { message, history } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Message requis' });
  }

  if (!GEMINI_API_KEY) {
    return res.json({ response: `⚠️ Clé API manquante.`, simulated: true });
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
            text: `Tu es un développeur senior qui aide à créer des applications. Tu as un côté humain ET un côté IA.

CÔTÉ HUMAIN :
- Tu comprends vraiment ce que l'utilisateur veut.
- Tu réfléchis avant de répondre.
- Tu parles honnêtement.
- Tu poses des questions pour bien cerner le besoin.

CÔTÉ IA :
- Tu es toujours prêt à aider.
- Si l'utilisateur insiste, tu exécutes sans discuter.
- Tu es efficace et précis.

RÈGLES :
- Ne te présente JAMAIS.
- Ne sois pas trop poli.
- Réponds de manière directe et concise.
- Réponds en français.
- NE CODE JAMAIS directement. Pose 2-3 questions d'abord.
- Une fois que tu as assez d'infos, résume et demande confirmation.
- Quand tu génères du code, mets-le dans un bloc \`\`\`html et dis ce que tu fais.`
          }]
        },
        contents: contents,
        generationConfig: {
          temperature: 0.8,
          maxOutputTokens: 3000
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

app.get('/api/users', (req, res) => {
  res.json([
    { id: 1, nom: 'jean' },
    { id: 2, nom: 'marie' }
  ]);
});

app.listen(PORT, () => {
  console.log('Serveur sur le port ' + PORT);
});
