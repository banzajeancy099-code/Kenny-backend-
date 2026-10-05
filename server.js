const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ============ TEST ============
app.get('/', (req, res) => {
  res.json({ 
    message: 'Backend Kenny opérationnel !',
    supabase: SUPABASE_URL ? '✅ Connecté' : '❌ Manquant'
  });
});

// ============ AUTH ============
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

// ============ PROJETS ============
app.post('/api/projects', async (req, res) => {
  const { user_id, name } = req.body;
  if (!user_id || !name) return res.status(400).json({ error: 'user_id et name requis' });

  try {
    const { data, error } = await supabase
      .from('projects')
      .insert([{ user_id, name, code: '' }])
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, project: data });
  } catch (error) {
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/projects/:user_id', async (req, res) => {
  const { user_id } = req.params;
  try {
    const { data, error } = await supabase
      .from('projects')
      .select('*')
      .eq('user_id', user_id)
      .order('name', { ascending: true });

    if (error) throw error;
    res.json({ projects: data });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/projects/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase.from('projects').delete().eq('id', id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Mettre à jour le code d'un projet
app.put('/api/projects/:id', async (req, res) => {
  const { id } = req.params;
  const { code } = req.body;
  try {
    const { error } = await supabase
      .from('projects')
      .update({ code })
      .eq('id', id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ MESSAGES ============
app.post('/api/messages', async (req, res) => {
  const { project_id, role, content } = req.body;
  if (!project_id || !role || !content) {
    return res.status(400).json({ error: 'Champs requis' });
  }

  try {
    const { data, error } = await supabase
      .from('messages')
      .insert([{ project_id, role, content }])
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, message: data });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/messages/:project_id', async (req, res) => {
  const { project_id } = req.params;
  try {
    const { data, error } = await supabase
      .from('messages')
      .select('*')
      .eq('project_id', project_id)
      .order('created_at', { ascending: true });

    if (error) throw error;
    res.json({ messages: data });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ CHAT IA ============
app.post('/api/chat', async (req, res) => {
  const { message, history } = req.body;
  if (!message) return res.status(400).json({ error: 'Message requis' });

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
            text: `Tu es un développeur senior qui aide à créer des applications.

COMPORTEMENT :
- Sois parfois gentil, parfois direct. Équilibre. Comme un humain.
- Ne te présente JAMAIS.
- Réponds en français.

QUESTIONS :
- Pose autant de questions que nécessaire pour comprendre le besoin.
- Si l'utilisateur dit "arrête" ou "c'est bon", obéis immédiatement.
- 2-4 questions suffisent souvent.

CODE :
- Ne code JAMAIS avant confirmation explicite.
- Quand tu codes, mets CHAQUE fichier dans un bloc de code SÉPARÉ avec son nom.
- Format obligatoire : \`\`\`html:index.html ou \`\`\`css:styles.css ou \`\`\`javascript:app.js
- Chaque langage va dans SON fichier.

FORMAT :
- Mets ton texte AVANT les blocs de code.
- Pas de code dans le texte.

EMOJIS :
- Parfois, pas d'habitude.`
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

app.listen(PORT, () => {
  console.log('Serveur sur le port ' + PORT);
});
