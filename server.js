const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

app.get('/', (req, res) => {
  res.json({ 
    message: 'Backend Kenny opérationnel !',
    supabase: SUPABASE_URL ? '✅ Connecté' : '❌ Manquant'
  });
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
- Exemple :
  \`\`\`html:index.html
  <!DOCTYPE html>...
  \`\`\`
  \`\`\`css:styles.css
  body { ... }
  \`\`\`
- Chaque langage va dans SON fichier :
  - HTML → index.html
  - CSS → styles.css
  - JavaScript → app.js
  - Python → main.py
  - Kotlin → Main.kt
  - JSON → data.json
- Après avoir codé, relis ton code 5 FOIS ligne par ligne pour vérifier.

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

// ============ AUTH (garde ce qu'on avait) ============
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Champs requis' });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
      .from('users')
      .insert([{ email, password: hashedPassword }])
      .select()
      .single();
    if (error) throw error;
    res.json({ success: true, user: { id: data.id, email: data.email } });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Champs requis' });
  try {
    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();
    if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    res.json({ success: true, user: { id: user.id, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/users', (req, res) => {
  res.json([{ id: 1, nom: 'jean' }, { id: 2, nom: 'marie' }]);
});

app.listen(PORT, () => {
  console.log('Serveur sur le port ' + PORT);
});
