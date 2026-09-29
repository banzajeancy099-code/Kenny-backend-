const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Clé API DeepSeek (depuis les variables d'environnement Render)
const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY;

// Route de test
app.get('/', (req, res) => {
  res.json({ message: 'Backend Kenny opérationnel !' });
});

// Route du chat avec IA
app.post('/api/chat', async (req, res) => {
  const { message } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Message requis' });
  }

  // Si pas de clé API, réponse simulée
  if (!DEEPSEEK_API_KEY) {
    return res.json({ 
      response: `⚠️ Clé API manquante. Tu as dit : "${message}"`,
      simulated: true
    });
  }

  try {
    const response = await axios.post(
      'https://api.deepseek.com/chat/completions',
      {
        model: 'deepseek-chat',
        messages: [
          {
            role: 'system',
            content: `Tu es Kenny, un assistant IA expert qui aide les utilisateurs à créer des applications. 
Tu réponds de manière claire, amicale et professionnelle en français.
Quand l'utilisateur décrit une app, tu lui expliques comment tu vas la créer.`
          },
          {
            role: 'user',
            content: message
          }
        ],
        temperature: 0.7,
        max_tokens: 500
      },
      {
        headers: {
          'Authorization': `Bearer ${DEEPSEEK_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const reponse = response.data.choices[0].message.content;
    res.json({ response: reponse });

  } catch (error) {
    console.error('Erreur DeepSeek:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Erreur IA',
      response: '❌ Désolé, je rencontre un problème technique. Réessaie.'
    });
  }
});

// Route utilisateurs
app.get('/api/users', (req, res) => {
  res.json([
    { id: 1, nom: 'jean' },
    { id: 2, nom: 'marie' }
  ]);
});

app.listen(PORT, () => {
  console.log('Serveur sur le port ' + PORT);
});
