const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

app.get('/', (req, res) => {
  res.json({ message: 'Backend Kenny opérationnel !' });
});

app.post('/api/chat', async (req, res) => {
  const { message } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Message requis' });
  }

  if (!GEMINI_API_KEY) {
    return res.json({ 
      response: `⚠️ Clé API manquante. Tu as dit : "${message}"`,
      simulated: true
    });
  }

  try {
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.7-flash:generateContent?key=${GEMINI_API_KEY}`,
      {
        contents: [{
          parts: [{
            text: `Tu es Kenny, un assistant IA expert qui aide les utilisateurs à créer des applications. Tu réponds en français de manière claire et amicale. Voici la demande de l'utilisateur : ${message}`
          }]
        }]
      },
      {
        headers: { 'Content-Type': 'application/json' },
        timeout: 30000
      }
    );

    const reponse = response.data.candidates[0].content.parts[0].text;
    res.json({ response: reponse });

  } catch (error) {
    console.error('Erreur Gemini:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Erreur IA',
      response: `❌ Erreur : ${error.response?.data?.error?.message || error.message}`
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
