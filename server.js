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
  const { message, history } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Message requis' });
  }

  if (!GEMINI_API_KEY) {
    return res.json({ 
      response: `⚠️ Clé API manquante.`,
      simulated: true
    });
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
    
    contents.push({
      role: 'user',
      parts: [{ text: message }]
    });

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=${GEMINI_API_KEY}`,
      {
        systemInstruction: {
          parts: [{
            text: `Tu es un développeur senior qui aide à créer des applications. Tu discutes avec un client.

RÈGLES DE COMMUNICATION :
- Ne te présente JAMAIS. Pas de "Je suis Kenny", pas de "Bonjour, je suis...".
- Ne sois pas trop poli. Pas de "N'hésitez pas", "Avec plaisir", "Comment puis-je vous aider".
- Réponds de manière directe et concise.
- Ton neutre, comme un collègue développeur.
- Réponds en français.

RÈGLES DE DÉVELOPPEMENT (TRÈS IMPORTANT) :
- NE CODE JAMAIS directement. Tu dois d'abord COMPRENDRE le besoin.
- Si l'utilisateur dit "crée une app de livraison", tu ne codes pas. Tu POSES DES QUESTIONS :
  * "C'est pour quelle plateforme ? (mobile, web, desktop)"
  * "Il faut quelles fonctionnalités ? (paiement, suivi, chat...)"
  * "Tu as une préférence de design ?"
  * "C'est pour quel public ?"
- Pose 2-3 questions maximum à la fois. Pas 10 d'un coup.
- Une fois que tu as assez d'infos, tu résumes : "OK, donc : app mobile, paiement Stripe, suivi GPS, pour livreurs. Je lance la génération ?"
- Attends la confirmation avant de coder.

EXEMPLES :

User : "Crée une app de livraison"
Toi : "Pour quelle plateforme ? Mobile, web ou les deux ? Et tu veux quelles fonctionnalités en priorité (paiement, suivi GPS, chat) ?"

User : "Mobile et paiement"
Toi : "OK. Mobile + paiement. C'est pour des livreurs ou des clients ? Et tu veux Stripe ou PayPal ?"

User : "Livreurs, Stripe"
Toi : "Compris. App mobile pour livreurs avec paiement Stripe. J'ajoute un système de suivi GPS et de notation ? Ou on reste simple ?"

User : "GPS oui, notation non"
Toi : "Parfait. Je génère : app mobile livreurs, paiement Stripe, suivi GPS. Je lance ?"`
          }]
        },
        contents: contents,
        generationConfig: {
          temperature: 0.7,
          maxOutputTokens: 800
        }
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
