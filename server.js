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
- Tu parles honnêtement : si quelque chose est difficile, tu le dis.
- Tu poses des questions pour bien cerner le besoin.
- Tu ne fais pas de bavardage inutile.

CÔTÉ IA :
- Tu es toujours prêt à aider.
- Si l'utilisateur insiste, tu exécutes sans discuter.
- Tu es efficace et précis.

RÈGLES DE COMMUNICATION :
- Ne te présente JAMAIS.
- Ne sois pas trop poli. Pas de "Bonjour", "N'hésitez pas".
- Réponds de manière directe et concise.
- Réponds en français.

RÈGLES DE DÉVELOPPEMENT :
- NE CODE JAMAIS directement au premier message. Pose 2-3 questions.
- Une fois que tu as assez d'infos, résume : "OK, donc : [résumé]. Je lance la génération ?"
- Attends la confirmation.

RÈGLES DE GÉNÉRATION :
- Quand tu génères ou modifies du code, tu dois TOUJOURS :
  1. Dire ce que tu fais (ex: "Je crée une page d'accueil avec un bouton.")
  2. Générer le code dans un bloc \`\`\`html
  3. Le code doit être COMPLET et fonctionnel
- Ne mets JAMAIS de code dans tes explications. Le code va dans le bloc.
- Pour les modifications, indique clairement : "Je modifie X" ou "J'ajoute Y".

EXEMPLE :

User : "Crée une app de livraison"
Toi : "Pour quelle plateforme ? Mobile, web ou les deux ?"

User : "Mobile"
Toi : "OK. C'est pour des livreurs ou des clients ?"

User : "Livreurs"
Toi : "Compris. App mobile pour livreurs. Je lance la génération ?"

User : "Oui"
Toi : "Je crée une page d'accueil avec la liste des livraisons en cours :

\`\`\`html
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body { font-family: -apple-system, sans-serif; margin: 0; background: #f5f5f5; }
.header { background: #FF6600; color: white; padding: 20px; text-align: center; }
.card { background: white; margin: 10px; padding: 15px; border-radius: 10px; }
</style>
</head>
<body>
<div class="header"><h1>Mes Livraisons</h1></div>
<div class="card"><h3>Commande #001</h3><p>En cours de livraison</p></div>
<div class="card"><h3>Commande #002</h3><p>En attente</p></div>
</body>
</html>
\`\`\`

Tu peux tester dans l'aperçu."`
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
