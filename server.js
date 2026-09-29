const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Route de test
app.get('/', (req, res) => {
  res.json({ message: 'Backend Kenny opérationnel !' });
});

// Route du chat
app.post('/api/chat', (req, res) => {
  const { message } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Message requis' });
  }
  
  // Réponse simulée (on branchera l'IA après)
  const reponse = `Tu as dit : "${message}". Je vais créer ton application !`;
  
  res.json({ 
    response: reponse,
    timestamp: new Date().toISOString()
  });
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
