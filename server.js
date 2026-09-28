const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const users = [
  { id: 1, nom: 'jean' },
  { id: 2, nom: 'marie' }
];

app.get('/', (req, res) => {
  res.json({ message: 'Backend Kenny operationnel !' });
});

app.get('/api/users', (req, res) => {
  res.json(users);
});

app.listen(PORT, () => {
  console.log('Serveur sur le port ' + PORT);
});
