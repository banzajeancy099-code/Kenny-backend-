const express = require('express');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;


app.use(cors());
app.use(express.json());

const users = [
  { id: 1, nom: ' Jean' },
  { id: 2, nom: ' marie'}
];
app.get('/',(req, res) => {
  res.json({ message: 'backend kenny operationnel !
           });

  app.listen(port, () => {
    console.log('serveur sur le port ${PORT}');
  });

        
