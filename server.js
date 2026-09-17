const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connecté à MongoDB Atlas'))
    .catch(err => console.error('❌ Erreur MongoDB:', err));

const User = mongoose.model('User', new mongoose.Schema({
    phone: String, password: String, name: String, solde: Number, data: Number
}));

const Forfait = mongoose.model('Forfait', new mongoose.Schema({
    nom: String, prix: Number, data: String
}));

const Historique = mongoose.model('Historique', new mongoose.Schema({
    userId: String, titre: String, prix: Number, date: String, statut: String
}));

app.get('/', (req, res) => res.send('Backend Kenny Forfaits opérationnel !'));

app.post('/api/login', async (req, res) => {
    try {
        const { phone, password } = req.body;
        const user = await User.findOne({ phone, password });
        if (user) res.json({ success: true, user });
        else res.status(401).json({ success: false, message: "Identifiants incorrects" });
    } catch (e) { res.status(500).json({ message: "Erreur serveur" }); }
});

app.get('/api/forfaits', async (req, res) => {
    const forfaits = await Forfait.find();
    res.json(forfaits);
});

app.post('/api/achat', async (req, res) => {
    try {
        const { forfaitId, userId } = req.body;
        const forfait = await Forfait.findById(forfaitId);
        const user = await User.findById(userId);
        if (!forfait || !user) return res.status(404).json({ message: "Introuvable" });
        if (user.solde < forfait.prix) return res.status(400).json({ message: "Solde insuffisant" });

        user.solde -= forfait.prix;
        user.data += parseInt(forfait.data);
        await user.save();

        await new Historique({
            userId: user._id,
            titre: `${forfait.nom} — 7 jours`,
            prix: forfait.prix,
            date: new Date().toLocaleString('fr-FR'),
            statut: "Payé"
        }).save();

        res.json({ success: true, user });
    } catch (e) { res.status(500).json({ message: "Erreur" }); }
});

app.get('/api/historique/:userId', async (req, res) => {
    const hist = await Historique.find({ userId: req.params.userId }).sort({ _id: -1 });
    res.json(hist);
});

app.get('/api/seed', async (req, res) => {
    try {
        await User.deleteMany({});
        await Forfait.deleteMany({});
        
        await new User({ phone: "0985825885", password: "123456", name: "Alex", solde: 12500, data: 4.5 }).save();
        
        await Forfait.insertMany([
            { nom: "Forfait 1Go", prix: 500, data: "1" },
            { nom: "Forfait 2Go", prix: 1000, data: "2" },
            { nom: "Forfait 3Go", prix: 1500, data: "3" },
            { nom: "Forfait 4Go", prix: 2000, data: "4" },
            { nom: "Forfait 5Go", prix: 2500, data: "5" },
            { nom: "Forfait 10Go", prix: 5000, data: "10" }
        ]);
        
        res.json({ message: "Base de données initialisée avec succès !" });
    } catch (e) { res.status(500).json({ message: "Erreur seed", error: e.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Serveur sur le port ${PORT}`));
