const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const cors    = require('cors');
const { MongoClient } = require('mongodb');

const app = express();
app.use(cors());
app.use(express.json());

// ─── Configuração ─────────────────────────────────────────────────────────────
const JWT_SECRET   = process.env.JWT_SECRET   || 'troque-isso-aqui';
const GAME_VERSION = process.env.GAME_VERSION || '1.0.0';
const DOWNLOAD_URL = process.env.DOWNLOAD_URL || 'https://github.com/SEU-USER/SEU-REPO/releases/latest/download/client.zip';
const PORT         = process.env.PORT         || 3000;
const MONGO_URL    = process.env.MONGO_URL; // defina no Render

// ─── MongoDB ──────────────────────────────────────────────────────────────────
let usersCol;

async function connectDB() {
    const client = new MongoClient(MONGO_URL);
    await client.connect();
    const db = client.db('zeanu');
    usersCol = db.collection('users');
    await usersCol.createIndex({ usernameLower: 1 }, { unique: true });
    await usersCol.createIndex({ email: 1 },         { unique: true });
    console.log('MongoDB conectado!');
}

// ─── Skins (Render apaga arquivos, mas skins ficam no MongoDB como base64) ────
const SKINS_DIR = path.join(__dirname, 'skins');
if (!fs.existsSync(SKINS_DIR)) fs.mkdirSync(SKINS_DIR);

// ─── Sessoes ativas ───────────────────────────────────────────────────────────
const activeSessions = new Map();
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

// ─── Auth middleware ──────────────────────────────────────────────────────────
function auth(req, res, next) {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer '))
        return res.status(401).json({ success: false, message: 'Não autenticado' });
    try {
        req.user = jwt.verify(h.slice(7), JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ success: false, message: 'Token inválido ou expirado' });
    }
}

// ─── REGISTER ─────────────────────────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email)
        return res.status(400).json({ success: false, message: 'Preencha todos os campos' });

    if (username.length < 3 || username.length > 16)
        return res.status(400).json({ success: false, message: 'Nome deve ter 3–16 caracteres' });

    if (!/^[a-zA-Z0-9_]+$/.test(username))
        return res.status(400).json({ success: false, message: 'Nome só pode ter letras, números e _' });

    if (password.length < 6)
        return res.status(400).json({ success: false, message: 'Senha muito curta (mín. 6)' });

    try {
        await usersCol.insertOne({
            username,
            usernameLower: username.toLowerCase(),
            email: email.toLowerCase(),
            password: await bcrypt.hash(password, 10),
            createdAt: new Date()
        });
        res.json({ success: true });
    } catch (e) {
        if (e.code === 11000) {
            const field = e.message.includes('email') ? 'Email já cadastrado' : 'Usuário já existe';
            return res.status(400).json({ success: false, message: field });
        }
        res.status(500).json({ success: false, message: 'Erro interno' });
    }
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ success: false, message: 'Preencha usuário e senha' });

    const user = await usersCol.findOne({ usernameLower: username.toLowerCase() });

    if (!user)
        return res.status(401).json({ success: false, message: 'Usuário não encontrado' });

    if (!await bcrypt.compare(password, user.password))
        return res.status(401).json({ success: false, message: 'Senha incorreta' });

    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    activeSessions.set(user.username.toLowerCase(), Date.now());
    res.json({ success: true, token, username: user.username });
});

// ─── RENAME ───────────────────────────────────────────────────────────────────
app.post('/auth/rename', auth, async (req, res) => {
    const { newUsername } = req.body;
    if (!newUsername)
        return res.status(400).json({ success: false, message: 'Novo nome obrigatório' });

    if (newUsername.length < 3 || newUsername.length > 16)
        return res.status(400).json({ success: false, message: 'Nome deve ter 3–16 caracteres' });

    if (!/^[a-zA-Z0-9_]+$/.test(newUsername))
        return res.status(400).json({ success: false, message: 'Nome inválido' });

    const oldKey = req.user.username.toLowerCase();
    const newKey = newUsername.toLowerCase();

    try {
        await usersCol.updateOne(
            { usernameLower: oldKey },
            { $set: { username: newUsername, usernameLower: newKey } }
        );
        const token = jwt.sign({ username: newUsername }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, username: newUsername, token });
    } catch (e) {
        if (e.code === 11000)
            return res.status(400).json({ success: false, message: 'Nome já está em uso' });
        res.status(500).json({ success: false, message: 'Erro interno' });
    }
});

// ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────
app.post('/auth/change-password', auth, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword)
        return res.status(400).json({ success: false, message: 'Preencha os campos' });

    if (newPassword.length < 6)
        return res.status(400).json({ success: false, message: 'Nova senha muito curta' });

    const user = await usersCol.findOne({ usernameLower: req.user.username.toLowerCase() });

    if (!await bcrypt.compare(oldPassword, user.password))
        return res.status(401).json({ success: false, message: 'Senha atual incorreta' });

    await usersCol.updateOne(
        { usernameLower: req.user.username.toLowerCase() },
        { $set: { password: await bcrypt.hash(newPassword, 10) } }
    );
    res.json({ success: true });
});

// ─── DELETE ACCOUNT ───────────────────────────────────────────────────────────
app.post('/auth/delete', auth, async (req, res) => {
    const key = req.user.username.toLowerCase();
    await usersCol.deleteOne({ usernameLower: key });
    const skinFile = path.join(SKINS_DIR, key + '.png');
    if (fs.existsSync(skinFile)) fs.unlinkSync(skinFile);
    res.json({ success: true });
});

// ─── CHECK SESSION ────────────────────────────────────────────────────────────
app.get('/auth/check/:username', (req, res) => {
    const key = req.params.username.toLowerCase();
    const lastSeen = activeSessions.get(key);
    if (lastSeen && (Date.now() - lastSeen) < SESSION_TIMEOUT_MS) {
        return res.json({ success: true });
    }
    return res.status(401).json({ success: false, message: 'Sessao nao encontrada ou expirada' });
});

// ─── VERSION ──────────────────────────────────────────────────────────────────
app.get('/version', (req, res) => {
    res.json({ version: GAME_VERSION, downloadUrl: DOWNLOAD_URL });
});

// ─── PING (mantém o Render acordado via cron-job) ─────────────────────────────
app.get('/ping', (req, res) => res.send('OK'));

// ─── SKIN UPLOAD ──────────────────────────────────────────────────────────────
const upload = multer({
    storage: multer.diskStorage({
        destination: SKINS_DIR,
        filename: (req, file, cb) => cb(null, req.user.username.toLowerCase() + '.png')
    }),
    limits: { fileSize: 256 * 1024 },
    fileFilter: (_, file, cb) => file.mimetype === 'image/png' ? cb(null, true) : cb(new Error('Apenas PNG'))
});

app.post('/skin/upload', auth, upload.single('skin'), (req, res) => {
    res.json({ success: true });
});

// ─── SKIN SERVE ───────────────────────────────────────────────────────────────
app.get('/skin/:user.png', (req, res) => {
    const file = path.join(SKINS_DIR, req.params.user.toLowerCase() + '.png');
    if (fs.existsSync(file)) {
        res.setHeader('Content-Type', 'image/png');
        res.setHeader('Cache-Control', 'no-cache');
        return res.sendFile(file);
    }
    const def = path.join(__dirname, 'default_skin.png');
    if (fs.existsSync(def)) return res.sendFile(def);
    res.status(404).end();
});

// ─── START ────────────────────────────────────────────────────────────────────
connectDB().then(() => {
    app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
}).catch(err => {
    console.error('Falha ao conectar no MongoDB:', err);
    process.exit(1);
});
