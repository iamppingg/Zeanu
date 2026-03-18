const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const cors    = require('cors');

const app = express();
app.use(cors());          // necessário para o site Netlify falar com este backend
app.use(express.json());

// ─── Configuração ────────────────────────────────────────────────────────────
const JWT_SECRET   = process.env.JWT_SECRET   || 'troque-isso-aqui';
const GAME_VERSION = process.env.GAME_VERSION || '1.0.0';
const DOWNLOAD_URL = process.env.DOWNLOAD_URL || 'https://github.com/SEU-USER/SEU-REPO/releases/latest/download/client.zip';
const PORT         = process.env.PORT         || 3000;

// Pasta de skins
const SKINS_DIR = path.join(__dirname, 'skins');
if (!fs.existsSync(SKINS_DIR)) fs.mkdirSync(SKINS_DIR);

// ─── Banco de dados simples (arquivo JSON) ────────────────────────────────────
// Para escalar: troque por MongoDB Atlas (free tier) ou Supabase
const DB_FILE = path.join(__dirname, 'users.json');

function readDB()       { try { return JSON.parse(fs.readFileSync(DB_FILE,'utf8')); } catch { return {}; } }
function writeDB(users) { fs.writeFileSync(DB_FILE, JSON.stringify(users,null,2)); }

// ─── Auth middleware ──────────────────────────────────────────────────────────
function auth(req, res, next) {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer '))
        return res.status(401).json({ success:false, message:'Não autenticado' });
    try {
        req.user = jwt.verify(h.slice(7), JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ success:false, message:'Token inválido ou expirado' });
    }
}

// ─── REGISTER ─────────────────────────────────────────────────────────────────
app.post('/auth/register', async (req,res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email)
        return res.status(400).json({ success:false, message:'Preencha todos os campos' });

    if (username.length < 3 || username.length > 16)
        return res.status(400).json({ success:false, message:'Nome deve ter 3–16 caracteres' });

    if (!/^[a-zA-Z0-9_]+$/.test(username))
        return res.status(400).json({ success:false, message:'Nome só pode ter letras, números e _' });

    if (password.length < 6)
        return res.status(400).json({ success:false, message:'Senha muito curta (mín. 6)' });

    const db  = readDB();
    const key = username.toLowerCase();

    if (db[key])
        return res.status(400).json({ success:false, message:'Usuário já existe' });

    // Checar email duplicado
    if (Object.values(db).some(u => u.email === email.toLowerCase()))
        return res.status(400).json({ success:false, message:'Email já cadastrado' });

    db[key] = {
        username,
        email: email.toLowerCase(),
        password: await bcrypt.hash(password, 10),
        createdAt: new Date().toISOString()
    };
    writeDB(db);
    res.json({ success:true });
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/auth/login', async (req,res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ success:false, message:'Preencha usuário e senha' });

    const db   = readDB();
    const user = db[username.toLowerCase()];

    if (!user)
        return res.status(401).json({ success:false, message:'Usuário não encontrado' });

    if (!await bcrypt.compare(password, user.password))
        return res.status(401).json({ success:false, message:'Senha incorreta' });

    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ success:true, token, username: user.username });
});

// ─── RENAME ───────────────────────────────────────────────────────────────────
app.post('/auth/rename', auth, (req,res) => {
    const { newUsername } = req.body;
    if (!newUsername)
        return res.status(400).json({ success:false, message:'Novo nome obrigatório' });

    if (newUsername.length < 3 || newUsername.length > 16)
        return res.status(400).json({ success:false, message:'Nome deve ter 3–16 caracteres' });

    if (!/^[a-zA-Z0-9_]+$/.test(newUsername))
        return res.status(400).json({ success:false, message:'Nome inválido' });

    const db     = readDB();
    const oldKey = req.user.username.toLowerCase();
    const newKey = newUsername.toLowerCase();

    if (db[newKey] && newKey !== oldKey)
        return res.status(400).json({ success:false, message:'Nome já está em uso' });

    const user   = db[oldKey];
    user.username = newUsername;

    // Mover chave no banco
    if (newKey !== oldKey) {
        db[newKey] = user;
        delete db[oldKey];
        // Renomear skin se existir
        const oldSkin = path.join(SKINS_DIR, oldKey + '.png');
        const newSkin = path.join(SKINS_DIR, newKey + '.png');
        if (fs.existsSync(oldSkin)) fs.renameSync(oldSkin, newSkin);
    }
    writeDB(db);

    // Novo token com nome atualizado
    const token = jwt.sign({ username: newUsername }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ success:true, username: newUsername, token });
});

// ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────
app.post('/auth/change-password', auth, async (req,res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword)
        return res.status(400).json({ success:false, message:'Preencha os campos' });

    if (newPassword.length < 6)
        return res.status(400).json({ success:false, message:'Nova senha muito curta' });

    const db   = readDB();
    const key  = req.user.username.toLowerCase();
    const user = db[key];

    if (!await bcrypt.compare(oldPassword, user.password))
        return res.status(401).json({ success:false, message:'Senha atual incorreta' });

    user.password = await bcrypt.hash(newPassword, 10);
    writeDB(db);
    res.json({ success:true });
});

// ─── DELETE ACCOUNT ───────────────────────────────────────────────────────────
app.post('/auth/delete', auth, (req,res) => {
    const db  = readDB();
    const key = req.user.username.toLowerCase();
    delete db[key];
    writeDB(db);
    // Remover skin
    const skinFile = path.join(SKINS_DIR, key + '.png');
    if (fs.existsSync(skinFile)) fs.unlinkSync(skinFile);
    res.json({ success:true });
});

// ─── VERIFY TOKEN (usado pelo servidor Minecraft) ─────────────────────────────
app.post('/auth/verify', (req,res) => {
    const { username, token } = req.body;
    if (!username || !token)
        return res.status(400).json({ success:false, message:'Dados incompletos' });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        if (payload.username.toLowerCase() === username.toLowerCase()) {
            return res.json({ success:true });
        }
        return res.status(401).json({ success:false, message:'Token nao pertence a esse usuario' });
    } catch {
        return res.status(401).json({ success:false, message:'Token invalido ou expirado' });
    }
});

// ─── VERSION ──────────────────────────────────────────────────────────────────
app.get('/version', (req,res) => {
    res.json({ version: GAME_VERSION, downloadUrl: DOWNLOAD_URL });
});

// ─── SKIN UPLOAD ──────────────────────────────────────────────────────────────
const upload = multer({
    storage: multer.diskStorage({
        destination: SKINS_DIR,
        filename: (req,file,cb) => cb(null, req.user.username.toLowerCase() + '.png')
    }),
    limits: { fileSize: 256*1024 },
    fileFilter: (_,file,cb) => file.mimetype === 'image/png' ? cb(null,true) : cb(new Error('Apenas PNG'))
});

app.post('/skin/upload', auth, upload.single('skin'), (req,res) => {
    res.json({ success:true });
});

// ─── SKIN SERVE ───────────────────────────────────────────────────────────────
app.get('/skin/:user.png', (req,res) => {
    const file = path.join(SKINS_DIR, req.params.user.toLowerCase() + '.png');
    if (fs.existsSync(file)) {
        res.setHeader('Content-Type','image/png');
        res.setHeader('Cache-Control','no-cache');
        return res.sendFile(file);
    }
    // Skin padrão
    const def = path.join(__dirname, 'default_skin.png');
    if (fs.existsSync(def)) return res.sendFile(def);
    res.status(404).end();
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
