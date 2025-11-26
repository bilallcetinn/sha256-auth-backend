const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors'); // <--- YENİ EKLENDİ

const app = express();
const PORT = 3000;

app.use(cors()); // <--- YENİ: Tarayıcıdan erişime izin ver
app.use(bodyParser.json());

const usersDB = []; 

// --- Şifreleme Fonksiyonları ---
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHash('sha256')
                       .update(password + salt)
                       .digest('hex');
    return { salt, hash };
}

function verifyPassword(password, storedSalt, storedHash) {
    const newHash = crypto.createHash('sha256')
                          .update(password + storedSalt)
                          .digest('hex');
    return newHash === storedHash;
}

// --- API Endpoint'leri ---
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send({ message: 'Eksik bilgi.' });
    if (usersDB.find(u => u.username === username)) return res.status(409).send({ message: 'Kullanıcı zaten var.' });

    const data = hashPassword(password);
    usersDB.push({ username, salt: data.salt, hash: data.hash });
    
    console.log(`> YENİ KAYIT: ${username}`);
    res.status(201).send({ message: 'Kayıt başarılı.' });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = usersDB.find(u => u.username === username);

    if (!user) return res.status(401).send({ message: 'Hatalı kullanıcı adı veya şifre.' });

    if (verifyPassword(password, user.salt, user.hash)) {
        console.log(`> GİRİŞ BAŞARILI: ${username}`);
        res.send({ message: 'Giriş başarılı!' });
    } else {
        console.log(`> GİRİŞ HATASI: ${username}`);
        res.status(401).send({ message: 'Hatalı kullanıcı adı veya şifre.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server çalışıyor (CORS aktif): http://localhost:${PORT}`);
});