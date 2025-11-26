// server.js (SON GÜVENLİ VERSİYON - process.env kullanır)

// Bu satır, MONGO_URI'yi .env dosyasından okur (Lokalde çalışması için gereklidir)
require('dotenv').config(); 

const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose'); 
const app = express();
const PORT = 3000;

// GÜVENLİĞİN KALBİ: URI'yi gizli ortam değişkeninden çekiyoruz
const MONGO_URI = process.env.MONGO_URI; 

// --- MONGODB BAĞLANTISI ---
// Eğer MONGO_URI tanımsızsa, hemen hata fırlatır (Lokal .env hatası varsa)
if (!MONGO_URI) {
    console.error("KRİTİK HATA: MONGO_URI ortam değişkeni okunamadı. .env dosyanızı veya Render ayarlarınızı kontrol edin.");
    process.exit(1); // Sunucuyu durdurur
}

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Bağlantısı Başarılı. ✅'))
  .catch(err => {
    console.error('MongoDB Bağlantı Hatası: Lütfen şifrenizi kontrol edin.', err);
    process.exit(1);
  });

// --- MONGODB ŞEMASI ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    salt: { type: String, required: true }, 
    hash: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema); 

// --- MIDDLEWARE ---
app.use(cors());
app.use(bodyParser.json());

// --- KRİPTOGRAFİK FONKSİYONLAR (SHA-256) ---
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

// --- API ENDPOINT'LERİ ---
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send({ message: 'Eksik bilgi.' });

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(409).send({ message: 'Bu kullanıcı adı zaten kayıtlı.' });

        const hashedData = hashPassword(password);
        const newUser = new User({ username, salt: hashedData.salt, hash: hashedData.hash });

        await newUser.save(); 
        console.log(`> DB KAYIT: ${username}`);
        res.status(201).send({ message: 'Kayıt başarılı.' });
    } catch (e) {
        res.status(500).send({ message: 'Sunucu hatası.' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send({ message: 'Eksik bilgi.' });

    try {
        const user = await User.findOne({ username });

        if (!user) return res.status(401).send({ message: 'Kullanıcı adı veya parola hatalı.' });

        const isPasswordValid = verifyPassword(password, user.salt, user.hash);

        if (isPasswordValid) {
            console.log(`> GİRİŞ BAŞARILI: ${username}`);
            res.send({ message: 'Giriş başarılı!', token: 'simule_jwt_token' });
        } else {
            console.log(`> GİRİŞ HATASI: ${username}`);
            res.status(401).send({ message: 'Kullanıcı adı veya parola hatalı.' });
        }
    } catch (e) {
        res.status(500).send({ message: 'Sunucu hatası.' });
    }
});

// Sunucuyu Başlatma
app.listen(PORT, () => {
    console.log(`Server çalışıyor: http://localhost:${PORT}`);
});