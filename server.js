// server.js (SON GÜVENLİ VERSİYON - Dosya/Fotoğraf Desteği)

// Bu satır, MONGO_URI'yi .env dosyasından okur (Lokalde test için gereklidir)
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
if (!MONGO_URI) {
    console.error("KRİTİK HATA: MONGO_URI ortam değişkeni okunamadı.");
    process.exit(1); 
}

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Bağlantısı Başarılı. ✅'))
  .catch(err => {
    console.error('MongoDB Bağlantı Hatası:', err);
    process.exit(1);
  });

// --- MONGODB ŞEMALARI ---
// 1. Kullanıcı Doğrulama Şeması (Authentication)
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    salt: { type: String, required: true },
    hash: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema); 

// 2. Güvenli Not/Veri Saklama Şeması (Encryption)
const NoteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    encryptedContent: { type: String, required: true }, // Şifreli içerik (Metin veya Base64 Dosya Verisi)
    iv: { type: String, required: true }, // Şifre çözme vektörü
    contentType: { type: String, required: true }, // VERİ TÜRÜ (text, image/png, application/pdf vb.)
    fileName: { type: String }, // Opsiyonel: Dosya adı
    createdAt: { type: Date, default: Date.now }
});
const Note = mongoose.model('Note', NoteSchema); 

// --- MIDDLEWARE ---
// Artık daha büyük dosya yüklemelerini desteklemek için body-parser limitini artırıyoruz
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' })); // ÖNEMLİ: Dosya boyutu limitini artırdık
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

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

// 1. KAYIT ENDPOINT'i
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send({ message: 'Eksik bilgi.' });

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(409).send({ message: 'Bu kullanıcı adı zaten kayıtlı.' });

        const hashedData = hashPassword(password);
        const newUser = new User({ username, salt: hashedData.salt, hash: hashedData.hash });

        await newUser.save(); 
        res.status(201).send({ message: 'Kayıt başarılı.' });
    } catch (e) {
        res.status(500).send({ message: 'Sunucu hatası.' });
    }
});

// 2. GİRİŞ ENDPOINT'i
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send({ message: 'Eksik bilgi.' });

    try {
        const user = await User.findOne({ username });

        if (!user) return res.status(401).send({ message: 'Kullanıcı adı veya parola hatalı.' });

        const isPasswordValid = verifyPassword(password, user.salt, user.hash);

        if (isPasswordValid) {
            console.log(`> GİRİŞ BAŞARILI: ${username}`);
            return res.send({ message: 'Giriş başarılı!', userId: user._id });
        } else {
            console.log(`> GİRİŞ HATASI: ${username}`);
            return res.status(401).send({ message: 'Kullanıcı adı veya parola hatalı.' });
        }
    } catch (e) {
        res.status(500).send({ message: 'Sunucu hatası.' });
    }
});

// 3. NOT/VERİ KAYDETME ENDPOINT'i
app.post('/save_note', async (req, res) => {
    const { userId, encryptedContent, iv, contentType, fileName } = req.body; 

    if (!userId || !encryptedContent || !iv || !contentType) {
        return res.status(400).send({ message: 'Eksik veri: Kullanıcı ID, şifreli içerik, IV ve içerik türü gereklidir.' });
    }

    try {
        const newNote = new Note({
            userId: userId,
            encryptedContent: encryptedContent,
            iv: iv,
            contentType: contentType, // YENİ
            fileName: fileName,     // YENİ
        });

        await newNote.save();
        res.status(201).send({ message: 'Veriniz güvenli bir şekilde şifreli olarak kaydedildi.' });

    } catch (e) {
        console.error("Veri Kaydetme Hatası:", e);
        res.status(500).send({ message: 'Sunucu, veriyi kaydederken hata oluştu.' });
    }
});


// 4. NOTLARI/VERİLERİ ÇEKME ENDPOINT'i
app.get('/get_notes/:userId', async (req, res) => {
    const userId = req.params.userId;

    try {
        // Tüm alanları çekiyoruz
        const notes = await Note.find({ userId: userId }).select('encryptedContent iv contentType fileName createdAt');
        
        res.status(200).send({ notes: notes });

    } catch (e) {
        res.status(500).send({ message: 'Sunucu, verileri çekerken hata oluştu.' });
    }
});


app.listen(PORT, () => {
    console.log(`Server çalışıyor: http://localhost:${PORT}`);
});