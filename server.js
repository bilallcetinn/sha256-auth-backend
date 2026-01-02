require('dotenv').config(); // .env dosyasındaki değişkenleri okumak için
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" }
});

app.use(cors());
app.use(express.json());

// --- MONGODB BAĞLANTISI ---
// Render Environment Variables kısmına MONGODB_URI eklemeyi unutma!
const mongoURI = process.env.MONGODB_URI; 

if (!mongoURI) {
    console.error("HATA: MONGODB_URI tanımlanmamış!");
    process.exit(1);
}

mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Atlas Bağlantısı Başarılı"))
  .catch(err => console.error("MongoDB Bağlantı Hatası:", err));

// --- MODELLER ---

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    fullName: { type: String, required: true },
    password: { type: String, required: true },
    salt: { type: String, required: true },
    recoveryWord: { type: String, required: true } 
});
const User = mongoose.model('User', userSchema);

const sharedFileSchema = new mongoose.Schema({
    fromUserId: mongoose.Schema.Types.ObjectId,
    toUserId: mongoose.Schema.Types.ObjectId,
    toUsername: String,
    fileName: String,
    contentType: String,
    encryptedContent: String,
    iv: String, // Şifreleme için gerekli IV alanı
    shareCode: { type: String, unique: true, sparse: true },
    createdAt: { type: Date, default: Date.now }
});
const SharedFile = mongoose.model('SharedFile', sharedFileSchema);

// --- SOCKET.IO AYARLARI ---
io.on('connection', (socket) => {
    socket.on('join', (userId) => {
        socket.join(userId);
        console.log(`Kullanıcı odaya katıldı: ${userId}`);
    });
});

// --- ROTALAR (API) ---

// Sağlık Kontrolü (Render uyanık mı bakmak için)
app.get("/", (req, res) => res.send("AuthenLock Sunucusu Aktif!"));

// 1. KAYIT
app.post("/register", async (req, res) => {
    const { username, fullName, password, recoveryWord } = req.body;
    try {
        if (!username || !fullName || !password || !recoveryWord) {
            return res.status(400).json({ message: "Eksik alan var." });
        }
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: "Bu kullanıcı adı alınmış." });

        const salt = crypto.randomBytes(16).toString('hex');
        const hashedPassword = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');

        const newUser = new User({
            username, fullName, password: hashedPassword, salt, recoveryWord
        });

        await newUser.save();
        res.status(201).json({ message: "Kayıt başarılı." });
    } catch (err) {
        console.error("Kayıt Hatası:", err);
        res.status(500).json({ message: "Sunucu hatası." });
    }
});

// 2. GİRİŞ
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(401).json({ message: "Hatalı kullanıcı adı veya şifre." });

        const hash = crypto.pbkdf2Sync(password, user.salt, 1000, 64, 'sha512').toString('hex');
        if (hash !== user.password) return res.status(401).json({ message: "Hatalı kullanıcı adı veya şifre." });

        res.json({
            userId: user._id,
            fullName: user.fullName,
            salt: user.salt
        });
    } catch (err) {
        res.status(500).json({ message: "Giriş hatası." });
    }
});

// 3. ŞİFRE SIFIRLAMA
app.post("/reset_password", async (req, res) => {
    const { username, recoveryWord, newPassword } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || user.recoveryWord !== recoveryWord) {
            return res.status(401).json({ message: "Kurtarma bilgileri yanlış." });
        }

        const newSalt = crypto.randomBytes(16).toString('hex');
        const newHashedPassword = crypto.pbkdf2Sync(newPassword, newSalt, 1000, 64, 'sha512').toString('hex');

        user.password = newHashedPassword;
        user.salt = newSalt;
        await user.save();

        res.json({ message: "Şifre güncellendi." });
    } catch (err) {
        res.status(500).json({ message: "Hata oluştu." });
    }
});

// 4. GELEN KUTUSU
app.get("/inbox/:userId", async (req, res) => {
    try {
        const items = await SharedFile.find({ toUserId: req.params.userId }).sort({ createdAt: -1 });
        res.json({ items });
    } catch (err) {
        res.status(500).json({ error: "Yüklenemedi." });
    }
});

// 5. GİDEN KUTUSU
app.get("/sent_items/:userId", async (req, res) => {
    try {
        const items = await SharedFile.find({ fromUserId: req.params.userId }).sort({ createdAt: -1 });
        res.json({ items });
    } catch (err) {
        res.status(500).json({ error: "Yüklenemedi." });
    }
});

// 6. DOSYA GÖNDER
app.post("/send_note", async (req, res) => {
    const { fromUserId, toUsername, fileName, encryptedContent, iv, contentType } = req.body;
    try {
        const targetUser = await User.findOne({ username: toUsername });
        if (!targetUser) return res.status(404).json({ message: "Alıcı bulunamadı." });

        const newFile = new SharedFile({
            fromUserId, toUserId: targetUser._id, toUsername, fileName, encryptedContent, iv, contentType
        });

        await newFile.save();
        io.to(targetUser._id.toString()).emit('inbox_updated');
        res.status(201).json({ message: "Dosya gönderildi." });
    } catch (err) {
        res.status(500).json({ error: "Gönderim hatası." });
    }
});

// 7. SİLME
app.delete("/inbox_item/:id", async (req, res) => {
    try {
        await SharedFile.findByIdAndDelete(req.params.id);
        res.json({ message: "Silindi." });
    } catch (err) {
        res.status(500).json({ error: "Silinemedi." });
    }
});

// --- SERVER BAŞLATMA ---
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Sunucu ${PORT} portunda aktif.`);
});