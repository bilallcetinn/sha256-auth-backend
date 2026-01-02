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
mongoose.connect('mongodb://localhost:27017/authenlock', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Bağlantısı Başarılı"))
  .catch(err => console.error("Bağlantı Hatası:", err));

// --- MODELLER ---

// Kullanıcı Modeli (recoveryWord eklendi)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    fullName: { type: String, required: true },
    password: { type: String, required: true },
    salt: { type: String, required: true },
    recoveryWord: { type: String, required: true } // Şifre kurtarma için kritik alan
});
const User = mongoose.model('User', userSchema);

// Paylaşılan Dosya Modeli
const sharedFileSchema = new mongoose.Schema({
    fromUserId: mongoose.Schema.Types.ObjectId,
    toUserId: mongoose.Schema.Types.ObjectId,
    toUsername: String,
    fileName: String,
    contentType: String,
    encryptedContent: String,
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

// --- ROTALAR (ROUTES) ---

// 1. KAYIT OLMA
app.post("/register", async (req, res) => {
    const { username, fullName, password, recoveryWord } = req.body;
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: "Kullanıcı adı zaten alınmış." });

        const salt = crypto.randomBytes(16).toString('hex');
        const hashedPassword = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');

        const newUser = new User({
            username,
            fullName,
            password: hashedPassword,
            salt,
            recoveryWord // Kurtarma kelimesi kaydediliyor
        });

        await newUser.save();
        res.status(201).json({ message: "Kayıt başarılı." });
    } catch (err) {
        res.status(500).json({ message: "Kayıt hatası." });
    }
});

// 2. GİRİŞ YAPMA
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

// 3. ŞİFRE SIFIRLAMA (RECOVERY)
app.post("/reset_password", async (req, res) => {
    const { username, recoveryWord, newPassword } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || user.recoveryWord !== recoveryWord) {
            return res.status(401).json({ message: "Kullanıcı adı veya kurtarma kelimesi yanlış!" });
        }

        // Yeni şifre için yeni salt ve hash oluşturuluyor
        const newSalt = crypto.randomBytes(16).toString('hex');
        const newHashedPassword = crypto.pbkdf2Sync(newPassword, newSalt, 1000, 64, 'sha512').toString('hex');

        user.password = newHashedPassword;
        user.salt = newSalt;
        await user.save();

        res.json({ message: "Şifre başarıyla güncellendi." });
    } catch (err) {
        res.status(500).json({ message: "Sıfırlama hatası." });
    }
});

// 4. GELEN KUTUSUNU GETİR
app.get("/inbox/:userId", async (req, res) => {
    try {
        const items = await SharedFile.find({ toUserId: req.params.userId }).sort({ createdAt: -1 });
        res.json({ items });
    } catch (err) {
        res.status(500).json({ error: "Gelen kutusu yüklenemedi." });
    }
});

// 5. GİDEN KUTUSUNU GETİR
app.get("/sent_items/:userId", async (req, res) => {
    try {
        const items = await SharedFile.find({ fromUserId: req.params.userId }).sort({ createdAt: -1 });
        res.json({ items });
    } catch (err) {
        res.status(500).json({ error: "Giden kutusu yüklenemedi." });
    }
});

// 6. DOSYA/NOT GÖNDERME
app.post("/send_note", async (req, res) => {
    const { fromUserId, toUsername, fileName, encryptedContent, contentType } = req.body;
    try {
        const targetUser = await User.findOne({ username: toUsername });
        if (!targetUser) return res.status(404).json({ message: "Alıcı bulunamadı." });

        const newFile = new SharedFile({
            fromUserId,
            toUserId: targetUser._id,
            toUsername,
            fileName,
            encryptedContent,
            contentType
        });

        await newFile.save();
        
        // Socket.io ile alıcıya bildirim gönder (Sayaç anlık artacak)
        io.to(targetUser._id.toString()).emit('inbox_updated');

        res.status(201).json({ message: "Gönderildi." });
    } catch (err) {
        res.status(500).json({ error: "Gönderim hatası." });
    }
});

// 7. GELEN KUTUSUNDAN SİLME
app.delete("/inbox_item/:id", async (req, res) => {
    try {
        await SharedFile.findByIdAndDelete(req.params.id);
        res.json({ message: "Silindi." });
    } catch (err) {
        res.status(500).json({ error: "Silme hatası." });
    }
});

// --- SERVER BAŞLATMA ---
const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor.`);
});