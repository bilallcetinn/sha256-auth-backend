// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');
const bodyParser = require('body-parser');
const http = require('http');
const { Server } = require('socket.io');

const app = express();

// JSON limitleri
app.use(express.json({ limit: '100mb' }));
app.use(bodyParser.json({ limit: '100mb' }));
app.use(cors());

// HTTP + Socket.io
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'DELETE', 'PUT'],
  },
});

// ----------------- SOCKET.IO -----------------
io.on('connection', (socket) => {
  console.log('🔌 Yeni bir client bağlandı:', socket.id);
  socket.on('join', (userId) => {
    if (!userId) return;
    socket.join(userId);
    console.log(`🟢 Kullanıcı odaya katıldı: userId=${userId}`);
  });
  socket.on('disconnect', () => {
    console.log('❌ Client bağlantısı koptu:', socket.id);
  });
});

// ----------------- MONGODB -----------------
// BAĞLANTI KISMINA HİÇ DOKUNMADIM (İstediğin gibi)
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB bağlantısı başarılı'))
  .catch((err) => console.error('❌ MongoDB bağlantı hatası:', err));

// ----------------- MODELLER -----------------
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  fullName: { type: String, required: true },
  password: { type: String, required: true },
  salt: { type: String, required: true },
  recoveryWord: { type: String, required: true }, // Yeni eklenen alan
});
const User = mongoose.model('User', userSchema);

const sharedFileSchema = new mongoose.Schema({
  fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  toUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  toUsername: String,
  fileName: String,
  contentType: String,
  encryptedContent: String,
  iv: String, // Şifreleme için gerekli
  shareCode: { type: String, unique: true, sparse: true },
  createdAt: { type: Date, default: Date.now },
});
const SharedFile = mongoose.model('SharedFile', sharedFileSchema);

// ----------------- ROUTES -----------------

// 1. KAYIT OLMA (recoveryWord EKLENDİ)
app.post('/register', async (req, res) => {
  try {
    const { username, fullName, password, recoveryWord } = req.body;

    if (!username || !fullName || !password || !recoveryWord) {
      return res.status(400).send({ message: 'Tüm alanlar zorunludur.' });
    }

    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(400).send({ message: 'Bu kullanıcı adı zaten alınmış.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hashedPassword = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');

    const newUser = new User({
      username,
      fullName,
      password: hashedPassword,
      salt,
      recoveryWord,
    });

    await newUser.save();
    res.status(201).send({ message: 'Kayıt başarılı.' });
  } catch (err) {
    console.error('Kayıt hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// 2. GİRİŞ YAPMA
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).send({ message: 'Hatalı kullanıcı adı veya şifre.' });
    }

    const hash = crypto.pbkdf2Sync(password, user.salt, 1000, 64, 'sha512').toString('hex');
    if (hash !== user.password) {
      return res.status(401).send({ message: 'Hatalı kullanıcı adı veya şifre.' });
    }

    res.send({
      userId: user._id,
      fullName: user.fullName,
      salt: user.salt,
    });
  } catch (err) {
    console.error('Giriş hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// 3. ŞİFRE SIFIRLAMA
app.post('/reset_password', async (req, res) => {
  try {
    const { username, recoveryWord, newPassword } = req.body;
    const user = await User.findOne({ username });

    if (!user || user.recoveryWord !== recoveryWord) {
      return res.status(401).send({ message: 'Kurtarma bilgileri eşleşmiyor.' });
    }

    const newSalt = crypto.randomBytes(16).toString('hex');
    const newHash = crypto.pbkdf2Sync(newPassword, newSalt, 1000, 64, 'sha512').toString('hex');

    user.password = newHash;
    user.salt = newSalt;
    await user.save();

    res.send({ message: 'Şifre başarıyla güncellendi.' });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// 4. DOSYA GÖNDERME (iv EKLENDİ)
app.post('/send_note', async (req, res) => {
  try {
    const { fromUserId, toUsername, fileName, encryptedContent, iv, contentType } = req.body;

    const targetUser = await User.findOne({ username: toUsername });
    if (!targetUser) {
      return res.status(404).send({ message: 'Alıcı kullanıcı bulunamadı.' });
    }

    const newShared = new SharedFile({
      fromUserId,
      toUserId: targetUser._id,
      toUsername,
      fileName,
      encryptedContent,
      iv,
      contentType,
    });

    await newShared.save();

    // Socket ile bildirim gönder
    io.to(targetUser._id.toString()).emit('inbox_updated');

    res.status(201).send({ message: 'Gönderildi.' });
  } catch (err) {
    console.error('send_note hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// 5. GELEN KUTUSU
app.get('/inbox/:userId', async (req, res) => {
  try {
    const items = await SharedFile.find({ toUserId: req.params.userId }).sort({ createdAt: -1 });
    res.send({ items });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// 6. GİDEN KUTUSU
app.get('/sent_items/:userId', async (req, res) => {
  try {
    const items = await SharedFile.find({ fromUserId: req.params.userId }).sort({ createdAt: -1 });
    res.send({ items });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// 7. SİLME
app.delete('/inbox_item/:id', async (req, res) => {
  try {
    const deleted = await SharedFile.findByIdAndDelete(req.params.id);
    if (deleted && deleted.toUserId) {
      io.to(deleted.toUserId.toString()).emit('inbox_updated');
    }
    res.send({ message: 'Silindi.' });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// --- SERVER BAŞLATMA (RENDER İÇİN PORT AYARI) ---
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Sunucu ${PORT} portunda yayında.`);
});