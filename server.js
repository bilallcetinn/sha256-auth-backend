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

// --- GÜNCELLEME: RESİM YÜKLEME İÇİN LİMİTLER ---
app.use(express.json({ limit: '100mb' }));
app.use(bodyParser.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
app.use(cors());

// HTTP + Socket.io
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'DELETE', 'PUT'],
  },
});

// --- YENİ: GÜÇLÜ ŞİFRE KONTROL FONKSİYONU ---
// En az 8 karakter, 1 büyük, 1 küçük harf, 1 rakam ve 1 özel karakter zorunluluğu
function isPasswordValid(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
    return passwordRegex.test(password);
}

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

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB bağlantısı başarılı'))
  .catch((err) => {
    console.error('❌ MongoDB bağlantı hatası:', err);
    process.exit(1);
  });

// ----------------- MODELLER -----------------

// User şeması (RecoveryWord eklendi)
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  fullName: { type: String, required: true },
  salt: { type: String, required: true },
  hash: { type: String, required: true },
  recoveryWord: { type: String, required: true }, // Şifre sıfırlama için gerekli
});

const User = mongoose.model('User', UserSchema);

// Kasa için not/dosya şeması
const NoteSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  encryptedContent: { type: String, required: true },
  iv: { type: String, required: true },
  contentType: { type: String, required: true }, // image / video / pdf / text
  fileName: { type: String },
  label: { type: String, default: null },
  createdAt: { type: Date, default: Date.now },
  sharedFrom: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  shareCode: { type: String, default: null },
});

const Note = mongoose.model('Note', NoteSchema);

// Paylaşım için ayrı model (kasa dışı)
const SharedFileSchema = new mongoose.Schema({
  fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  toUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // direct ise dolu
  mode: { type: String, enum: ['direct', 'code'], required: true },
  shareCode: { type: String, default: null }, // code modunda kullanılacak kod
  encryptedContent: { type: String, required: true }, // burada aslında düz base64 içerik
  iv: { type: String, required: true }, 
  contentType: { type: String, required: true }, // image / video / pdf / file / text
  fileName: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const SharedFile = mongoose.model('SharedFile', SharedFileSchema);

// ----------------- YARDIMCI FONKSİYONLAR -----------------

function hashPassword(password, salt = null) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .createHash('sha256')
    .update(password + salt)
    .digest('hex');
  return { salt, hash };
}

// ----------------- AUTH -----------------

// Kayıt (Güvenlik kontrolü eklendi)
app.post('/register', async (req, res) => {
  try {
    const { username, password, fullName, recoveryWord } = req.body;

    if (!username || !password || !fullName || !recoveryWord) {
      return res.status(400).send({ message: 'Tüm alanlar zorunludur' });
    }

    // ŞİFRE GÜVENLİK KONTROLÜ
    if (!isPasswordValid(password)) {
      return res.status(400).send({ 
        message: 'Şifre en az 8 karakter olmalı; büyük/küçük harf, rakam ve özel karakter içermelidir.' 
      });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).send({ message: 'Bu kullanıcı adı zaten kayıtlı' });
    }

    const { salt, hash } = hashPassword(password);
    const user = new User({ username, fullName, salt, hash, recoveryWord });

    await user.save();
    res.status(201).send({ message: 'Kayıt başarılı' });
  } catch (err) {
    console.error('Kayıt hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// Giriş
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).send({ message: 'Tüm alanlar zorunludur' });
    }
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).send({ message: 'Kullanıcı bulunamadı' });
    }
    const { hash } = hashPassword(password, user.salt);
    if (hash !== user.hash) {
      return res.status(401).send({ message: 'Şifre hatalı' });
    }
    res.send({
      message: 'Giriş başarılı',
      userId: user._id,
      fullName: user.fullName,
      salt: user.salt,
    });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// Şifre Sıfırlama (Yeni eklenen rota - RecoveryWord ile)
app.post('/reset_password', async (req, res) => {
  try {
    const { username, recoveryWord, newPassword } = req.body;
    
    if (!isPasswordValid(newPassword)) {
      return res.status(400).send({ message: 'Yeni şifre kurallara uygun değil.' });
    }

    const user = await User.findOne({ username });
    if (!user || user.recoveryWord !== recoveryWord) {
      return res.status(401).send({ message: 'Kurtarma bilgileri eşleşmiyor.' });
    }

    const { salt, hash } = hashPassword(newPassword);
    user.hash = hash;
    user.salt = salt;
    await user.save();

    res.send({ message: 'Şifre başarıyla güncellendi' });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// ----------------- KASA (NOT / DOSYA) -----------------

app.post('/save_note', async (req, res) => {
  try {
    const { userId, encryptedContent, iv, contentType, fileName, label } = req.body;
    if (!userId || !encryptedContent || !iv || !contentType) {
      return res.status(400).send({ message: 'Zorunlu alanlar eksik' });
    }
    const note = new Note({ userId, encryptedContent, iv, contentType, fileName, label });
    await note.save();
    io.to(userId.toString()).emit('notes_updated');
    res.status(201).send({ message: 'Not kaydedildi', noteId: note._id });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

app.get('/get_notes/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    let page = parseInt(req.query.page) || 1;
    let limit = parseInt(req.query.limit) || 1000;
    const notes = await Note.find({ userId }).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit);
    const total = await Note.countDocuments({ userId });
    res.send({ notes, total, page, limit });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

app.delete('/delete_note/:id', async (req, res) => {
  try {
    const deleted = await Note.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).send({ message: 'Not bulunamadı' });
    io.to(deleted.userId.toString()).emit('notes_updated');
    res.send({ message: 'Not silindi' });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// ----------------- PAYLAŞIM (KASA DIŞI) -----------------

app.post('/share_file', async (req, res) => {
  try {
    const { fromUserId, mode, targetUsername, encryptedContent, iv, contentType, fileName } = req.body;
    if (!fromUserId || !mode || !encryptedContent || !iv || !contentType) {
      return res.status(400).send({ message: 'Zorunlu alanlar eksik.' });
    }
    const fromUser = await User.findById(fromUserId);
    if (!fromUser) return res.status(404).send({ message: 'Gönderen kullanıcı bulunamadı.' });

    if (mode === 'direct') {
      const targetUser = await User.findOne({ username: targetUsername });
      if (!targetUser) return res.status(404).send({ message: 'Hedef kullanıcı bulunamadı.' });
      const shared = new SharedFile({ fromUserId: fromUser._id, toUserId: targetUser._id, mode: 'direct', encryptedContent, iv, contentType, fileName });
      await shared.save();
      io.to(targetUser._id.toString()).emit('inbox_updated');
      return res.status(201).send({ message: 'Dosya kullanıcıya gönderildi.' });
    }

    if (mode === 'code') {
      const shareCode = crypto.randomBytes(4).toString('hex');
      const shared = new SharedFile({ fromUserId: fromUser._id, mode: 'code', shareCode, encryptedContent, iv, contentType, fileName });
      await shared.save();
      return res.status(201).send({ message: 'Kod ile paylaşım oluşturuldu.', code: shareCode });
    }
    return res.status(400).send({ message: 'Geçersiz mode.' });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

app.get('/inbox/:userId', async (req, res) => {
  try {
    const items = await SharedFile.find({ toUserId: req.params.userId }).sort({ createdAt: -1 }).populate('fromUserId', 'username fullName');
    res.send({ items });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

app.get('/shared_by_code/:code', async (req, res) => {
  try {
    const shared = await SharedFile.findOne({ shareCode: req.params.code });
    if (!shared) return res.status(404).send({ message: 'Paylaşım bulunamadı.' });
    res.send({ item: shared });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

app.delete('/inbox_item/:id', async (req, res) => {
  try {
    const deleted = await SharedFile.findByIdAndDelete(req.params.id);
    if (deleted && deleted.toUserId) io.to(deleted.toUserId.toString()).emit('inbox_updated');
    res.send({ message: 'Silindi.' });
  } catch (err) {
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// ----------------- SUNUCU (RENDER UYUMLU) -----------------
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Sunucu aktif: http://0.0.0.0:${PORT}`);
});