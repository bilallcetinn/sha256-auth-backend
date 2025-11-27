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

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB bağlantısı başarılı'))
  .catch((err) => {
    console.error('❌ MongoDB bağlantı hatası:', err);
    process.exit(1);
  });

// ----------------- MODELLER -----------------

// User şeması
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  fullName: { type: String, required: true },
  salt: { type: String, required: true },
  hash: { type: String, required: true },
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

  // ileride lazım olabilir, dursun
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
  iv: { type: String, required: true }, // şimdilik zorunlu alan, güvenlik için değil
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

// Kayıt
app.post('/register', async (req, res) => {
  try {
    const { username, password, fullName } = req.body;

    if (!username || !password || !fullName) {
      return res.status(400).send({ message: 'Tüm alanlar zorunludur' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).send({ message: 'Bu kullanıcı adı zaten kayıtlı' });
    }

    const { salt, hash } = hashPassword(password);

    const user = new User({
      username,
      fullName,
      salt,
      hash,
    });

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
    console.error('Giriş hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// Şifre değiştirme
app.post('/change_password', async (req, res) => {
  try {
    const { userId, oldPassword, newPassword } = req.body;

    if (!userId || !oldPassword || !newPassword) {
      return res.status(400).send({ message: 'Tüm alanlar zorunludur' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send({ message: 'Kullanıcı bulunamadı' });
    }

    const { hash: oldHash } = hashPassword(oldPassword, user.salt);
    if (oldHash !== user.hash) {
      return res.status(401).send({ message: 'Eski şifre hatalı' });
    }

    const { salt, hash } = hashPassword(newPassword);
    user.salt = salt;
    user.hash = hash;
    await user.save();

    res.send({ message: 'Şifre başarıyla değiştirildi' });
  } catch (err) {
    console.error('Şifre değiştirme hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// Hesap silme
app.delete('/delete_account/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send({ message: 'Kullanıcı bulunamadı' });
    }

    await Note.deleteMany({ userId });
    await SharedFile.deleteMany({
      $or: [{ fromUserId: userId }, { toUserId: userId }],
    });
    await User.findByIdAndDelete(userId);

    io.to(userId.toString()).emit('account_deleted');

    res.send({ message: 'Hesap ve tüm notlar/paylaşımlar silindi' });
  } catch (err) {
    console.error('Hesap silme hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// ----------------- KASA (NOT / DOSYA) -----------------

// Not / dosya kaydetme (kasa)
app.post('/save_note', async (req, res) => {
  try {
    const { userId, encryptedContent, iv, contentType, fileName, label } =
      req.body;

    if (!userId || !encryptedContent || !iv || !contentType) {
      return res.status(400).send({ message: 'Zorunlu alanlar eksik' });
    }

    const note = new Note({
      userId,
      encryptedContent,
      iv,
      contentType,
      fileName,
      label,
    });

    await note.save();

    io.to(userId.toString()).emit('notes_updated');

    res.status(201).send({ message: 'Not kaydedildi', noteId: note._id });
  } catch (err) {
    console.error('Not kaydetme hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// Notları listeleme
app.get('/get_notes/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    let { page = 1, limit = 1000 } = req.query;

    page = parseInt(page);
    limit = parseInt(limit);

    const notes = await Note.find({ userId })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    const total = await Note.countDocuments({ userId });

    res.send({
      notes,
      total,
      page,
      limit,
    });
  } catch (err) {
    console.error('Notları listeleme hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// Not silme
app.delete('/delete_note/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const deleted = await Note.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).send({ message: 'Not bulunamadı' });
    }

    io.to(deleted.userId.toString()).emit('notes_updated');

    res.send({ message: 'Not silindi' });
  } catch (err) {
    console.error('Not silme hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// ----------------- PAYLAŞIM (KASA DIŞI) -----------------

// Dosya paylaşma (kullanıcıya veya kod ile)
app.post('/share_file', async (req, res) => {
  try {
    const {
      fromUserId,
      mode, // 'direct' veya 'code'
      targetUsername,
      encryptedContent,
      iv,
      contentType,
      fileName,
    } = req.body;

    if (!fromUserId || !mode || !encryptedContent || !iv || !contentType) {
      return res.status(400).send({ message: 'Zorunlu alanlar eksik.' });
    }

    const fromUser = await User.findById(fromUserId);
    if (!fromUser) {
      return res.status(404).send({ message: 'Gönderen kullanıcı bulunamadı.' });
    }

    // 1) Kullanıcıya direkt gönder
    if (mode === 'direct') {
      if (!targetUsername) {
        return res
          .status(400)
          .send({ message: 'Direct paylaşım için targetUsername zorunlu.' });
      }

      const targetUser = await User.findOne({ username: targetUsername });
      if (!targetUser) {
        return res.status(404).send({ message: 'Hedef kullanıcı bulunamadı.' });
      }

      const shared = new SharedFile({
        fromUserId: fromUser._id,
        toUserId: targetUser._id,
        mode: 'direct',
        encryptedContent,
        iv,
        contentType,
        fileName,
      });

      await shared.save();

      io.to(targetUser._id.toString()).emit('inbox_updated');

      return res.status(201).send({ message: 'Dosya kullanıcıya gönderildi.' });
    }

    // 2) Kod ile paylaşım
    if (mode === 'code') {
      const shareCode = crypto.randomBytes(4).toString('hex'); // 8 karakter

      const shared = new SharedFile({
        fromUserId: fromUser._id,
        toUserId: null,
        mode: 'code',
        shareCode,
        encryptedContent,
        iv,
        contentType,
        fileName,
      });

      await shared.save();

      return res.status(201).send({
        message: 'Kod ile paylaşım oluşturuldu.',
        code: shareCode,
      });
    }

    return res.status(400).send({ message: 'Geçersiz mode.' });
  } catch (err) {
    console.error('share_file hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// Kullanıcıya gelen paylaşımlar (gelen kutusu)
app.get('/inbox/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const items = await SharedFile.find({ toUserId: userId })
      .sort({ createdAt: -1 })
      .populate('fromUserId', 'username fullName');

    res.send({ items });
  } catch (err) {
    console.error('inbox hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// Kod ile paylaşılan dosyayı bulma
app.get('/shared_by_code/:code', async (req, res) => {
  try {
    const { code } = req.params;
    if (!code) {
      return res.status(400).send({ message: 'Kod zorunlu.' });
    }

    const shared = await SharedFile.findOne({ shareCode: code });
    if (!shared) {
      return res.status(404).send({ message: 'Bu koda ait paylaşım yok.' });
    }

    res.send({
      item: {
        _id: shared._id,
        encryptedContent: shared.encryptedContent,
        iv: shared.iv,
        contentType: shared.contentType,
        fileName: shared.fileName,
        createdAt: shared.createdAt,
      },
    });
  } catch (err) {
    console.error('shared_by_code hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// Gelen kutusundaki paylaşılan dosyayı silme
app.delete('/inbox_item/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const deleted = await SharedFile.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).send({ message: 'Gelen dosya bulunamadı.' });
    }

    if (deleted.toUserId) {
      io.to(deleted.toUserId.toString()).emit('inbox_updated');
    }

    res.send({ message: 'Gelen dosya silindi.' });
  } catch (err) {
    console.error('inbox_item silme hatası:', err);
    res.status(500).send({ message: 'Sunucu hatası' });
  }
});

// ----------------- SUNUCU -----------------

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Sunucu çalışıyor: http://localhost:${PORT}`);
});
