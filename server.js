// server.js (FINAL, FRONTEND İLE UYUMLU)

require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------- MONGODB BAĞLANTISI -----------------
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB bağlantısı başarılı'))
  .catch((err) => {
    console.error('❌ MongoDB bağlantı hatası:', err);
    process.exit(1);
  });

// ----------------- ŞEMALAR -----------------
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  fullName: { type: String, required: true },
  salt: { type: String, required: true },
  hash: { type: String, required: true },
});

const User = mongoose.model('User', UserSchema);

const NoteSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  encryptedContent: { type: String, required: true },
  iv: { type: String, required: true },
  contentType: { type: String, required: true }, // image / video / pdf / text
  fileName: { type: String },
  label: { type: String, default: null },        // not etiketleri: İş / Okul / ...
  createdAt: { type: Date, default: Date.now },
});

const Note = mongoose.model('Note', NoteSchema);

// ----------------- MIDDLEWARE -----------------
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));

// ----------------- KRİPTO FONKSİYONU -----------------
function hashPassword(password, salt = null) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .createHash('sha256')
    .update(password + salt)
    .digest('hex');
  return { salt, hash };
}

// ----------------- ENDPOINTLER -----------------

// Kayıt
app.post('/register', async (req, res) => {
  try {
    const { username, password, fullName } = req.body;

    if (!username || !password || !fullName) {
      return res.status(400).send({ message: 'Eksik alanlar var.' });
    }

    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(409).send({ message: 'Kullanıcı adı mevcut.' });
    }

    const { salt, hash } = hashPassword(password);
    await new User({ username, fullName, salt, hash }).save();

    res.status(201).send({ message: 'Kayıt başarılı!' });
  } catch (err) {
    console.error('register error:', err);
    res.status(500).send({ message: 'Sunucu hatası.' });
  }
});

// Giriş
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).send({ message: 'Eksik alanlar var.' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).send({ message: 'Hatalı bilgiler.' });
    }

    const { hash } = hashPassword(password, user.salt);
    if (hash !== user.hash) {
      return res.status(401).send({ message: 'Hatalı bilgiler.' });
    }

    res.send({
      message: 'Giriş başarılı',
      userId: user._id,
      fullName: user.fullName,
      salt: user.salt,
    });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).send({ message: 'Sunucu hatası.' });
  }
});

// Veri / Dosya Yükleme
app.post('/save_note', async (req, res) => {
  try {
    const {
      userId,
      encryptedContent,
      iv,
      contentType,
      fileName,
      label, // opsiyonel
    } = req.body;

    if (!userId || !encryptedContent || !iv || !contentType) {
      return res.status(400).send({ message: 'Eksik veri.' });
    }

    const note = new Note({
      userId,
      encryptedContent,
      iv,
      contentType,
      fileName,
      label: label || null,
    });

    await note.save();
    res.status(201).send({ message: 'Kaydedildi', noteId: note._id });
  } catch (err) {
    console.error('save_note error:', err);
    res.status(500).send({ message: 'Sunucu hatası.' });
  }
});

// Veri Listeleme (isteğe bağlı sayfalama)
app.get('/get_notes/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    // ?page=1&limit=20 gibi kullanabilirsin
    const page = parseInt(req.query.page || '1', 10);
    const limit = parseInt(req.query.limit || '1000', 10); // frontend şu an limit göndermiyor
    const skip = (page - 1) * limit;

    const [notes, total] = await Promise.all([
      Note.find({ userId }).sort({ createdAt: -1 }).skip(skip).limit(limit),
      Note.countDocuments({ userId }),
    ]);

    const totalPages = Math.ceil(total / limit);

    res.send({ notes, page, totalPages, total });
  } catch (err) {
    console.error('get_notes error:', err);
    res.status(500).send({ message: 'Sunucu hatası.' });
  }
});

// Veri Silme
app.delete('/delete_note/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await Note.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).send({ message: 'Not bulunamadı.' });
    }
    res.send({ message: 'Silindi' });
  } catch (err) {
    console.error('delete_note error:', err);
    res.status(500).send({ message: 'Sunucu hatası.' });
  }
});

// Şifre Değiştirme
app.post('/change_password', async (req, res) => {
  try {
    const { userId, oldPassword, newPassword } = req.body;
    if (!userId || !oldPassword || !newPassword) {
      return res.status(400).send({ message: 'Eksik alanlar var.' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send({ message: 'Kullanıcı bulunamadı.' });
    }

    const { hash: oldHash } = hashPassword(oldPassword, user.salt);
    if (oldHash !== user.hash) {
      return res.status(403).send({ message: 'Eski şifre hatalı.' });
    }

    const { salt, hash } = hashPassword(newPassword);
    user.salt = salt;
    user.hash = hash;
    await user.save();

    res.send({ message: 'Şifre güncellendi.' });
  } catch (err) {
    console.error('change_password error:', err);
    res.status(500).send({ message: 'Sunucu hatası.' });
  }
});

// Hesabı Kalıcı Olarak Sil (kullanıcı + tüm notlar)
app.delete('/delete_account/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send({ message: 'Kullanıcı bulunamadı.' });
    }

    await Note.deleteMany({ userId });
    await User.deleteOne({ _id: userId });

    res.send({ message: 'Kullanıcı ve tüm notlar silindi.' });
  } catch (err) {
    console.error('delete_account error:', err);
    res.status(500).send({ message: 'Sunucu hatası.' });
  }
});

// ----------------- SUNUCU BAŞLAT -----------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
