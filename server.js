require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');
const bodyParser = require('body-parser');
const http = require('http');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const app = express();

/* -------------------- MIDDLEWARE -------------------- */
app.use(express.json({ limit: '100mb' }));
app.use(bodyParser.json({ limit: '100mb' }));
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

/* -------------------- RATE LIMIT -------------------- */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
});

/* -------------------- SOCKET -------------------- */
io.on('connection', (socket) => {
  socket.on('join', (userId) => userId && socket.join(userId));
});

/* -------------------- DB -------------------- */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(() => process.exit(1));

/* -------------------- MODELS -------------------- */
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, lowercase: true, trim: true },
  fullName: String,
  salt: String,
  hash: String,
});
const User = mongoose.model('User', UserSchema);

const NoteSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  encryptedContent: String,
  iv: String,
  contentType: String,
  fileName: String,
  label: String,
  createdAt: { type: Date, default: Date.now },
});
const Note = mongoose.model('Note', NoteSchema);

const SharedFileSchema = new mongoose.Schema({
  fromUserId: mongoose.Schema.Types.ObjectId,
  toUserId: mongoose.Schema.Types.ObjectId,
  mode: String,
  shareCode: String,
  encryptedContent: String,
  iv: String,
  contentType: String,
  fileName: String,
  expiresAt: Date,
  createdAt: { type: Date, default: Date.now },
});
const SharedFile = mongoose.model('SharedFile', SharedFileSchema);

/* -------------------- HELPERS -------------------- */
function isPasswordValid(p) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/.test(p);
}

// SHA256 + ITERATION (hocaya uygun)
function hashPassword(password, salt, iterations = 100000) {
  let hash = password + salt;
  for (let i = 0; i < iterations; i++) {
    hash = crypto.createHash('sha256').update(hash).digest('hex');
  }
  return hash;
}

/* -------------------- AUTH -------------------- */
app.post('/register', async (req, res) => {
  const username = req.body.username.trim().toLowerCase();
  const { password, fullName } = req.body;

  if (!isPasswordValid(password)) {
    return res.status(400).send({ message: 'Şifre zayıf' });
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);

  await new User({ username, fullName, salt, hash }).save();
  res.send({ message: 'Kayıt başarılı' });
});

app.post('/login', authLimiter, async (req, res) => {
  const username = req.body.username.trim().toLowerCase();
  const { password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(401).send({ message: 'Hatalı bilgi' });

  const hash = hashPassword(password, user.salt);
  if (hash !== user.hash) return res.status(401).send({ message: 'Hatalı bilgi' });

  res.send({ userId: user._id, fullName: user.fullName, salt: user.salt });
});

/* -------------------- CHANGE PASSWORD (SALT SABİT) -------------------- */
app.post('/change_password', authLimiter, async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;

  if (!isPasswordValid(newPassword)) {
    return res.status(400).send({ message: 'Yeni şifre zayıf' });
  }

  const user = await User.findById(userId);
  if (!user) return res.status(404).send({ message: 'Kullanıcı yok' });

  const oldHash = hashPassword(oldPassword, user.salt);
  if (oldHash !== user.hash) {
    return res.status(401).send({ message: 'Eski şifre hatalı' });
  }

  // SALT DEĞİŞMİYOR
  user.hash = hashPassword(newPassword, user.salt);
  await user.save();

  res.send({ message: 'Şifre değiştirildi' });
});

/* -------------------- DELETE ACCOUNT -------------------- */
app.delete('/delete_account/:userId', async (req, res) => {
  const { userId } = req.params;

  await Note.deleteMany({ userId });
  await SharedFile.deleteMany({ $or: [{ fromUserId: userId }, { toUserId: userId }] });
  await User.findByIdAndDelete(userId);

  io.to(userId).emit('account_deleted');
  res.send({ message: 'Hesap silindi' });
});

/* -------------------- NOTES -------------------- */
app.post('/save_note', async (req, res) => {
  const note = await new Note(req.body).save();
  io.to(req.body.userId).emit('notes_updated');
  res.send({ noteId: note._id });
});

app.get('/get_notes/:userId', async (req, res) => {
  const { userId } = req.params;
  const page = parseInt(req.query.page || 1);
  const limit = parseInt(req.query.limit || 1000);

  const notes = await Note.find({ userId })
    .sort({ createdAt: -1 })
    .skip((page - 1) * limit)
    .limit(limit);

  const total = await Note.countDocuments({ userId });
  res.send({ notes, total, page, limit });
});

app.put('/update_note/:id', async (req, res) => {
  const { userId, encryptedContent, iv } = req.body;
  const note = await Note.findOneAndUpdate(
    { _id: req.params.id, userId },
    { encryptedContent, iv },
    { new: true }
  );

  if (!note) return res.status(404).send({ message: 'Not yok' });
  io.to(userId).emit('notes_updated');
  res.send({ message: 'Not güncellendi' });
});

app.delete('/delete_note/:id', async (req, res) => {
  const note = await Note.findByIdAndDelete(req.params.id);
  if (note) io.to(note.userId.toString()).emit('notes_updated');
  res.send({ message: 'Not silindi' });
});

/* -------------------- SHARE -------------------- */
app.post('/share_file', async (req, res) => {
  const { fromUserId, mode, targetUsername } = req.body;

  if (mode === 'direct') {
    const target = await User.findOne({ username: targetUsername.toLowerCase() });
    await new SharedFile({ ...req.body, toUserId: target._id }).save();
    io.to(target._id.toString()).emit('inbox_updated');
    return res.send({ message: 'Gönderildi' });
  }

  const code = crypto.randomBytes(4).toString('hex');
  await new SharedFile({
    ...req.body,
    mode: 'code',
    shareCode: code,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
  }).save();

  res.send({ code });
});

app.get('/shared_by_code/:code', async (req, res) => {
  const item = await SharedFile.findOne({ shareCode: req.params.code });
  if (!item || item.expiresAt < new Date()) {
    return res.status(410).send({ message: 'Kod süresi dolmuş' });
  }
  res.send({ item });
});

/* -------------------- SERVER -------------------- */
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on ${PORT}`));
