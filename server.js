// server.js (FINAL VERSION)

require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB Bağlantısı
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Bağlantısı Başarılı"))
  .catch(err => { console.error(err); process.exit(1); });


// --- ŞEMALAR --- //
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  fullName: { type: String, required: true },
  salt: { type: String, required: true },
  hash: { type: String, required: true },
});
const User = mongoose.model("User", UserSchema);

const NoteSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  encryptedContent: { type: String, required: true },
  iv: { type: String, required: true },
  contentType: { type: String, required: true },
  fileName: { type: String },
  createdAt: { type: Date, default: Date.now },
});
const Note = mongoose.model("Note", NoteSchema);


// --- MIDDLEWARE --- //
app.use(cors());
app.use(bodyParser.json({ limit: "100mb" }));
app.use(bodyParser.urlencoded({ limit: "100mb", extended: true }));


// --- KRİPTO FONKSİYONLARI --- //
function hashPassword(password, salt = null) {
  salt = salt || crypto.randomBytes(16).toString("hex");
  const hash = crypto.createHash("sha256")
    .update(password + salt)
    .digest("hex");
  return { salt, hash };
}

// --- ENDPOINTLER --- //

// Kayıt
app.post("/register", async (req, res) => {
  const { username, password, fullName } = req.body;
  if (!username || !password || !fullName)
    return res.status(400).send({ message: "Eksik alanlar var." });

  const exists = await User.findOne({ username });
  if (exists)
    return res.status(409).send({ message: "Kullanıcı adı mevcut." });

  const { salt, hash } = hashPassword(password);
  await new User({ username, fullName, salt, hash }).save();

  res.status(201).send({ message: "Kayıt başarılı!" });
});

// Giriş
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) return res.status(401).send({ message: "Hatalı bilgiler." });

  const { hash } = hashPassword(password, user.salt);
  if (hash !== user.hash)
    return res.status(401).send({ message: "Hatalı bilgiler." });

  res.send({
    message: "Giriş başarılı",
    userId: user._id,
    fullName: user.fullName,
    salt: user.salt,
  });
});

// Veri / Dosya Yükleme
app.post("/save_note", async (req, res) => {
  const { userId, encryptedContent, iv, contentType, fileName } = req.body;
  if (!userId || !encryptedContent || !iv || !contentType)
    return res.status(400).send({ message: "Eksik veri" });

  await new Note({ userId, encryptedContent, iv, contentType, fileName }).save();
  res.status(201).send({ message: "Kaydedildi" });
});

// Veri Listeleme
app.get("/get_notes/:userId", async (req, res) => {
  const notes = await Note.find({ userId: req.params.userId }).sort({ createdAt: -1 });
  res.send({ notes });
});

// Veri Silme
app.delete("/delete_note/:id", async (req, res) => {
  await Note.findByIdAndDelete(req.params.id);
  res.send({ message: "Silindi" });
});

// Şifre Değiştirme
app.post("/change_password", async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;
  const user = await User.findById(userId);

  const { hash } = hashPassword(oldPassword, user.salt);
  if (hash !== user.hash)
    return res.status(403).send({ message: "Eski şifre hatalı" });

  const newHashed = hashPassword(newPassword);
  user.hash = newHashed.hash;
  user.salt = newHashed.salt;
  await user.save();

  res.send({ message: "Şifre güncellendi." });
});

// Sunucu başlat
app.listen(PORT, () => console.log("Server Running → " + PORT));
