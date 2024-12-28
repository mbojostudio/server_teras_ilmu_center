const express = require("express");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const session = require("express-session");
const path = require("path");
const multer = require("multer");
const fs = require('fs');
const bcrypt = require("bcrypt");
const axios = require('axios');
const crypto = require('crypto');

// Setup multer untuk menangani unggahan file
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
require('dotenv').config();

const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'), // Perhatikan penggantian karakter \n
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
};
// Inisialisasi Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://fbuses-3e232-default-rtdb.firebaseio.com/", // Ganti sesuai databaseURL Firebase Anda
});
// Set up multer untuk menyimpan file di server

const db = admin.database();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());


const cors = require("cors");
app.use(cors());

// Middleware untuk memproses JSON
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware session
app.use(
  session({
    secret: "iniadalahprojectujicoba", // Ganti dengan key rahasia
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 3600000, secure: false }, // Cookie aktif selama 1 jam
  })
);



// Endpoint untuk signup
app.post("/signup", async (req, res) => {
  const { email, username, password } = req.body;

  // Validasi data
  if (!email || !username || !password) {
    return res.status(400).json({ error: "Semua field harus diisi!" });
  }

  try {
    const usersRef = db.ref("users");

    // Cek jika email sudah terdaftar
    const snapshot = await usersRef.orderByChild("email").equalTo(email).once("value");
    if (snapshot.exists()) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate ID unik untuk pengguna baru
    const newUserId = usersRef.push().key;

    // Simpan data pengguna ke Firebase
    const newUser = {
      id: newUserId,
      email,
      password: hashedPassword,
      username,
      profilePicture: "",
    };

    await usersRef.child(newUserId).set(newUser);
    res.status(201).json({ message: "Signup successful", userId: newUserId });
  } catch (error) {
    console.error("Error signing up:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});


// Endpoint Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  try {
    const usersRef = db.ref("users");
    const snapshot = await usersRef.orderByChild("email").equalTo(email).once("value");

    if (!snapshot.exists()) {
      return res.status(404).json({ message: "User not found." });
    }

    const userData = Object.values(snapshot.val())[0];

    // Periksa password yang di-hash
    const isPasswordValid = await bcrypt.compare(password, userData.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Incorrect password." });
    }

    res.status(200).json({ 
      message: "Login successful", 
      userId: userData.id,
      name: userData.username
    });
    
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});



// Endpoint untuk logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Gagal logout!" });
    }
    res.status(200).json({ message: "Logout berhasil!" });
  });
});


// Endpoint untuk mengambil data profil pengguna dari Firebase
app.get("/getUserProfile/:username", async (req, res) => {
  const username = req.params.username;

  try {
    const userRef = db.ref(`users/${username}`);
    const snapshot = await userRef.once("value");

    if (!snapshot.exists()) {
      return res.status(404).json({ success: false, message: "Pengguna tidak ditemukan" });
    }

    const userData = snapshot.val();
    res.json({
      success: true,
      username,
      imageUrl: userData.profileImageUrl || "",
    });
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({ success: false, message: "Terjadi kesalahan pada server" });
  }
});

// Middleware untuk melayani file statis (gambar yang diunggah)
app.use("/uploads", express.static(path.join(__dirname, "uploads")));


app.get('/users/:userId/profile-picture', async (req, res) => {
  const userId = req.params.userId;

  try {
    const usersRef = db.ref("users");
    const snapshot = await usersRef.child(userId).once("value");

    if (!snapshot.exists()) {
      return res.status(404).json({ message: "User not found." });
    }

    const userData = snapshot.val();
    const profilePictureUrl = userData.profilePicture;

    if (!profilePictureUrl) {
      return res.status(404).json({ message: "Profile picture not found." });
    }

    // Redirect or proxy the image
    res.redirect(profilePictureUrl);
  } catch (error) {
    console.error("Error fetching profile picture:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Setup GitHub API token dan repositori
const githubToken = process.env.GITHUB_PAT; // Ganti dengan token GitHub Anda

const githubApiUrl = (userId) => `https://api.github.com/repos/mbojostudio/data-profile-user/contents/${userId}.jpg`;

app.post('/users/:userId/edit-profile', upload.single('image'), async (req, res) => {
  const { userId } = req.params;
  const imageFile = req.file;

  try {
    const usersRef = db.ref(`users/${userId}`);
    const snapshot = await usersRef.once("value");

    if (!snapshot.exists()) {
      return res.status(404).json({ message: "User not found." });
    }

    const userData = snapshot.val();
    let profilePictureUrl = userData.profilePicture;

    if (imageFile) {
      const fileBuffer = imageFile.buffer;
      const base64Content = fileBuffer.toString('base64');

      // Langkah 1: Dapatkan metadata file untuk mendapatkan "sha"
      const fileUrl = githubApiUrl(userId);
      let sha = null;
      try {
        const fileMetadata = await axios.get(fileUrl, {
          headers: {
            Authorization: `token ${githubToken}`,
            Accept: 'application/vnd.github.v3+json',
          },
        });
        sha = fileMetadata.data.sha; // Dapatkan "sha" file yang ada
      } catch (error) {
        if (error.response?.status !== 404) {
          throw error; // Jika error bukan karena file tidak ditemukan, lempar error
        }
      }

      // Langkah 2: Upload file ke GitHub (dengan atau tanpa "sha")
      const response = await axios.put(fileUrl, {
        message: `Upload profile picture for ${userId}`,
        content: base64Content,
        ...(sha && { sha }), // Sertakan "sha" jika file sudah ada
      }, {
        headers: {
          Authorization: `token ${githubToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });

      if (response.status === 200 || response.status === 201) {
        profilePictureUrl = `https://raw.githubusercontent.com/mbojostudio/data-profile-user/main/${userId}.jpg`;
      } else {
        return res.status(500).json({ message: "Failed to upload image to GitHub." });
      }
    }

    await usersRef.update({ profilePicture: profilePictureUrl });

    res.status(200).json({
      message: "Profile updated successfully.",
      profilePicture: profilePictureUrl,
      username: userData.username,
    });
  } catch (error) {
    console.error("Error updating profile:", error.response?.data || error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});


// Endpoint untuk menyimpan postingan
app.post('/api/post', async (req, res) => {
  const { userId, content, image } = req.body;

  // Validasi input
  if (!userId || (!content && !image)) {
    return res.status(400).json({ message: 'Invalid data' });
  }

  try {
    // Ambil data user berdasarkan userId
    const userRef = admin.database().ref(`users/${userId}`);
    const userSnapshot = await userRef.once('value');

    if (!userSnapshot.exists()) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userData = userSnapshot.val();

    // Tambahkan properti likes dan comments
    const post = {
      userId,
      username: userData.username,
      profilePicture: userData.profilePicture,
      content,
      image,
      timestamp: Date.now(),
      likes: 0, // Properti likes default 0
      comments: [], // Properti comments sebagai array kosong
    };

    // Simpan postingan ke database
    const postRef = admin.database().ref('posts').push();
    await postRef.set(post);

    res.status(200).json({
      message: 'Post created successfully',
      postId: postRef.key,
      post,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// Endpoint untuk mengambil postingan
app.get('/api/posts', async (req, res) => {
  try {
    const postsRef = admin.database().ref('posts');
    const postsSnapshot = await postsRef.once('value');

    const posts = [];
    postsSnapshot.forEach((child) => {
      posts.push({ id: child.key, ...child.val() });
    });

    res.status(200).json(posts);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



// Fungsi untuk handle like
app.post('/like', async (req, res) => {
  const { postId, userId } = req.body;

  if (!postId || !userId) {
    return res.status(400).json({ message: 'postId dan userId diperlukan.' });
  }

  try {
    const postRef = db.ref(`posts/${postId}`);
    const postSnapshot = await postRef.once('value');

    if (!postSnapshot.exists()) {
      return res.status(404).json({ message: 'Postingan tidak ditemukan.' });
    }

    const likesRef = db.ref(`postLikes/${postId}/${userId}`);
    const likeSnapshot = await likesRef.once('value');

    if (likeSnapshot.exists()) {
      // Jika sudah like, batalkan like
      await likesRef.remove();
      await postRef.child('likes').transaction((currentLikes) => (currentLikes || 0) - 1);

      return res.status(200).json({ message: 'Like dibatalkan.' });
    } else {
      // Jika belum like, tambahkan like
      await likesRef.set(true);
      await postRef.child('likes').transaction((currentLikes) => (currentLikes || 0) + 1);

      return res.status(200).json({ message: 'Like berhasil ditambahkan.' });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Terjadi kesalahan.' });
  }
});



// Jalankan server
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
  });
  