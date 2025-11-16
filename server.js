// server.js
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "YOUR_SUPER_SECRET_KEY_CHANGE_THIS"; // IMPORTANT: Use a long, random string

app.use(cors());
app.use(express.json());

// --- MOCK DATABASE ---
// In a real app, use a database like MongoDB or PostgreSQL
let usersDB = []; // Stores { id, username, passwordHash }
let keysDB = {
  "SNEAK-PEEK-123": {
    duration_ms: 10 * 1000,
    isUsed: false,
    activatedByUserId: null,
    expiration_timestamp: null,
  },
  "DAILY-TRIAL-456": {
    duration_ms: 2 * 24 * 60 * 60 * 1000,
    isUsed: false,
    activatedByUserId: null,
    expiration_timestamp: null,
  },
  "MONTHLY-SUB-789": {
    duration_ms: 30 * 24 * 60 * 60 * 1000,
    isUsed: false,
    activatedByUserId: null,
    expiration_timestamp: null,
  },
};

// --- AUTHENTICATION ENDPOINTS ---

// 1. User Registration
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res
      .status(400)
      .json({ message: "Username and password are required." });
  if (usersDB.find((u) => u.username === username))
    return res.status(409).json({ message: "Username already exists." });

  const passwordHash = await bcrypt.hash(password, 10);
  const newUser = { id: usersDB.length + 1, username, passwordHash };
  usersDB.push(newUser);
  console.log("Users DB:", usersDB);
  res.status(201).json({ message: "User registered successfully." });
});

// 2. User Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = usersDB.find((u) => u.username === username);
  if (!user) return res.status(401).json({ message: "Invalid credentials." });

  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch)
    return res.status(401).json({ message: "Invalid credentials." });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: "7d",
  });
  res.json({ message: "Login successful.", token });
});

// --- MIDDLEWARE TO PROTECT ROUTES ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Format: "Bearer TOKEN"
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token
    req.user = user;
    next();
  });
}

// --- SECURE ACTIVATION ENDPOINT ---
app.post("/api/activate", authenticateToken, (req, res) => {
  const { key } = req.body;
  const userId = req.user.id; // Get user ID from the verified JWT

  // Check if user already has an active key
  const existingKey = Object.values(keysDB).find(
    (k) => k.activatedByUserId === userId && k.expiration_timestamp > Date.now()
  );
  if (existingKey) {
    return res.status(409).json({ message: "You already have an active key." });
  }

  const keyData = keysDB[key.toUpperCase()];
  if (!keyData) return res.status(404).json({ message: "Invalid serial key." });
  if (keyData.isUsed)
    return res.status(403).json({ message: "This key has already been used." });

  // Activate the key: Lock it to the user
  keyData.isUsed = true;
  keyData.activatedByUserId = userId;
  keyData.expiration_timestamp = Date.now() + keyData.duration_ms;

  console.log("Keys DB updated:", keysDB);
  res.json({
    status: "success",
    message: `Key activated! Expires at ${new Date(
      keyData.expiration_timestamp
    ).toLocaleString()}`,
  });
});

// --- STATUS CHECK ENDPOINT ---
// The dashboard will call this to verify the session and key status
app.get("/api/status", authenticateToken, (req, res) => {
  const userId = req.user.id;
  const activeKey = Object.values(keysDB).find(
    (k) => k.activatedByUserId === userId && k.expiration_timestamp > Date.now()
  );

  if (activeKey) {
    res.json({
      isLoggedIn: true,
      isActivated: true,
      username: req.user.username,
      expires: activeKey.expiration_timestamp,
    });
  } else {
    res.json({
      isLoggedIn: true,
      isActivated: false,
      username: req.user.username,
    });
  }
});
// --- HEALTH CHECK / PING ENDPOINT ---
// This is the dedicated URL that UptimeRobot will hit.
app.get("/ping", (req, res) => {
  // It simply sends back a success response.
  res.status(200).json({
    status: "ok",
    message: "Server is awake and running.",
  });
});
app.listen(PORT, () =>
  console.log(`Secure server running on http://localhost:${PORT}`)
);
