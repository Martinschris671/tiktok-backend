const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "YOUR_SUPER_SECRET_KEY_CHANGE_THIS_IN_RENDER";

app.use(cors());
app.use(express.json());

// --- MOCK DATABASE ---
// In a real app, use a database like MongoDB or PostgreSQL
let usersDB = []; // Stores { id, email, passwordHash }
let keysDB = {
  "SNEAK-PEEK-123": {
    duration_ms: 3 * 60 * 1000,
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

// --- HELPER FUNCTION FOR EMAIL VALIDATION ---
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// --- AUTHENTICATION ENDPOINTS ---

// 1. User Registration (Now with strong validation)
app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // --- Validation Checks ---
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required." });
    }
    if (!isValidEmail(email)) {
      return res
        .status(400)
        .json({ message: "Please enter a valid email address." });
    }
    if (password.length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters long." });
    }
    if (usersDB.find((u) => u.email.toLowerCase() === email.toLowerCase())) {
      return res
        .status(409)
        .json({ message: "This email address is already in use." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = {
      id: usersDB.length + 1,
      email: email.toLowerCase(),
      passwordHash,
    };
    usersDB.push(newUser);

    console.log("New user registered:", newUser.email);
    res
      .status(201)
      .json({ message: "Account created successfully. You can now log in." });
  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({ message: "An internal server error occurred." });
  }
});

// 2. User Login (Secure and robust)
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required." });
    }

    const user = usersDB.find(
      (u) => u.email.toLowerCase() === email.toLowerCase()
    );
    // Security: Use the same error message for non-existent user or wrong password
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });
    res.json({ message: "Login successful.", token });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "An internal server error occurred." });
  }
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
app.get("/api/status", authenticateToken, (req, res) => {
  const userId = req.user.id;
  const activeKey = Object.values(keysDB).find(
    (k) => k.activatedByUserId === userId && k.expiration_timestamp > Date.now()
  );

  if (activeKey) {
    res.json({
      isLoggedIn: true,
      isActivated: true,
      email: req.user.email,
      expires: activeKey.expiration_timestamp,
    });
  } else {
    res.json({ isLoggedIn: true, isActivated: false, email: req.user.email });
  }
});

app.listen(PORT, () =>
  console.log(`Secure server running on http://localhost:${PORT}`)
);
