const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors());

// Secret key for JWT
const SECRET = "secretkey";

// Connect DB
const db = new sqlite3.Database("./database.db", (err) => {
    if (err) console.error(err.message);
    else console.log("Database connected");
});

// ================== TABLES ==================

db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT
)
`);

db.run(`
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    date TEXT
)
`);

db.run(`
CREATE TABLE IF NOT EXISTS registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_id INTEGER
)
`);

db.run(`
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT
)
`);

// ================== TEST ==================

app.get("/", (req, res) => {
    res.send("Event Registration API Running 🚀");
});

// ================== AUTH MIDDLEWARE ==================

function authMiddleware(req, res, next) {
    const token = req.headers["authorization"];

    if (!token) {
        return res.status(401).json({ error: "Access denied" });
    }

    try {
        const verified = jwt.verify(token, SECRET);
        req.admin = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: "Invalid token" });
    }
}

// ================== ADMIN AUTH ==================

// Signup
app.post("/admin/signup", async (req, res) => {
    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
        `INSERT INTO admins (email, password) VALUES (?, ?)`,
        [email, hashedPassword],
        function (err) {
            if (err) {
                return res.status(500).json({ error: "Admin already exists" });
            }

            res.json({ message: "Admin created" });
        }
    );
});

// Login
app.post("/admin/login", (req, res) => {
    const { email, password } = req.body;

    db.get(
        `SELECT * FROM admins WHERE email = ?`,
        [email],
        async (err, admin) => {
            if (!admin) {
                return res.status(400).json({ error: "Invalid credentials" });
            }

            const valid = await bcrypt.compare(password, admin.password);

            if (!valid) {
                return res.status(400).json({ error: "Invalid credentials" });
            }

            const token = jwt.sign(
                { id: admin.id },
                SECRET,
                { expiresIn: "1h" }
            );

            res.json({ token });
        }
    );
});

// ================== EVENTS ==================

// Create event (protected)
app.post("/events", authMiddleware, (req, res) => {
    const { title, description, date } = req.body;

    db.run(
        `INSERT INTO events (title, description, date) VALUES (?, ?, ?)`,
        [title, description, date],
        function (err) {
            if (err) return res.status(500).json(err);

            res.json({
                message: "Event created",
                eventId: this.lastID
            });
        }
    );
});

// Get all events
app.get("/events", (req, res) => {
    db.all(`SELECT * FROM events`, [], (err, rows) => {
        if (err) return res.status(500).json(err);
        res.json(rows);
    });
});

// Get event by ID
app.get("/events/:id", (req, res) => {
    db.get(
        `SELECT * FROM events WHERE id = ?`,
        [req.params.id],
        (err, row) => {
            if (err) return res.status(500).json(err);

            if (!row) {
                return res.status(404).json({ message: "Event not found" });
            }

            res.json(row);
        }
    );
});

// ================== USERS ==================

// Create user
app.post("/users", (req, res) => {
    const { name, email } = req.body;

    db.run(
        `INSERT INTO users (name, email) VALUES (?, ?)`,
        [name, email],
        function (err) {
            if (err) return res.status(500).json(err);

            res.json({
                message: "User created",
                userId: this.lastID
            });
        }
    );
});

// ================== REGISTRATION ==================

// Register user
app.post("/register", (req, res) => {
    const { user_id, event_id } = req.body;

    db.run(
        `INSERT INTO registrations (user_id, event_id) VALUES (?, ?)`,
        [user_id, event_id],
        function (err) {
            if (err) return res.status(500).json(err);

            res.json({
                message: "Registered successfully"
            });
        }
    );
});

// View registrations
app.get("/registrations/:userId", (req, res) => {
    db.all(
        `
        SELECT events.id, events.title, events.date
        FROM registrations
        JOIN events ON registrations.event_id = events.id
        WHERE registrations.user_id = ?
        `,
        [req.params.userId],
        (err, rows) => {
            if (err) return res.status(500).json(err);
            res.json(rows);
        }
    );
});

// Cancel registration
app.delete("/register", (req, res) => {
    const { user_id, event_id } = req.body;

    db.run(
        `DELETE FROM registrations WHERE user_id = ? AND event_id = ?`,
        [user_id, event_id],
        function (err) {
            if (err) return res.status(500).json(err);

            res.json({
                message: "Registration cancelled"
            });
        }
    );
});

// ================== START ==================

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});