const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize SQLite Database
const dbPath = path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstName TEXT NOT NULL,
            lastName TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            userId TEXT UNIQUE NOT NULL,
            phone TEXT,
            password TEXT NOT NULL
        )`);
    }
});

// Register Endpoint
app.post('/api/register', async (req, res) => {
    const { firstName, lastName, role, email, userId, phone, password } = req.body;

    if (!firstName || !lastName || !role || !email || !userId || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO users (firstName, lastName, role, email, userId, phone, password) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        
        db.run(sql, [firstName, lastName, role, email, userId, phone, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({ error: 'Email or User ID already exists' });
                }
                return res.status(500).json({ error: 'Database error' });
            }
            res.status(201).json({ message: 'User registered successfully', id: this.lastID });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Login Endpoint
app.post('/api/login', (req, res) => {
    const { loginId, password, role } = req.body;

    if (!loginId || !password || !role) {
        return res.status(400).json({ error: 'Login ID, password, and role are required' });
    }

    // Login ID can be either email or userId
    const sql = `SELECT * FROM users WHERE (email = ? OR userId = ?) AND role = ?`;
    
    db.get(sql, [loginId, loginId, role], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials or incorrect role' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (match) {
            // In a real app, generate a JWT token here
            res.status(200).json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    role: user.role,
                    email: user.email
                }
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
