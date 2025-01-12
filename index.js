const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("@node-rs/bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// PostgreSQL Connection
require("dotenv").config();
const SECRET_KEY = process.env.SECRET_KEY;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// JWT Secret
//const SECRET_KEY = "password";

// User Authentication Middleware
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("Access Denied");

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).send("Invalid Token");
    req.user = user;
    next();
  });
}

// Routes

// User Signup
app.post("/signup", async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)",
      [name, email, hashedPassword, role]
    );
    res.status(201).send("User created successfully.");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// User Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(400).send("User not found");

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).send("Invalid password");

    const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY);
    res.json({ token });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Get All Cases (Admin & Lawyer)
app.get("/cases", authenticate, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM cases");
    res.json(result.rows);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Add a New Case (Admin Only)
app.post("/cases", authenticate, async (req, res) => {
  const { case_number, parties, registration_date, status } = req.body;
  if (req.user.role !== "Admin") return res.status(403).send("Access Denied");

  try {
    await pool.query(
      "INSERT INTO cases (case_number, parties, registration_date, status) VALUES ($1, $2, $3, $4)",
      [case_number, parties, registration_date, status]
    );
    res.status(201).send("Case added successfully.");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Update a Case
app.put("/cases/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const { case_number, parties, registration_date, status } = req.body;

  try {
    await pool.query(
      "UPDATE cases SET case_number = $1, parties = $2, registration_date = $3, status = $4 WHERE id = $5",
      [case_number, parties, registration_date, status, id]
    );
    res.send("Case updated successfully.");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Delete a Case (Admin Only)
app.delete("/cases/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  if (req.user.role !== "Admin") return res.status(403).send("Access Denied");

  try {
    await pool.query("DELETE FROM cases WHERE id = $1", [id]);
    res.send("Case deleted successfully.");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Start Server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

