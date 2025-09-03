import { Router } from "express";
import type { Request, Response } from "express";
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../db.js"; // MySQL connection
import { v4 as uuidv4 } from "uuid";

const router = Router();

// Ensure JSON parsing
router.use(express.json());

/**
 * POST /api/auth/register
 * Body: { email, password, role }
 */
router.post("/register", async (req: Request, res: Response) => {
  try {
    console.log("Headers:", req.headers);
    console.log("Content-Type:", req.get('Content-Type'));
    console.log("Request body:", req.body);
    console.log("Raw body:", req.rawBody);
    
    if (!req.body) {
      return res.status(400).json({ error: "No request body received" });
    }
    
    const { email, password, role } = req.body;

    // basic input validation
    if (!email || !password || !role) {
      return res.status(400).json({ error: "Email, password, and role required" });
    }

    // check if user already exists
    console.log("Checking if user exists...");
    const [existing] = await db.query("SELECT id FROM users WHERE email = ?", [email]);
    console.log("User check result:", existing);
    if ((existing as any[]).length > 0) {
      return res.status(400).json({ error: "User already exists" });
    }

    // hash password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // create new user
    const userId = uuidv4();
    await db.query(
      "INSERT INTO users (id, email, password_hash, role, kyc_status) VALUES (?, ?, ?, ?, ?)",
      [userId, email, passwordHash, role, "pending"]
    );

    // generate JWT
    const token = jwt.sign(
      { id: userId, email, role },
      process.env.JWT_SECRET as string,
      { expiresIn: "1h" }
    );

    res.status(201).json({
      message: "User registered successfully",
      user: { id: userId, email, role },
      token,
    });
  } catch (err) {
    console.error("Register error:", err);
    console.error("Error details:", err.message);
    console.error("Error code:", err.code);
    res.status(500).json({ error: "Internal server error", details: err.message });
  }
});

/**
 * POST /api/auth/login
 * Body: { email, password }
 */
router.post("/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    // check if user exists
    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    const users = rows as any[];

    if (users.length === 0) {
      return res.status(400).json({ 
        error: "Invalid email or password" 
      });
    }

    const user = users[0];

    // verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    // issue JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET as string,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      user: { id: user.id, email: user.email, role: user.role },
      token,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


export default router;
