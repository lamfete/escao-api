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
    if (err instanceof Error) {
      console.error("Error details:", err.message);
      res.status(500).json({ error: "Internal server error", details: err.message });
    } else {
      console.error("Error details:", err);
      res.status(500).json({ error: "Internal server error", details: String(err) });
    }
    // Remove err.code since it's not guaranteed to exist
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

    // issue access token
    const accessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET as string,
      { expiresIn: "15m" }
    );

    // issue refresh token (longer expiry)
    const refreshToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET as string,
      { expiresIn: "7d" }
    );

    // Store user_id and user_role in session
    if (req.session) {
      req.session.user_id = user.id;
      req.session.user_role = user.role;
    }

    // Set refresh token in HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== "development", // true on Heroku
      sameSite: "none", // required for cross-origin requests
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: "/", // optional; default "/"
    });

    res.json({
      message: "Login successful",
      user: { id: user.id, email: user.email, role: user.role },
      accessToken,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/auth/refresh
 * Body: none (uses refreshToken cookie)
 */
router.post("/refresh", async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ error: "Refresh token missing" });
    }
    // Verify refresh token
    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_SECRET as string);
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired refresh token" });
    }
    // Issue new access token
    const accessToken = jwt.sign(
      { id: (payload as any).id, email: (payload as any).email, role: (payload as any).role },
      process.env.JWT_SECRET as string,
      { expiresIn: "15m" }
    );
    res.json({ accessToken });
  } catch (err) {
    console.error("Refresh token error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/auth/logout
 * Clears refresh token cookie and destroys session
 */
router.post("/logout", async (req: Request, res: Response) => {
  try {
    // Clear the refresh token cookie (must match cookie attributes used when setting it)
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV !== "development",
      sameSite: "none",
      path: "/",
    });

    // Destroy session if present
    if (req.session) {
      req.session.destroy((err) => {
        if (err) {
          console.error("Session destroy error:", err);
        }
      });
    }

    return res.json({ message: "Logged out" });
  } catch (err) {
    console.error("Logout error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});


export default router;
