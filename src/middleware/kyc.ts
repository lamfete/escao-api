import type { NextFunction, Response } from "express";
import db from "../db.js"; // MySQL connection
import type { AuthRequest } from "../middleware/auth.js";

/**
 * Middleware to enforce KYC verification for sellers
 */
export const requireKYCVerified = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const [rows] = await db.query("SELECT kyc_status FROM users WHERE id = ?", [req.user?.id]);
    const users = rows as any[];

    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    if (users[0].kyc_status !== "verified") {
      return res.status(403).json({ error: "KYC verification required to perform this action" });
    }

    next();
  } catch (err) {
    console.error("KYC check error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Middleware to enforce admin role
 */
export const requireAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
};
