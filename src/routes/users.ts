import { Router } from "express";
import type { Response } from "express";
import { authenticateJWT } from "../middleware/auth.js";
import { requireAdmin } from "../middleware/kyc.js";
import type { AuthRequest } from "../middleware/auth.js";
import db from "../db.js"; // MySQL connection
import { v4 as uuidv4, v4 } from "uuid";
import multer from "multer";
import path from "path";
import fs from "fs";

const router = Router();

/**
 * GET /api/users/me
 * Get current user profile
 */
router.get("/me", authenticateJWT, (req: AuthRequest, res: Response) => {
  res.json({
    user: req.user
  });
});

/**
 * GET /api/users
 * Admin-only: lookup user by email
 */
router.get("/", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const email = (req.query.email as string) || "";
    if (!email) return res.status(400).json({ error: "email is required" });
    const [rows] = await db.query("SELECT id, email, role, kyc_status FROM users WHERE email = ?", [email]);
    const list = rows as any[];
    if (list.length === 0) return res.status(404).json({ error: "User not found" });
    return res.json({ user: list[0] });
  } catch (err) {
    console.error("Admin lookup user by email error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /api/users/kyc/pending
 * Admin-only: list users whose KYC needs verification (pending submissions)
 * Query params:
 *   - role: 'seller' | 'buyer' | 'all' (default 'seller')
 *   - email: substring filter (optional)
 *   - limit: number (default 20, max 100)
 *   - offset: number (default 0)
 */
router.get("/kyc/pending", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({ error: "Only admins can access pending KYC list" });
    }

    const role = ((req.query.role as string) || "seller").toLowerCase();
    const email = (req.query.email as string) || "";
    const limit = Math.min(parseInt((req.query.limit as string) || "20", 10), 100);
    const offset = parseInt((req.query.offset as string) || "0", 10);

    const roles: string[] = [];
    if (role === "all") {
      roles.push("buyer", "seller");
    } else if (role === "buyer" || role === "seller") {
      roles.push(role);
    } else {
      return res.status(400).json({ error: "Invalid role. Use 'seller', 'buyer', or 'all'" });
    }

    let sql = `
      SELECT 
        u.id, u.email, u.role, u.kyc_status,
        ks.id AS submission_id, ks.full_name, ks.id_number, ks.document_url, ks.selfie_url,
        ks.status AS submission_status, ks.submitted_at AS submitted_at
      FROM users u
      JOIN kyc_submissions ks ON ks.user_id = u.id AND ks.status = 'pending'
      WHERE u.role IN (${roles.map(() => "?").join(",")})
    `;
    const params: any[] = [...roles];

    if (email) {
      sql += " AND u.email LIKE ?";
      params.push(`%${email}%`);
    }

    // Only show users who still need verification (typically 'submitted' or 'pending')
    sql += " AND u.kyc_status IN ('submitted','pending')";

    sql += " ORDER BY ks.submitted_at DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const [rows] = await db.query(sql, params);
    return res.json({
      users: rows,
      paging: { limit, offset, role, email: email || null }
    });
  } catch (err) {
    console.error("List pending KYC error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /api/users/me/kyc
 * Returns current user's KYC status
 */
router.get("/me/kyc", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const [rows] = await db.query("SELECT kyc_status FROM users WHERE id = ?", [req.user?.id]);
    const list = rows as any[];
    if (list.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.json({ kyc_status: list[0].kyc_status });
  } catch (err) {
    console.error("Get my KYC status error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /api/users?email=... (admin)
 * Returns a user's id, email, role, and kyc_status by email
 */
router.get("/", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({ error: "Only admins can lookup users" });
    }
    const email = (req.query.email as string) || "";
    if (!email) {
      return res.status(400).json({ error: "email query param is required" });
    }
    const [rows] = await db.query(
      "SELECT id, email, role, kyc_status FROM users WHERE email = ?",
      [email]
    );
    const list = rows as any[];
    if (list.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.json({ user: list[0] });
  } catch (err) {
    console.error("Admin lookup user by email error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

const uploadDir = path.resolve(process.env.UPLOADS_ROOT || "./uploads", "kyc");
fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname) || "";
    cb(null, `${Date.now()}-${uuidv4()}${ext}`);
  },
});
const kycUpload = multer({ storage });

/**
 * POST /api/users/kyc
 * Submit KYC info
 * Accepts multipart/form-data with files or JSON body.
 * Fields:
 *   - full_name (string)
 *   - id_number (string)
 *   - document (file) OR document_url (string)
 *   - selfie (file) OR selfie_url (string)
 */
router.post("/kyc", authenticateJWT, kycUpload.fields([
  { name: "document", maxCount: 1 },
  { name: "selfie", maxCount: 1 },
]), async (req: AuthRequest, res: Response) => {
  try {
    const { full_name, id_number } = req.body as any;

    // Derive URLs: prefer uploaded files; fallback to provided *_url strings
    const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;
    const documentFile = files?.document?.[0];
    const selfieFile = files?.selfie?.[0];
    const document_url = documentFile
      ? `${process.env.BASE_URL || ""}/uploads/kyc/${path.basename(documentFile.path)}`
      : (req.body as any)?.document_url;
    const selfie_url = selfieFile
      ? `${process.env.BASE_URL || ""}/uploads/kyc/${path.basename(selfieFile.path)}`
      : (req.body as any)?.selfie_url;

    if (!full_name || !id_number || !document_url || !selfie_url) {
      return res.status(400).json({ error: "All KYC fields are required (full_name, id_number, document or document_url, selfie or selfie_url)" });
    }

    const submissionId = v4();

    await db.query(
      `INSERT INTO kyc_submissions (id, user_id, full_name, id_number, document_url, selfie_url, status)
       VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
      [submissionId, req.user?.id, full_name, id_number, document_url, selfie_url]
    );

    // Update user KYC status to submitted
    await db.query(
      "UPDATE users SET kyc_status = 'submitted' WHERE id = ?",
      [req.user?.id]
    );

    res.status(201).json({
      message: "KYC submitted successfully",
      submission: { id: submissionId, status: "pending", document_url, selfie_url }
    });
  } catch (err) {
    console.error("KYC submit error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


/**
 * GET /api/users/:id/kyc
 * Get KYC submission details for a specific user.
 * - Allowed if requester is the same user or an admin.
 * - Returns the pending submission if exists; otherwise the most recent one available.
 */
router.get("/:id/kyc", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const targetUserId = req.params.id;

    if (!req.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    if (req.user.id !== targetUserId && req.user.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }

    // Ensure user exists
    const [userRows] = await db.query(
      "SELECT id, email, role, kyc_status FROM users WHERE id = ?",
      [targetUserId]
    );
    const users = userRows as any[];
    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    // Prefer a pending submission if present
    const [pendingRows] = await db.query(
      "SELECT id, user_id, full_name, id_number, document_url, selfie_url, status FROM kyc_submissions WHERE user_id = ? AND status = 'pending' LIMIT 1",
      [targetUserId]
    );
    const pending = (pendingRows as any[])[0];

    let submission = pending;
    if (!submission) {
      // Fallback: latest submission by id (UUID order is not chronological but avoids unknown timestamp columns)
      const [anyRows] = await db.query(
        "SELECT id, user_id, full_name, id_number, document_url, selfie_url, status FROM kyc_submissions WHERE user_id = ? ORDER BY id DESC LIMIT 1",
        [targetUserId]
      );
      submission = (anyRows as any[])[0];
    }

    if (!submission) {
      return res.status(404).json({ error: "No KYC submission found for this user" });
    }

    return res.json({
      user: users[0],
      submission
    });
  } catch (err) {
    console.error("Get user KYC details error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});


/**
 * POST /api/users/:id/kyc/verify
 * Admin approves or rejects user KYC
 * Body: { decision, note }
 */
router.post("/:id/kyc/verify", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.params.id;
    const { decision, note } = req.body;

    if (!["verified", "rejected"].includes(decision)) {
      return res.status(400).json({ error: "Decision must be 'verified' or 'rejected'" });
    }

    // Update submission
    await db.query(
      `UPDATE kyc_submissions 
       SET status = ?, reviewer_id = ?, note = ?, 
           verified_at = CASE WHEN ? = 'verified' THEN NOW() ELSE NULL END,
           rejected_at = CASE WHEN ? = 'rejected' THEN NOW() ELSE NULL END
       WHERE user_id = ? AND status = 'pending'`,
      [decision, req.user?.id, note || null, decision, decision, userId]
    );

    // Update user
    await db.query(
      "UPDATE users SET kyc_status = ? WHERE id = ?",
      [decision, userId]
    );

    res.json({
      message: `KYC ${decision} successfully`,
      user: { id: userId, kyc_status: decision }
    });
  } catch (err) {
    console.error("KYC verify error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/users/kyc/verify
 * Admin-only: verify KYC by email or user_id in the body
 * Body: { decision: 'verified' | 'rejected', note?, email?, user_id? }
 */
router.post("/kyc/verify", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const { decision, note, email, user_id } = req.body as any;
    if (!decision || !["verified", "rejected"].includes(decision)) {
      return res.status(400).json({ error: "Decision must be 'verified' or 'rejected'" });
    }

    let targetUserId = user_id as string | undefined;
    if (!targetUserId && email) {
      const [rows] = await db.query("SELECT id FROM users WHERE email = ?", [email]);
      const list = rows as any[];
      if (list.length === 0) return res.status(404).json({ error: "User not found for email" });
      targetUserId = list[0].id as string;
    }
    if (!targetUserId) return res.status(400).json({ error: "Provide email or user_id" });

    // Update submission
    await db.query(
      `UPDATE kyc_submissions 
       SET status = ?, reviewer_id = ?, note = ?, 
           verified_at = CASE WHEN ? = 'verified' THEN NOW() ELSE NULL END,
           rejected_at = CASE WHEN ? = 'rejected' THEN NOW() ELSE NULL END
       WHERE user_id = ? AND status = 'pending'`,
      [decision, req.user?.id, note || null, decision, decision, targetUserId]
    );

    // Update user
    await db.query("UPDATE users SET kyc_status = ? WHERE id = ?", [decision, targetUserId]);

    return res.json({ message: `KYC ${decision} successfully`, user: { id: targetUserId, kyc_status: decision } });
  } catch (err) {
    console.error("Admin KYC verify by email error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/users/kyc/verify (admin)
 * Body: { decision: 'verified'|'rejected', note?: string, user_id?: string, email?: string }
 * Allows admin to verify KYC by user_id or email without path param.
 */
router.post("/kyc/verify", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({ error: "Only admins can verify KYC" });
    }

    const { decision, note, user_id, email } = req.body || {};
    if (!["verified", "rejected"].includes(decision)) {
      return res.status(400).json({ error: "Decision must be 'verified' or 'rejected'" });
    }
    if (!user_id && !email) {
      return res.status(400).json({ error: "Provide either user_id or email" });
    }

    // Resolve user id
    let targetUserId = user_id as string | undefined;
    if (!targetUserId && email) {
      const [rows] = await db.query("SELECT id FROM users WHERE email = ?", [email]);
      const list = rows as any[];
      if (list.length === 0) {
        return res.status(404).json({ error: "User not found for given email" });
      }
      targetUserId = list[0].id as string;
    }

    // Update submission
    await db.query(
      `UPDATE kyc_submissions 
       SET status = ?, reviewer_id = ?, note = ?, 
           verified_at = CASE WHEN ? = 'verified' THEN NOW() ELSE NULL END,
           rejected_at = CASE WHEN ? = 'rejected' THEN NOW() ELSE NULL END
       WHERE user_id = ? AND status = 'pending'`,
      [decision, req.user?.id, note || null, decision, decision, targetUserId]
    );

    // Update user
    await db.query(
      "UPDATE users SET kyc_status = ? WHERE id = ?",
      [decision, targetUserId]
    );

    return res.json({
      message: `KYC ${decision} successfully`,
      user: { id: targetUserId, kyc_status: decision }
    });
  } catch (err) {
    console.error("KYC verify (body) error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});


export default router;