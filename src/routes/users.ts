import { Router } from "express";
import type { Response } from "express";
import { authenticateJWT } from "../middleware/auth.js";
import type { AuthRequest } from "../middleware/auth.js";
import db from "../db.js"; // MySQL connection
import { v4 as uuidv4, v4 } from "uuid";

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
 * POST /api/users/kyc
 * Submit KYC info
 * Body: { full_name, id_number, document_url, selfie_url }
 */
router.post("/kyc", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const { full_name, id_number, document_url, selfie_url } = req.body;

    if (!full_name || !id_number || !document_url || !selfie_url) {
      return res.status(400).json({ error: "All KYC fields are required" });
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
      submission: { id: submissionId, status: "pending" }
    });
  } catch (err) {
    console.error("KYC submit error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


/**
 * POST /api/users/:id/kyc/verify
 * Admin approves or rejects user KYC
 * Body: { decision, note }
 */
router.post("/:id/kyc/verify", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({ error: "Only admins can verify KYC" });
    }

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


export default router;