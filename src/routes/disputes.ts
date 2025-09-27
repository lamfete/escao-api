import { Router } from "express";
import type { Response } from "express";
import db from "../db.js";
import { v4 as uuidv4 } from "uuid";
import { authenticateJWT } from "../middleware/auth.js";
import type { AuthRequest } from "../middleware/auth.js";
import { requireKYCVerified } from "../middleware/kyc.js";

const router = Router();

/**
 * POST /api/disputes/:id/evidence
 * Body: { file_url, note }
 */
router.post("/:id/evidence", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const disputeId = req.params.id;
    const { file_url, note } = req.body;

    if (!file_url) {
      return res.status(400).json({ error: "file_url is required" });
    }

    // check dispute
    const [disputeRows] = await db.query(
      `SELECT d.id, d.status, e.buyer_id, e.seller_id
       FROM disputes d
       JOIN escrow_transactions e ON d.escrow_id = e.id
       WHERE d.id = ?`,
      [disputeId]
    );
    const disputes = disputeRows as any[];

    if (disputes.length === 0) {
      return res.status(404).json({ error: "Dispute not found" });
    }

    const dispute = disputes[0];

    if (dispute.status !== "open") {
      return res.status(400).json({ error: "Cannot upload evidence to closed dispute" });
    }

    // only buyer or seller in this escrow can upload
    if (req.user?.id !== dispute.buyer_id && req.user?.id !== dispute.seller_id) {
      return res.status(403).json({ error: "Not authorized to upload evidence for this dispute" });
    }

    const evidenceId = uuidv4();

    await db.query(
      `INSERT INTO evidence (id, dispute_id, file_url, note, uploaded_by, created_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [evidenceId, disputeId, file_url, note || null, req.user?.id]
    );

    // audit log
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'upload_evidence', 'evidence', ?, JSON_OBJECT('file_url', ?, 'note', ?), NOW())`,
      [uuidv4(), req.user?.id, evidenceId, file_url, note || null]
    );

    res.status(201).json({
      message: "Evidence uploaded successfully",
      evidence: { id: evidenceId, dispute_id: disputeId, file_url, note }
    });
  } catch (err) {
    console.error("Upload evidence error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/disputes/:id/resolve
 * Admin resolves dispute
 * Body: { decision, note }
 */

router.post("/:id/resolve", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const disputeId = req.params.id;
    const { decision, note } = req.body;

    if (req.user?.role !== "admin") {
      return res.status(403).json({ error: "Only admins can resolve disputes" });
    }

    if (!decision || !["favor_buyer", "favor_seller", "rejected"].includes(decision)) {
      return res.status(400).json({ error: "Decision must be 'favor_buyer', 'favor_seller', or 'rejected'" });
    }

    // check dispute
    const [disputeRows] = await db.query(
      `SELECT d.id, d.status, d.escrow_id, e.seller_id
       FROM disputes d
       JOIN escrow_transactions e ON d.escrow_id = e.id
       WHERE d.id = ?`,
      [disputeId]
    );
    const disputes = disputeRows as any[];

    if (disputes.length === 0) {
      return res.status(404).json({ error: "Dispute not found" });
    }

    const dispute = disputes[0];

    if (dispute.status !== "open") {
      return res.status(400).json({ error: "Dispute already resolved or closed" });
    }

    // If decision is favor_seller, check seller KYC status before releasing funds
    if (decision === "favor_seller") {
      // Use KYC middleware logic directly
      const [sellerRows] = await db.query(
        "SELECT kyc_status FROM users WHERE id = ?",
        [dispute.seller_id]
      );
      const sellers = sellerRows as any[];
      if (sellers.length === 0 || sellers[0].kyc_status !== "verified") {
        return res.status(403).json({ error: "Seller is not KYC verified. Cannot release funds." });
      }

      // Release funds to seller (update escrow status and create payout)
      await db.query(
        "UPDATE escrow_transactions SET status = 'released', updated_at = NOW() WHERE id = ?",
        [dispute.escrow_id]
      );
      const payoutId = uuidv4();
      await db.query(
        `INSERT INTO payouts (id, escrow_id, bank_account, method, status, sent_at, pg_reference)
         VALUES (?, ?, '1234567890', 'BI-FAST', 'pending', NULL, NULL)`,
        [payoutId, dispute.escrow_id]
      );
    }

    // update dispute
    await db.query(
      `UPDATE disputes 
       SET status = 'resolved', resolved_at = NOW() 
       WHERE id = ?`,
      [disputeId]
    );

    // audit log
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'resolve_dispute', 'disputes', ?, JSON_OBJECT('decision', ?, 'note', ?), NOW())`,
      [uuidv4(), req.user?.id, disputeId, decision, note || null]
    );

    res.json({
      message: "Dispute resolved successfully",
      dispute: { id: disputeId, status: "resolved", decision, note }
    });
  } catch (err) {
    console.error("Resolve dispute error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


export default router;
