import { Router } from "express";
import type { Response } from "express";
import { authenticateJWT } from "../middleware/auth.js";
import type { AuthRequest } from "../middleware/auth.js";
import { requireAdmin } from "../middleware/kyc.js";
import db from "../db.js";
import { v4 as uuidv4 } from "uuid";

const router = Router();

/**
 * GET /api/admin/kyc
 * Admin-only alias to list users whose KYC needs verification (pending submissions)
 * Query params:
 *   - role: 'seller' | 'buyer' | 'all' (default 'seller')
 *   - email: substring filter (optional)
 *   - limit: number (default 20, max 100)
 *   - offset: number (default 0)
 */
router.get("/kyc", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
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

    sql += " AND u.kyc_status IN ('submitted','pending')";
  sql += " ORDER BY ks.submitted_at DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const [rows] = await db.query(sql, params);
    return res.json({ users: rows, paging: { limit, offset, role, email: email || null } });
  } catch (err) {
    console.error("Admin KYC list error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
 
/**
 * GET /api/admin/escrows
 * Admin-only: list escrow transactions with optional filters
 * Query params:
 *  - status: filter by escrow status
 *  - buyer: filter by buyer email substring
 *  - seller: filter by seller email substring
 *  - created_from: ISO date string (inclusive)
 *  - created_to: ISO date string (inclusive)
 *  - limit: number (default 20, max 100)
 *  - offset: number (default 0)
 *  - sort: '-created' | 'created' | '-updated' | 'updated' (default '-created')
 */
router.get("/escrows", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const status = ((req.query.status as string) || "").trim();
    const buyer = ((req.query.buyer as string) || "").trim();
    const seller = ((req.query.seller as string) || "").trim();
    const createdFrom = ((req.query.created_from as string) || "").trim();
    const createdTo = ((req.query.created_to as string) || "").trim();
    const limit = Math.min(parseInt((req.query.limit as string) || "20", 10), 100);
    const offset = parseInt((req.query.offset as string) || "0", 10);
    const sort = ((req.query.sort as string) || "-created").toLowerCase();

    let orderBy = "e.created_at DESC";
    if (sort === "created") orderBy = "e.created_at ASC";
    else if (sort === "-updated") orderBy = "e.updated_at DESC";
    else if (sort === "updated") orderBy = "e.updated_at ASC";

    let sql = `
      SELECT 
        e.id, e.amount, e.currency, e.status, e.created_at, e.updated_at,
        e.buyer_id, b.email AS buyer_email,
        e.seller_id, s.email AS seller_email
      FROM escrow_transactions e
      LEFT JOIN users b ON b.id = e.buyer_id
      LEFT JOIN users s ON s.id = e.seller_id
      WHERE 1=1`;

    const params: any[] = [];

    if (status) {
      sql += " AND e.status = ?";
      params.push(status);
    }
    if (buyer) {
      sql += " AND b.email LIKE ?";
      params.push(`%${buyer}%`);
    }
    if (seller) {
      sql += " AND s.email LIKE ?";
      params.push(`%${seller}%`);
    }
    if (createdFrom) {
      sql += " AND e.created_at >= ?";
      params.push(createdFrom);
    }
    if (createdTo) {
      sql += " AND e.created_at <= ?";
      params.push(createdTo);
    }

    sql += ` ORDER BY ${orderBy} LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const [rows] = await db.query(sql, params);
    return res.json({
      escrows: rows,
      paging: { limit, offset },
      filters: { status: status || null, buyer: buyer || null, seller: seller || null, created_from: createdFrom || null, created_to: createdTo || null, sort }
    });
  } catch (err) {
    console.error("Admin list escrows error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /api/admin/disputes
 * Admin-only: list disputes with optional filters
 * Query params:
 *  - status: filter by dispute status (open|resolved|rejected)
 *  - escrow_id: filter by specific escrow id
 *  - buyer: filter by buyer email substring
 *  - seller: filter by seller email substring
 *  - limit: number (default 20, max 100)
 *  - offset: number (default 0)
 *  - sort: '-created' | 'created' | '-updated' | 'updated' (default '-created')
 */
router.get("/disputes", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const status = ((req.query.status as string) || "").trim();
    const escrowId = ((req.query.escrow_id as string) || "").trim();
    const buyer = ((req.query.buyer as string) || "").trim();
    const seller = ((req.query.seller as string) || "").trim();
    const limit = Math.min(parseInt((req.query.limit as string) || "20", 10), 100);
    const offset = parseInt((req.query.offset as string) || "0", 10);
    const sort = ((req.query.sort as string) || "-created").toLowerCase();

    let orderBy = "d.created_at DESC";
    if (sort === "created") orderBy = "d.created_at ASC";
    else orderBy;

    let sql = `
      SELECT 
        d.id, d.escrow_id, d.status, d.created_at, d.updated_at,
        e.amount, e.currency, e.status AS escrow_status,
        e.buyer_id, b.email AS buyer_email,
        e.seller_id, s.email AS seller_email
      FROM disputes d
      JOIN escrow_transactions e ON e.id = d.escrow_id
      LEFT JOIN users b ON b.id = e.buyer_id
      LEFT JOIN users s ON s.id = e.seller_id
      WHERE 1=1`;

    const params: any[] = [];

    if (status) {
      sql += " AND d.status = ?";
      params.push(status);
    }
    if (escrowId) {
      sql += " AND d.escrow_id = ?";
      params.push(escrowId);
    }
    if (buyer) {
      sql += " AND b.email LIKE ?";
      params.push(`%${buyer}%`);
    }
    if (seller) {
      sql += " AND s.email LIKE ?";
      params.push(`%${seller}%`);
    }

    sql += ` ORDER BY ${orderBy} LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const [rows] = await db.query(sql, params);
    return res.json({
      disputes: rows,
      paging: { limit, offset },
      filters: { status: status || null, escrow_id: escrowId || null, buyer: buyer || null, seller: seller || null, sort }
    });
  } catch (err) {
    console.error("Admin list disputes error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /api/admin/disputes/:id
 * Admin-only: get dispute details including related escrow and participants
 */
router.get("/disputes/:id", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const id = req.params.id;
    const [rows] = await db.query(
      `SELECT 
         d.id, d.escrow_id, d.status, d.created_at, d.updated_at,
         e.amount, e.currency, e.status AS escrow_status,
         e.buyer_id, b.email AS buyer_email,
         e.seller_id, s.email AS seller_email
       FROM disputes d
       JOIN escrow_transactions e ON e.id = d.escrow_id
       LEFT JOIN users b ON b.id = e.buyer_id
       LEFT JOIN users s ON s.id = e.seller_id
       WHERE d.id = ?`,
      [id]
    );
    const list = rows as any[];
    if (list.length === 0) return res.status(404).json({ error: "Dispute not found" });

    // Load evidence entries
    const [evidRows] = await db.query(
      `SELECT id, file_url, note, uploaded_by, created_at FROM evidence WHERE dispute_id = ? ORDER BY created_at ASC`,
      [id]
    );

    return res.json({ dispute: list[0], evidence: evidRows });
  } catch (err) {
    console.error("Admin get dispute error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/admin/disputes/:id/reject
 * Admin rejects dispute: dispute.status='rejected', escrow.status='completed'
 * Idempotent and audited.
 */
router.post("/disputes/:id/reject", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const id = req.params.id;
    const [rows] = await db.query(
      `SELECT d.id, d.status, d.escrow_id, e.status AS escrow_status
       FROM disputes d JOIN escrow_transactions e ON e.id = d.escrow_id WHERE d.id = ?`,
      [id]
    );
    const list = rows as any[];
    if (list.length === 0) return res.status(404).json({ error: "Dispute not found" });
    const rec = list[0];

    // Idempotency: if already rejected and escrow completed, return OK
    const alreadyRejected = rec.status === "rejected";
    const escrowCompleted = rec.escrow_status === "completed";
    if (alreadyRejected && escrowCompleted) {
      return res.json({ message: "Dispute already rejected and escrow completed", dispute: { id, status: "rejected" }, escrow: { id: rec.escrow_id, status: "completed" } });
    }

    // Update escrow -> completed (allowed if released/confirmed/dispute)
    await db.query(
      "UPDATE escrow_transactions SET status = 'completed', updated_at = NOW() WHERE id = ?",
      [rec.escrow_id]
    );

    // Update dispute -> rejected
    await db.query(
      "UPDATE disputes SET status = 'rejected', updated_at = NOW() WHERE id = ?",
      [id]
    );

    // Audit
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'dispute_reject', 'disputes', ?, JSON_OBJECT('escrow_id', ?, 'to','rejected'), NOW())`,
      [uuidv4(), req.user?.id, id, rec.escrow_id]
    );

    return res.json({ message: "Dispute rejected; escrow completed", dispute: { id, status: "rejected" }, escrow: { id: rec.escrow_id, status: "completed" } });
  } catch (err) {
    console.error("Admin reject dispute error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/admin/disputes/:id/approve
 * Admin approves dispute: dispute.status='resolved', escrow.status='cancelled'
 * Idempotent and audited.
 */
router.post("/disputes/:id/approve", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const id = req.params.id;
    const [rows] = await db.query(
      `SELECT d.id, d.status, d.escrow_id, e.status AS escrow_status
       FROM disputes d JOIN escrow_transactions e ON e.id = d.escrow_id WHERE d.id = ?`,
      [id]
    );
    const list = rows as any[];
    if (list.length === 0) return res.status(404).json({ error: "Dispute not found" });
    const rec = list[0];

    // Idempotency: resolved + cancelled
    const alreadyResolved = rec.status === "resolved";
    const escrowCancelled = rec.escrow_status === "cancelled";
    if (alreadyResolved && escrowCancelled) {
      return res.json({ message: "Dispute already approved and escrow cancelled", dispute: { id, status: "resolved" }, escrow: { id: rec.escrow_id, status: "cancelled" } });
    }

    // Cancel escrow
    await db.query(
      "UPDATE escrow_transactions SET status = 'cancelled', updated_at = NOW() WHERE id = ?",
      [rec.escrow_id]
    );

    // Resolve dispute
    await db.query(
      "UPDATE disputes SET status = 'resolved', updated_at = NOW(), updated_at = NOW() WHERE id = ?",
      [id]
    );

    // Audit
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'dispute_approve', 'disputes', ?, JSON_OBJECT('escrow_id', ?, 'to','resolved'), NOW())`,
      [uuidv4(), req.user?.id, id, rec.escrow_id]
    );

    return res.json({ message: "Dispute approved; escrow cancelled", dispute: { id, status: "resolved" }, escrow: { id: rec.escrow_id, status: "cancelled" } });
  } catch (err) {
    console.error("Admin approve dispute error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/admin/escrows/:id/release
 * Admin releases funds to the seller when escrow is confirmed
 */
router.post("/escrows/:id/release", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;

    // Fetch escrow and validate state
    const [eRows] = await db.query(
      "SELECT id, status, seller_id FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const list = eRows as any[];
    if (list.length === 0) return res.status(404).json({ error: "Escrow not found" });
    const escrow = list[0];

    if (escrow.status === "released") {
      // Idempotent: already released
      return res.json({ message: "Escrow already released", escrow: { id: escrowId, status: "released" } });
    }
    if (escrow.status !== "confirmed") {
      return res.status(400).json({ error: "Escrow must be 'confirmed' before release", current_status: escrow.status, hint: "If it's already released, use /api/admin/escrows/:id/complete" });
    }

    // Ensure seller KYC verified
    const [sRows] = await db.query("SELECT kyc_status FROM users WHERE id = ?", [escrow.seller_id]);
    const sellers = sRows as any[];
    if (sellers.length === 0 || sellers[0].kyc_status !== "verified") {
      return res.status(403).json({ error: "Seller is not KYC verified" });
    }

    // Update escrow status to released
    await db.query(
      "UPDATE escrow_transactions SET status = 'released', updated_at = NOW() WHERE id = ?",
      [escrowId]
    );

    // Create payout record (pending)
    let payoutId: string | null = null;
    try {
      const [payoutsTableRows] = await db.query("SHOW TABLES LIKE 'payouts'");
      const exists = (payoutsTableRows as any[]).length > 0;
      if (!exists) {
        console.error("Admin release payout error: payouts table missing");
        return res.status(500).json({ error: "Internal server error", detail: "payouts table missing" });
      }
      payoutId = uuidv4();
      await db.query(
        `INSERT INTO payouts (id, escrow_id, seller_id, amount, status, created_at)
         VALUES (?, ?, ?, (SELECT amount FROM escrow_transactions WHERE id = ?), 'pending', NOW())`,
        [payoutId, escrowId, escrow.seller_id, escrowId]
      );
    } catch (payoutErr) {
      console.error("Admin release payout insert error:", payoutErr);
      return res.status(500).json({ error: "Internal server error", detail: "Failed to create payout" });
    }

    // Audit release
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'release', 'escrow_transactions', ?, JSON_OBJECT('status','released','by','admin'), NOW())`,
      [uuidv4(), req.user?.id, escrowId]
    );

    return res.json({ message: "Escrow released by admin, payout initiated", escrow: { id: escrowId, status: 'released' }, payout: { id: payoutId, status: 'pending' } });
  } catch (err) {
    console.error("Admin release escrow error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/admin/escrows/:id/complete
 * Admin marks a released escrow as completed
 */
router.post("/escrows/:id/complete", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;

    const [rows] = await db.query(
      "SELECT id, status FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const list = rows as any[];
    if (list.length === 0) return res.status(404).json({ error: "Escrow not found" });
    const escrow = list[0];
    if (escrow.status === "completed") {
      // Idempotent: already completed
      return res.json({ message: "Escrow already completed", escrow: { id: escrowId, status: "completed" } });
    }
    if (escrow.status !== "released") {
      return res.status(400).json({ error: "Escrow must be 'released' before completion", current_status: escrow.status, hint: "Use /api/admin/escrows/:id/release first" });
    }

    await db.query(
      "UPDATE escrow_transactions SET status = 'completed', updated_at = NOW() WHERE id = ?",
      [escrowId]
    );

    // Find latest payout for this escrow and advance status if still pending
    try {
      const [pRows] = await db.query(
        "SELECT id, status FROM payouts WHERE escrow_id = ? ORDER BY created_at DESC LIMIT 1",
        [escrowId]
      );
      const payouts = pRows as any[];
      if (payouts.length > 0) {
        const payout = payouts[0];
        if (payout.status === 'pending') {
          await db.query(
            "UPDATE payouts SET status = 'sent', sent_at = NOW() WHERE id = ?",
            [payout.id]
          );
          // Audit payout status change
          await db.query(
            `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
             VALUES (?, ?, 'payout_status', 'payouts', ?, JSON_OBJECT('from','pending','to','sent'), NOW())`,
            [uuidv4(), req.user?.id, payout.id]
          );
        }
      }
    } catch (payoutAdvanceErr) {
      console.error("Advance payout status error:", payoutAdvanceErr);
    }

    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'complete', 'escrow_transactions', ?, JSON_OBJECT('status','completed'), NOW())`,
      [uuidv4(), req.user?.id, escrowId]
    );

    return res.json({ message: "Escrow marked as completed", escrow: { id: escrowId, status: "completed" } });
  } catch (err) {
    console.error("Admin complete escrow error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/admin/escrows/:id/refund
 * Admin refunds a disputed escrow (sets status to 'cancelled')
 */
router.post("/escrows/:id/refund", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;

    const [rows] = await db.query(
      "SELECT id, status FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const list = rows as any[];
    if (list.length === 0) return res.status(404).json({ error: "Escrow not found" });
    const escrow = list[0];
    if (escrow.status !== "dispute") {
      return res.status(400).json({ error: "Escrow must be in 'dispute' to refund", current_status: escrow.status });
    }

    await db.query(
      "UPDATE escrow_transactions SET status = 'cancelled', updated_at = NOW() WHERE id = ?",
      [escrowId]
    );

    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'refund', 'escrow_transactions', ?, JSON_OBJECT('status','cancelled'), NOW())`,
      [uuidv4(), req.user?.id, escrowId]
    );

    return res.json({ message: "Escrow refunded and cancelled", escrow: { id: escrowId, status: "cancelled" } });
  } catch (err) {
    console.error("Admin refund escrow error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/admin/payouts/:id/resolve
 * Marks a payout as resolved (finalized). Intended after external settlement confirmation.
 * Body (optional): { note?: string }
 */
router.post("/payouts/:id/resolve", authenticateJWT, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const payoutId = req.params.id;
    const note = (req.body?.note as string | undefined) || null;

    // Fetch payout
    const [pRows] = await db.query(
      "SELECT id, escrow_id, seller_id, status FROM payouts WHERE id = ?",
      [payoutId]
    );
    const payouts = pRows as any[];
    if (payouts.length === 0) return res.status(404).json({ error: "Payout not found" });
    const payout = payouts[0];

    if (payout.status === 'resolved') {
      return res.json({ message: "Payout already resolved", payout: { id: payoutId, status: 'resolved' } });
    }

    // Only allow resolving if currently sent or pending (could enforce 'sent' strictly)
    if (!['sent','pending'].includes(payout.status)) {
      return res.status(400).json({ error: "Payout cannot be resolved from current status", current_status: payout.status });
    }

    // Update status -> resolved
    await db.query(
      "UPDATE payouts SET status = 'resolved', resolved_at = NOW() WHERE id = ?",
      [payoutId]
    );

    // Audit
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'payout_resolve', 'payouts', ?, JSON_OBJECT('from', ?, 'to', 'resolved', 'note', ?), NOW())`,
      [uuidv4(), req.user?.id, payoutId, payout.status, note]
    );

    return res.json({ message: "Payout resolved", payout: { id: payoutId, status: 'resolved' } });
  } catch (err) {
    console.error("Admin resolve payout error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});
