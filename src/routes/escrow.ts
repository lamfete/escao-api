import { Router } from "express";
import type { Response } from "express";
import express from "express";
import db from "../db.js";
import { v4 as uuidv4 } from "uuid";
import { authenticateJWT } from "../middleware/auth.js";
import type { AuthRequest } from "../middleware/auth.js";

const router = Router();

// Ensure JSON parsing
router.use(express.json());

/**
 * POST /api/escrow
 * Body: { buyer_id, seller_id, amount, currency }
 */
router.post("/", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const { buyer_id, seller_id, amount, currency } = req.body;

    // validation
    if (!buyer_id || !seller_id || !amount) {
      return res.status(400).json({ error: "buyer_id, seller_id, and amount are required" });
    }

    if (req.user?.role !== "buyer" && req.user?.role !== "seller") {
      return res.status(403).json({ error: "Only buyers or sellers can create escrow" });
    }

    // generate escrow ID
    const escrowId = uuidv4();

    await db.query(
      `INSERT INTO escrow_transactions (id, buyer_id, seller_id, amount, currency, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'created', NOW(), NOW())`,
      [escrowId, buyer_id, seller_id, amount, currency || "IDR"]
    );

    // add audit log
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'create', 'escrow_transactions', ?, JSON_OBJECT('amount', ?, 'currency', ?), NOW())`,
      [uuidv4(), req.user?.id, escrowId, amount, currency || "IDR"]
    );

    res.status(201).json({
      message: "Escrow created successfully",
      escrow: {
        id: escrowId,
        buyer_id,
        seller_id,
        amount,
        currency: currency || "IDR",
        status: "created",
      },
    });
  } catch (err) {
    console.error("Create escrow error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /api/escrow/:id
 * Returns escrow transaction details
 */
router.get("/:id", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;

    const [rows] = await db.query(
      `SELECT e.id, e.amount, e.currency, e.status, e.created_at, e.updated_at,
              b.id AS buyer_id, b.email AS buyer_email,
              s.id AS seller_id, s.email AS seller_email
       FROM escrow_transactions e
       LEFT JOIN users b ON e.buyer_id = b.id
       LEFT JOIN users s ON e.seller_id = s.id
       WHERE e.id = ?`,
      [escrowId]
    );

    const escrows = rows as any[];

    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }

    res.json({ escrow: escrows[0] });
  } catch (err) {
    console.error("Get escrow error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/escrow/:id/fund
 * Body: { method, pg_reference, qr_code_url }
 * Marks escrow as funded after payment success
 */
router.post("/:id/fund", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;
    console.log("Fund request body:", req.body);
    console.log("Fund request headers:", req.headers);
    
    if (!req.body) {
      return res.status(400).json({ error: "No request body received" });
    }
    
    const { method, pg_reference, qr_code_url } = req.body;

    if (!method || !pg_reference) {
      return res.status(400).json({ error: "method and pg_reference are required" });
    }

    // check if escrow exists
    const [escrowRows] = await db.query(
      "SELECT id, status FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const escrows = escrowRows as any[];

    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }
    const escrow = escrows[0];
    console.log("Current escrow status:", escrow.status);

    if (escrow.status !== "created") {
      return res.status(400).json({ 
        error: "Escrow is not in 'created' state", 
        current_status: escrow.status 
      });
    }

    const paymentId = uuidv4();

    // insert payment intent
    await db.query(
      `INSERT INTO payment_intents (id, escrow_id, method, pg_reference, qr_code_url, status, paid_at, raw_payload)
       VALUES (?, ?, ?, ?, ?, 'paid', NOW(), JSON_OBJECT('pg_ref', ?, 'method', ?))`,
      [paymentId, escrowId, method, pg_reference, qr_code_url || null, pg_reference, method]
    );

    // update escrow status
    await db.query(
      "UPDATE escrow_transactions SET status = 'funded', updated_at = NOW() WHERE id = ?",
      [escrowId]
    );

    // audit log
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'fund', 'escrow_transactions', ?, JSON_OBJECT('method', ?, 'pg_ref', ?), NOW())`,
      [uuidv4(), req.user?.id, escrowId, method, pg_reference]
    );

    res.json({
      message: "Escrow funded successfully",
      escrow: { id: escrowId, status: "funded" },
      payment_intent: { id: paymentId, method, pg_reference }
    });
  } catch (err) {
    console.error("Fund escrow error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


/**
 * POST /api/escrow/:id/ship
 * Body: { tracking_number }
 * Marks escrow as shipped (seller confirms shipping)
 */
router.post("/:id/ship", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;
    console.log("Ship request body:", req.body);
    
    if (!req.body) {
      return res.status(400).json({ error: "No request body received" });
    }
    
    const { tracking_number } = req.body;

    console.log("Current user role:", req.user?.role);
    
    // only sellers can ship
    if (req.user?.role !== "seller") {
      return res.status(403).json({ 
        error: "Only sellers can mark escrow as shipped",
        current_role: req.user?.role 
      });
    }

    // check escrow
    const [escrowRows] = await db.query(
      "SELECT id, status FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const escrows = escrowRows as any[];

    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }

    const escrow = escrows[0];
    console.log("Current escrow status for shipping:", escrow.status);

    if (escrow.status !== "funded") {
      return res.status(400).json({ 
        error: "Escrow must be in 'funded' state before shipping",
        current_status: escrow.status 
      });
    }

    // update escrow status
    await db.query(
      "UPDATE escrow_transactions SET status = 'shipped', updated_at = NOW() WHERE id = ?",
      [escrowId]
    );

    // log audit
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'ship', 'escrow_transactions', ?, JSON_OBJECT('tracking_number', ?), NOW())`,
      [uuidv4(), req.user?.id, escrowId, tracking_number || null]
    );

    res.json({
      message: "Escrow marked as shipped",
      escrow: { id: escrowId, status: "shipped", tracking_number: tracking_number || null }
    });
  } catch (err) {
    console.error("Ship escrow error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/escrow/:id/confirm
 * Buyer confirms they have received the goods
 */
router.post("/:id/confirm", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;

    // only buyers can confirm
    if (req.user?.role !== "buyer") {
      return res.status(403).json({ error: "Only buyers can confirm receipt" });
    }

    // check escrow
    const [escrowRows] = await db.query(
      "SELECT id, status FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const escrows = escrowRows as any[];

    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }

    const escrow = escrows[0];

    if (escrow.status !== "shipped") {
      return res.status(400).json({ error: "Escrow must be in 'shipped' state before confirming" });
    }

    // update escrow status
    await db.query(
      "UPDATE escrow_transactions SET status = 'confirmed', updated_at = NOW() WHERE id = ?",
      [escrowId]
    );

    // audit log
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'confirm', 'escrow_transactions', ?, JSON_OBJECT('status','confirmed'), NOW())`,
      [uuidv4(), req.user?.id, escrowId]
    );

    res.json({
      message: "Escrow confirmed successfully",
      escrow: { id: escrowId, status: "confirmed" }
    });
  } catch (err) {
    console.error("Confirm escrow error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/escrow/:id/release
 * Releases funds to seller (usually admin/system action)
 */
router.post("/:id/release", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;

    // Only admin or system can release funds
    if (req.user?.role !== "admin") {
      return res.status(403).json({ error: "Only admins can release escrow funds" });
    }

    // check escrow
    const [escrowRows] = await db.query(
      "SELECT id, status FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const escrows = escrowRows as any[];

    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }

    const escrow = escrows[0];

    if (escrow.status !== "confirmed") {
      return res.status(400).json({ error: "Escrow must be 'confirmed' before releasing funds" });
    }

    // update escrow status
    await db.query(
      "UPDATE escrow_transactions SET status = 'released', updated_at = NOW() WHERE id = ?",
      [escrowId]
    );

    // simulate payout record
    const payoutId = uuidv4();
    await db.query(
      `INSERT INTO payouts (id, escrow_id, bank_account, method, status, sent_at, pg_reference)
       VALUES (?, ?, '1234567890', 'BI-FAST', 'pending', NULL, NULL)`,
      [payoutId, escrowId]
    );

    // audit log
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'release', 'escrow_transactions', ?, JSON_OBJECT('status','released'), NOW())`,
      [uuidv4(), req.user?.id, escrowId]
    );

    res.json({
      message: "Escrow released successfully, payout initiated",
      escrow: { id: escrowId, status: "released" },
      payout: { id: payoutId, status: "pending" }
    });
  } catch (err) {
    console.error("Release escrow error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/escrow/:id/dispute
 * Opens a dispute for an escrow transaction
 * Body: { reason }
 */
router.post("/:id/dispute", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;
    const { reason } = req.body;

    if (!reason) {
      return res.status(400).json({ error: "Reason is required" });
    }

    // check escrow
    const [escrowRows] = await db.query(
      "SELECT id, status, buyer_id, seller_id FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const escrows = escrowRows as any[];

    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }

    const escrow = escrows[0];

    // only buyer or seller involved can open dispute
    if (req.user?.id !== escrow.buyer_id && req.user?.id !== escrow.seller_id) {
      return res.status(403).json({ error: "Only buyer or seller can open dispute" });
    }

    // escrow must be active
    if (!["funded", "shipped", "confirmed"].includes(escrow.status)) {
      return res.status(400).json({ error: "Cannot dispute escrow in current state" });
    }

    // create dispute
    const disputeId = uuidv4();
    await db.query(
      `INSERT INTO disputes (id, escrow_id, opened_by, reason, status, created_at)
       VALUES (?, ?, ?, ?, 'open', NOW())`,
      [disputeId, escrowId, req.user?.id, reason]
    );

    // audit log
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'dispute', 'disputes', ?, JSON_OBJECT('reason', ?), NOW())`,
      [uuidv4(), req.user?.id, disputeId, reason]
    );

    res.status(201).json({
      message: "Dispute opened successfully",
      dispute: { id: disputeId, escrow_id: escrowId, reason, status: "open" }
    });
  } catch (err) {
    console.error("Dispute escrow error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/escrow/:id/cancel
 * Buyer or Seller can cancel escrow before it is funded
 */
router.post("/:id/cancel", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;

    // check escrow
    const [escrowRows] = await db.query(
      "SELECT id, status, buyer_id, seller_id FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const escrows = escrowRows as any[];

    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }

    const escrow = escrows[0];

    // only buyer or seller in this escrow can cancel
    if (req.user?.id !== escrow.buyer_id && req.user?.id !== escrow.seller_id) {
      return res.status(403).json({ error: "Only buyer or seller can cancel this escrow" });
    }

    // can only cancel if not funded
    if (escrow.status !== "created") {
      return res.status(400).json({ error: "Escrow can only be cancelled before funding" });
    }

    // update escrow status
    await db.query(
      "UPDATE escrow_transactions SET status = 'cancelled', updated_at = NOW() WHERE id = ?",
      [escrowId]
    );

    // audit log
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (?, ?, 'cancel', 'escrow_transactions', ?, JSON_OBJECT('status','cancelled'), NOW())`,
      [uuidv4(), req.user?.id, escrowId]
    );

    res.json({
      message: "Escrow cancelled successfully",
      escrow: { id: escrowId, status: "cancelled" }
    });
  } catch (err) {
    console.error("Cancel escrow error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
