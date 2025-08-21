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

export default router;
