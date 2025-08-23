import { Router } from "express";
import type { Request, Response } from "express";
import db from "../db.js";
import { v4 as uuidv4 } from "uuid";

const router = Router();

/**
 * POST /webhooks/payments
 * Handles incoming payment webhook from PG
 */
router.post("/payments", async (req: Request, res: Response) => {
  try {
    const rawPayload = req.body;
    const signature = req.headers["x-signature"] as string || null;

    // TODO: Verify signature properly with your PG secret
    if (!signature) {
      return res.status(400).json({ error: "Missing signature" });
    }

    const eventType = rawPayload.event || "unknown";
    const pgRef = rawPayload.pg_ref || null;

    // idempotency: check if this event already processed
    const eventId = uuidv4();
    const [existing] = await db.query(
      "SELECT id FROM webhook_events WHERE JSON_EXTRACT(payload, '$.pg_ref') = ? AND event_type = ?",
      [pgRef, eventType]
    );
    if ((existing as any[]).length > 0) {
      return res.status(200).json({ message: "Event already processed" });
    }

    // save raw event
    await db.query(
      `INSERT INTO webhook_events (id, source, event_type, payload, processed, created_at)
       VALUES (?, ?, ?, ?, FALSE, NOW())`,
      [eventId, "payment_gateway", eventType, JSON.stringify(rawPayload)]
    );

    // process if event = "payment_succeeded"
    if (eventType === "payment_succeeded" && pgRef) {
      // find payment intent
      const [piRows] = await db.query(
        "SELECT id, escrow_id FROM payment_intents WHERE pg_reference = ?",
        [pgRef]
      );
      const intents = piRows as any[];
      if (intents.length > 0) {
        const intent = intents[0];

        // update payment intent
        await db.query(
          "UPDATE payment_intents SET status = 'paid', paid_at = NOW(), raw_payload = ?, method = ? WHERE id = ?",
          [JSON.stringify(rawPayload), rawPayload.method || null, intent.id]
        );

        // update escrow
        await db.query(
          "UPDATE escrow_transactions SET status = 'funded', updated_at = NOW() WHERE id = ?",
          [intent.escrow_id]
        );

        // mark webhook as processed
        await db.query(
          "UPDATE webhook_events SET processed = TRUE WHERE id = ?",
          [eventId]
        );
      }
    }

    res.status(200).json({ message: "Webhook processed" });
  } catch (err) {
    console.error("Webhook error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /webhooks/payouts
 * Handles payout webhook events (seller disbursements)
 */
router.post("/payouts", async (req: Request, res: Response) => {
  try {
    const rawPayload = req.body;
    const signature = req.headers["x-signature"] as string || null;

    // TODO: verify with PG secret
    if (!signature) {
      return res.status(400).json({ error: "Missing signature" });
    }

    const eventType = rawPayload.event || "unknown";
    const pgRef = rawPayload.pg_ref || null;
    const payoutStatus = rawPayload.status || "pending";

    // idempotency check
    const eventId = uuidv4();
    const [existing] = await db.query(
      "SELECT id FROM webhook_events WHERE JSON_EXTRACT(payload, '$.pg_ref') = ? AND event_type = ?",
      [pgRef, eventType]
    );
    if ((existing as any[]).length > 0) {
      return res.status(200).json({ message: "Event already processed" });
    }

    // save webhook
    await db.query(
      `INSERT INTO webhook_events (id, source, event_type, payload, processed, created_at)
       VALUES (?, ?, ?, ?, FALSE, NOW())`,
      [eventId, "payment_gateway", eventType, JSON.stringify(rawPayload)]
    );

    if (pgRef) {
      // find payout
      const [payoutRows] = await db.query(
        "SELECT id, escrow_id FROM payouts WHERE pg_reference = ?",
        [pgRef]
      );
      const payouts = payoutRows as any[];

      if (payouts.length > 0) {
        const payout = payouts[0];

        // update payout status
        await db.query(
          "UPDATE payouts SET status = ?, sent_at = NOW(), pg_reference = ? WHERE id = ?",
          [payoutStatus, pgRef, payout.id]
        );

        // update escrow if payout succeeded
        if (payoutStatus === "sent") {
          await db.query(
            "UPDATE escrow_transactions SET status = 'completed', updated_at = NOW() WHERE id = ?",
            [payout.escrow_id]
          );
        }

        // mark webhook as processed
        await db.query(
          "UPDATE webhook_events SET processed = TRUE WHERE id = ?",
          [eventId]
        );

        // audit log
        await db.query(
          `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
           VALUES (?, ?, 'payout_webhook', 'payouts', ?, JSON_OBJECT('pg_ref', ?, 'status', ?), NOW())`,
          [uuidv4(), "system", payout.id, pgRef, payoutStatus]
        );
      }
    }

    res.status(200).json({ message: "Payout webhook processed" });
  } catch (err) {
    console.error("Payout webhook error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
