import { Router } from "express";
import type { Response } from "express";
import express from "express";
import db from "../db.js";
import { v4 as uuidv4 } from "uuid";
import { authenticateJWT } from "../middleware/auth.js";
import type { AuthRequest } from "../middleware/auth.js";
import { requireKYCVerified } from "../middleware/kyc.js";
import multer from "multer";
import path from "path";
import fs from "fs";


const router = Router();

// Ensure JSON parsing
router.use(express.json());

/**
 * POST /api/escrow
 * Body: { amount: number, currency?: string, counterparty_id: string }
 * Note: counterparty_id can be a user UUID or an email address. If email is provided, it will be resolved to the user's id.
 */
router.post("/", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const { amount, currency, counterparty_id } = req.body;

    // Use session user_id and user_role; fallback to JWT user (so it works without session cookie)
    const user_id = req.session?.user_id || req.user?.id;
    const user_role = req.session?.user_role || req.user?.role;

    if (!user_id || !user_role) {
      return res.status(401).json({ error: "User not logged in" });
    }
    if (amount == null || Number.isNaN(Number(amount)) || Number(amount) <= 0) {
      return res.status(400).json({ error: "Valid amount is required" });
    }
    if (!counterparty_id || typeof counterparty_id !== "string") {
      return res.status(400).json({ error: "counterparty_id is required" });
    }
    if (user_role !== "buyer" && user_role !== "seller") {
      return res.status(403).json({ error: "Only buyers or sellers can create escrow" });
    }

    // Resolve counterparty_id if email provided
    let resolvedCounterpartyId: string | null = null;
    if (counterparty_id.includes("@")) {
      const [cpRows] = await db.query("SELECT id FROM users WHERE email = ?", [counterparty_id]);
      const cps = cpRows as any[];
      if (cps.length === 0) {
        return res.status(404).json({ error: "Counterparty not found for the given email" });
      }
      resolvedCounterpartyId = cps[0].id as string;
    } else {
      // Assume it's already a UUID (or valid user id) as provided
      resolvedCounterpartyId = counterparty_id;
    }

    // Assign buyer/seller based on role
    let buyer_id, seller_id;
    if (user_role === "buyer") {
      buyer_id = user_id;
      seller_id = resolvedCounterpartyId;
    } else {
      seller_id = user_id;
      buyer_id = resolvedCounterpartyId;
    }

    // generate escrow ID
    const escrowId = uuidv4();

    await db.query(
      `INSERT INTO escrow_transactions (id, buyer_id, seller_id, amount, currency, status, created_at, updated_at, deadline_confirm)
       VALUES (?, ?, ?, ?, ?, 'created', NOW(), NOW(), DATE_ADD(NOW(), INTERVAL 24 HOUR))`,
      [escrowId, buyer_id, seller_id, Number(amount), currency || "IDR"]
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
 * GET /api/escrow
 * Returns escrows where the logged-in user is buyer or seller.
 * Optional query params:
 *   - status: string
 *   - limit: number (default 20, max 100)
 *   - offset: number (default 0)
 *   - as: 'buyer' | 'seller' (optional filter to one side)
 *   - user_id or email: only honored for admin users to query on behalf of someone
 */
router.get("/", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    // Base identity is the current token/session user
    let effectiveUserId: string | undefined = req.user?.id || req.session?.user_id;
    const requesterRole = req.user?.role || req.session?.user_role;

    if (!effectiveUserId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const status = (req.query.status as string) || undefined;
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const offset = parseInt(req.query.offset as string) || 0;
    const as = (req.query.as as string) || undefined; // buyer | seller

    // Admin can override target user via user_id or email
    let adminOverrideUsed = false;
    if (requesterRole === "admin") {
      const targetUserId = (req.query.user_id as string) || undefined;
      const targetEmail = (req.query.email as string) || undefined;
      if (targetUserId) {
        effectiveUserId = targetUserId;
        adminOverrideUsed = true;
      } else if (targetEmail) {
        const [uRows] = await db.query("SELECT id FROM users WHERE email = ?", [targetEmail]);
        const list = uRows as any[];
        if (list.length > 0) {
          effectiveUserId = list[0].id as string;
          adminOverrideUsed = true;
        } else {
          return res.status(404).json({ error: "Target user not found for given email" });
        }
      }
    }

    // Build query
    let sql = `SELECT e.id, e.amount, e.currency, e.status, e.created_at, e.updated_at,
                      e.buyer_id, e.seller_id
               FROM escrow_transactions e
               WHERE `;
    const params: any[] = [];

    if (as === "buyer") {
      sql += "e.buyer_id = ?";
      params.push(effectiveUserId);
    } else if (as === "seller") {
      sql += "e.seller_id = ?";
      params.push(effectiveUserId);
    } else {
      sql += "(e.buyer_id = ? OR e.seller_id = ?)";
      params.push(effectiveUserId, effectiveUserId);
    }

    if (status) {
      sql += " AND e.status = ?";
      params.push(status);
    }

    sql += " ORDER BY e.created_at DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const [rows] = await db.query(sql, params);
    return res.json({
      escrows: rows,
      paging: { limit, offset, status: status || null },
      filter: { user_id: effectiveUserId, as: as || null, adminOverrideUsed }
    });
  } catch (err) {
    console.error("List my escrows error:", err);
    return res.status(500).json({ error: "Internal server error" });
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
        e.seller_proof_url, e.seller_receipt_number, e.buyer_proof_url,
        e.pg_reference,
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
 * GET /api/escrow/:id/summary
 * Returns payment info and proofs (seller delivery, buyer receipt) for the escrow
 */
router.get("/:id/summary", authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;

    // Fetch escrow to validate existence and authorization (buyer/seller or admin)
    const [escrowRows] = await db.query(
      `SELECT e.id, e.buyer_id, e.seller_id, e.seller_proof_url, e.seller_receipt_number, e.buyer_proof_url,
              b.email AS buyer_email, s.email AS seller_email
       FROM escrow_transactions e
       LEFT JOIN users b ON e.buyer_id = b.id
       LEFT JOIN users s ON e.seller_id = s.id
       WHERE e.id = ?`,
      [escrowId]
    );
    const escrows = escrowRows as any[];
    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }
    const escrow = escrows[0];

    // Authorization: admin or party to the escrow
    if (req.user?.role !== "admin" && req.user?.id !== escrow.buyer_id && req.user?.id !== escrow.seller_id) {
      return res.status(403).json({ error: "Forbidden" });
    }

    // Latest payment intent
    const [piRows] = await db.query(
      `SELECT method, pg_reference, status, paid_at
       FROM payment_intents
       WHERE escrow_id = ?
       ORDER BY paid_at DESC, id DESC
       LIMIT 1`,
      [escrowId]
    );
    const payment = (piRows as any[])[0] || null;

    // Helper to parse JSON metadata safely
    const parseMeta = (val: any) => {
      if (!val) return null;
      if (typeof val === "string") {
        try { return JSON.parse(val); } catch { return null; }
      }
      if (typeof val === "object") return val;
      return null;
    };

    // Seller proof: last 'ship' audit for this escrow
    const [shipRows] = await db.query(
      `SELECT metadata FROM audit_logs
       WHERE entity = 'escrow_transactions' AND entity_id = ? AND action = 'ship'
       ORDER BY created_at DESC LIMIT 1`,
      [escrowId]
    );
    const shipMeta = parseMeta((shipRows as any[])[0]?.metadata);
    const seller_proof = shipMeta
      ? {
          tracking_number: shipMeta.tracking_number || escrow.seller_receipt_number || null,
          seller_proof_url: escrow.seller_proof_url || (shipMeta.file ? (shipMeta.file.url || null) : null),
          file: shipMeta.file
            ? {
                field: shipMeta.file.field || null,
                name: shipMeta.file.name || null,
                type: shipMeta.file.type || null,
                size: shipMeta.file.size || null,
                url: shipMeta.file.url || null
              }
            : null,
        }
      : null;

    // Buyer receipt: last 'upload_receipt' audit
    const [rcpRows] = await db.query(
      `SELECT metadata FROM audit_logs
       WHERE entity = 'escrow_transactions' AND entity_id = ? AND action = 'upload_receipt'
       ORDER BY created_at DESC LIMIT 1`,
      [escrowId]
    );
    const rcpMeta = parseMeta((rcpRows as any[])[0]?.metadata);
    const buyer_receipt = rcpMeta
      ? {
          receipt_url: rcpMeta.receipt_url || null,
          file: rcpMeta.file
            ? {
                field: rcpMeta.file.field || null,
                name: rcpMeta.file.name || null,
                type: rcpMeta.file.type || null,
                size: rcpMeta.file.size || null,
              }
            : null,
        }
      : null;

    return res.json({
      escrow_id: escrowId,
      buyer_email: escrow.buyer_email || null,
      seller_email: escrow.seller_email || null,
      payment,
      seller_proof,
      buyer_receipt,
    });
  } catch (err) {
    console.error("Escrow summary error:", err);
    return res.status(500).json({ error: "Internal server error" });
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
    
    // Accept common aliases for robustness
    const method = (req.body?.method ?? req.body?.payment_method ?? req.body?.paymentMethod ?? "").toString();
    const pg_reference = (req.body?.pg_reference ?? req.body?.pg_ref ?? req.body?.payment_reference ?? req.body?.reference ?? "").toString();
    const qr_code_url = (req.body?.qr_code_url ?? req.body?.qrCodeUrl ?? null) || null;

    if (!method?.trim() || !pg_reference?.trim()) {
      return res.status(400).json({
        error: "method and pg_reference are required",
        received_keys: Object.keys(req.body || {}),
      });
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
 * Marks escrow as shipped (seller confirms shipping) and stores optional proof file.
 */
// Ensure shipping directory exists
const shippingDir = path.resolve(process.env.UPLOADS_ROOT || "./uploads", "shipping");
fs.mkdirSync(shippingDir, { recursive: true });
const shippingStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, shippingDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname) || "";
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  },
});
const shippingUpload = multer({ storage: shippingStorage });

router.post("/:id/ship", authenticateJWT, shippingUpload.any(), async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;
    console.log("Ship request body:", req.body);
    // Normalize first file (if any) for logging/audit
    let firstFile: Express.Multer.File | null = null;
    if (req.files) {
      const fl = req.files as unknown;
      if (Array.isArray(fl)) {
        firstFile = (fl as Express.Multer.File[])[0] ?? null;
      } else if (fl && typeof fl === "object") {
        const dict = fl as Record<string, Express.Multer.File[]>;
        const k = Object.keys(dict)[0];
        if (k) firstFile = dict[k]?.[0] ?? null;
      }
    }
    if (firstFile) {
      console.log("Ship first file:", {
        fieldname: firstFile.fieldname,
        originalname: firstFile.originalname,
        mimetype: firstFile.mimetype,
        size: firstFile.size,
      });
    }
    
    if (!req.body) {
      return res.status(400).json({ error: "No request body received" });
    }
    
    // Accept alias fields for tracking/shipping receipt
    const tracking_number = (req.body?.tracking_number
      ?? req.body?.tracking_no
      ?? req.body?.trackingNo
      ?? req.body?.shipping_receipt
      ?? req.body?.shipping_receipt_number
      ?? req.body?.receipt
      ?? "").toString();
    const baseUrl = process.env.BASE_URL || "";
    const seller_proof_url = firstFile ? `${baseUrl}/uploads/shipping/${path.basename((firstFile as any).path)}` : null;

    console.log("Current user role:", req.user?.role);
    
    // only sellers can ship
    if (req.user?.role !== "seller") {
      return res.status(403).json({ 
        error: "Only sellers can mark escrow as shipped",
        current_role: req.user?.role 
      });
    }

    // check seller KYC status
    const [sellerRows] = await db.query(
      "SELECT kyc_status FROM users WHERE id = ?",
      [req.user?.id]
    );
    const sellers = sellerRows as any[];
    if (sellers.length === 0 || sellers[0].kyc_status !== "verified") {
      return res.status(403).json({ error: "Seller is not KYC verified" });
    }

    // check escrow and verify the caller is the seller of this escrow
    const [escrowRows] = await db.query(
      "SELECT id, status, seller_id FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const escrows = escrowRows as any[];

    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }

    const escrow = escrows[0];

    // seller must be the seller of this escrow
    if (escrow.seller_id !== req.user?.id) {
      return res.status(403).json({ error: "You are not the seller of this escrow" });
    }
    console.log("Current escrow status for shipping:", escrow.status);

    if (escrow.status !== "funded") {
      return res.status(400).json({ 
        error: "Escrow must be in 'funded' state before shipping",
        current_status: escrow.status 
      });
    }

    // update escrow status and persist seller proof + receipt number (do not overwrite if not provided)
    await db.query(
      "UPDATE escrow_transactions SET status = 'shipped', seller_proof_url = COALESCE(?, seller_proof_url), seller_receipt_number = COALESCE(?, seller_receipt_number), updated_at = NOW() WHERE id = ?",
      [seller_proof_url, tracking_number || null, escrowId]
    );

    // log audit
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (
         ?, ?, 'ship', 'escrow_transactions', ?,
         JSON_OBJECT(
           'tracking_number', ?,
           'file', JSON_OBJECT('field', ?, 'name', ?, 'type', ?, 'size', ?, 'url', ?)
         ),
         NOW()
       )`,
      [
        uuidv4(),
        req.user?.id,
        escrowId,
        tracking_number || null,
        firstFile?.fieldname || null,
        firstFile?.originalname || null,
        firstFile?.mimetype || null,
        firstFile?.size || null,
        seller_proof_url,
      ]
    );

    res.json({
      message: "Escrow marked as shipped",
      escrow: { id: escrowId, status: "shipped", tracking_number: tracking_number || null, seller_proof_url: seller_proof_url }
    });
  } catch (err) {
    console.error("Ship escrow error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /api/escrow/:id/receipt
 * Buyer uploads proof of receipt (file or URL). This does not change status; use /:id/confirm to confirm receipt.
 * Accepts:
 *  - multipart/form-data with a file field: receipt | proof | file | media
 *  - JSON/x-www-form-urlencoded with file_url (absolute URL)
 */
// Ensure receipts directory exists
const receiptsDir = path.resolve(process.env.UPLOADS_ROOT || "./uploads", "receipts");
fs.mkdirSync(receiptsDir, { recursive: true });
const receiptStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, receiptsDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname) || "";
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  },
});
const receiptUpload = multer({ storage: receiptStorage });

router.post("/:id/receipt", authenticateJWT, receiptUpload.any(), async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;

    // only buyers can upload receipt
    if (req.user?.role !== "buyer") {
      return res.status(403).json({ error: "Only buyers can upload receipt proof" });
    }

    // fetch escrow and verify ownership and state
    const [escrowRows] = await db.query(
      "SELECT id, status, buyer_id FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const escrows = escrowRows as any[];
    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }
    const escrow = escrows[0];
    if (escrow.buyer_id !== req.user?.id) {
      return res.status(403).json({ error: "You are not the buyer of this escrow" });
    }
    if (escrow.status !== "shipped") {
      return res.status(400).json({ error: "Escrow must be in 'shipped' state to upload receipt" });
    }

    // pick first file if present
    let firstFile: Express.Multer.File | undefined;
    if (Array.isArray(req.files) && req.files.length > 0) {
      // try to prefer specific fieldnames if present
      const preferred = (req.files as Express.Multer.File[]).find(f => ["receipt", "proof", "file", "media"].includes(f.fieldname));
      firstFile = preferred || (req.files as Express.Multer.File[])[0];
    }

    // derive URL
    const baseUrl = process.env.BASE_URL || "";
    const receipt_url = firstFile
      ? `${baseUrl}/uploads/receipts/${path.basename(firstFile.path)}`
      : ((req.body as any)?.file_url as string | undefined);

    if (!receipt_url) {
      return res.status(400).json({ error: "Provide a receipt file (multipart) or file_url" });
    }

    // persist buyer proof URL on escrow
    await db.query(
      "UPDATE escrow_transactions SET buyer_proof_url = COALESCE(?, buyer_proof_url), updated_at = NOW() WHERE id = ?",
      [receipt_url, escrowId]
    );

    // audit log
    await db.query(
      `INSERT INTO audit_logs (id, actor_id, action, entity, entity_id, metadata, created_at)
       VALUES (
         ?, ?, 'upload_receipt', 'escrow_transactions', ?,
         JSON_OBJECT('receipt_url', ?, 'file', JSON_OBJECT('field', ?, 'name', ?, 'type', ?, 'size', ?)),
         NOW()
       )`,
      [
        uuidv4(),
        req.user?.id,
        escrowId,
        receipt_url,
        firstFile?.fieldname || null,
        firstFile?.originalname || null,
        firstFile?.mimetype || null,
        firstFile?.size || null,
      ]
    );

    return res.status(201).json({
      message: "Receipt uploaded successfully",
      receipt_url,
      escrow: { id: escrowId, status: escrow.status, buyer_proof_url: receipt_url }
    });
  } catch (err) {
    console.error("Upload receipt error:", err);
    return res.status(500).json({ error: "Internal server error" });
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
      "SELECT id, status, buyer_id FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const escrows = escrowRows as any[];

    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }

    const escrow = escrows[0];

    // Ensure the caller is the buyer of this escrow
    if (escrow.buyer_id !== req.user?.id) {
      return res.status(403).json({ error: "You are not the buyer of this escrow" });
    }

    if (escrow.status !== "shipped") {
      return res.status(400).json({ error: "Escrow must be in 'shipped' state before confirming", current_status: escrow.status });
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
      "SELECT id, status, seller_id FROM escrow_transactions WHERE id = ?",
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

    // check seller KYC status
    const [sellerRows] = await db.query(
      "SELECT kyc_status FROM users WHERE id = ?",
      [escrow.seller_id]
    );
    const sellers = sellerRows as any[];
    if (sellers.length === 0 || sellers[0].kyc_status !== "verified") {
      return res.status(403).json({ error: "Seller is not KYC verified" });
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

/**
 * POST /api/escrow/:id/release
 * Buyer releases funds → payout to seller
 */
router.post("/:id/release", authenticateJWT, requireKYCVerified, async (req: AuthRequest, res: Response) => {
  try {
    const escrowId = req.params.id;

    const [escrowRows] = await db.query(
      "SELECT id, status, buyer_id, seller_id FROM escrow_transactions WHERE id = ?",
      [escrowId]
    );
    const escrows = escrowRows as any[];

    if (escrows.length === 0) {
      return res.status(404).json({ error: "Escrow not found" });
    }

    const escrow = escrows[0];

    // only buyer can release
    if (req.user?.id !== escrow.buyer_id) {
      return res.status(403).json({ error: "Only buyer can release funds" });
    }

    if (escrow.status !== "confirmed") {
      return res.status(400).json({ error: "Escrow must be confirmed before release" });
    }

    // update status
    await db.query(
      "UPDATE escrow_transactions SET status = 'released', updated_at = NOW() WHERE id = ?",
      [escrowId]
    );

    // create payout record
    const payoutId = uuidv4();
    await db.query(
      `INSERT INTO payouts (id, escrow_id, seller_id, amount, status, created_at)
       VALUES (?, ?, ?, (SELECT amount FROM escrow_transactions WHERE id = ?), 'pending', NOW())`,
      [payoutId, escrowId, escrow.seller_id, escrowId]
    );

    res.json({
      message: "Funds released and payout initiated",
      payout: { id: payoutId, escrow_id: escrowId, status: "pending" }
    });
  } catch (err) {
    console.error("Release escrow error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
