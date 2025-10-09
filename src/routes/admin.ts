import { Router } from "express";
import type { Response } from "express";
import { authenticateJWT } from "../middleware/auth.js";
import type { AuthRequest } from "../middleware/auth.js";
import { requireAdmin } from "../middleware/kyc.js";
import db from "../db.js";

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
