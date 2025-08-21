import { Router } from "express";
import type { Response } from "express";
import { authenticateJWT } from "../middleware/auth.js";
import type { AuthRequest } from "../middleware/auth.js";

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

export default router;