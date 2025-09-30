import express from "express";
import session from "express-session";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.js";
import escrowRoutes from "./routes/escrow.js";
import webhookRoutes from "./routes/webhooks.js";
import usersRoutes from "./routes/users.js";
import disputesRoutes from "./routes/disputes.js";
import adminRoutes from "./routes/admin.js";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";

declare module "express-session" {
  interface SessionData {
    lastActivity?: number;
    user_id?: string;
    user_role?: string;
  }
}

dotenv.config();

const app = express();

app.use(cookieParser());

// CORS configuration driven by env var CORS_ORIGINS (comma-separated)
// Default includes prod FE and common Vite dev ports (5173, 5174)
const originsEnv = process.env.CORS_ORIGINS || "https://esc-prod-fe-6e536405a054.herokuapp.com,http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173,http://127.0.0.1:5174";
const allowedOrigins = originsEnv.split(",").map(o => o.trim()).filter(Boolean);

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS: Origin not allowed: ${origin}`));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
// Preflight handling for all routes (Express 5 + path-to-regexp v6 safe)
app.options(/.*/, cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Serve uploaded files
const uploadsRoot = path.resolve(process.env.UPLOADS_ROOT || "./uploads");
app.use("/uploads", express.static(uploadsRoot));
app.use(session({
  secret: process.env.JWT_SECRET || "default_secret",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 5 * 60 * 1000 }
}));

// Inactivity auto-logout middleware
app.use((req, res, next) => {
  if (req.session) {
    const now = Date.now();
    if (req.session.lastActivity && now - req.session.lastActivity > 5 * 60 * 1000) {
      req.session.destroy(() => {});
      return res.status(440).json({ error: "Session expired due to inactivity" });
    }
    req.session.lastActivity = now;
  }
  next();
});

app.use("/api/auth", authRoutes);
app.use("/api/escrow", escrowRoutes);
app.use("/webhooks", webhookRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/disputes", disputesRoutes);
app.use("/api/admin", adminRoutes);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
