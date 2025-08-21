import express from "express";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.js";
import escrowRoutes from "./routes/escrow.js";
import webhookRoutes from "./routes/webhooks.js";
import usersRoutes from "./routes/users.js";

dotenv.config();
const app = express();
app.use(express.json());

app.use("/api/auth", authRoutes);
app.use("/api/escrow", escrowRoutes);
app.use("/webhooks", webhookRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/escrow", escrowRoutes);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
