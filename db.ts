import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

// TiDB recommended connection options
const db = mysql.createPool({
  host: process.env.DB_HOST!,
  user: process.env.DB_USER!,
  password: process.env.DB_PASS!,
  database: process.env.DB_NAME!,
  port: Number(process.env.DB_PORT) || 4000, // TiDB default port is 4000
  ssl: {
    // Optional: enable SSL if TiDB server requires it
    rejectUnauthorized: true,
  },
  // Optional: recommended flags for TiDB
  timezone: "Z",
  multipleStatements: true,
  connectionLimit: 10,
});

export default db;