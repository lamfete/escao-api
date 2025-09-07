import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

const dbUrl = new URL(process.env.DATABASE_URL!);

const db = mysql.createPool({
  host: dbUrl.hostname,
  port: Number(dbUrl.port),
  user: dbUrl.username,
  password: dbUrl.password,
  database: dbUrl.pathname.replace("/", ""),
  ssl: { rejectUnauthorized: true }
});

export default db;
