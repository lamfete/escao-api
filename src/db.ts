import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

const dbUrl = new URL(process.env.DATABASE_URL!);

const isLocal = dbUrl.hostname === "localhost" || dbUrl.hostname === "127.0.0.1";

const db = mysql.createPool({
  host: dbUrl.hostname,
  port: Number(dbUrl.port),
  user: dbUrl.username,
  password: dbUrl.password,
  database: dbUrl.pathname.replace("/", ""),
  ...(isLocal ? {} : { ssl: { rejectUnauthorized: true } })
});

export default db;
