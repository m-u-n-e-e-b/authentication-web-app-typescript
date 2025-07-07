import express, { Application } from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import authRoutes from "./routes/authRoutes";

dotenv.config();

const app: Application = express();
const PORT: number = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use("/api/auth", authRoutes);

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI as string)
  .then(() => {
    console.log("Connected to MongoDB");
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err: Error) => console.error("MongoDB connection error:", err));
