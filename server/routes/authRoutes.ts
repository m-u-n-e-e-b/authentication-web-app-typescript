import express from "express";
import {
  register,
  login,
  deleteUser,
  getUserData,
  updateUser,
} from "../controllers/authController";
import { protect } from "../middleware/authMiddleware";

const router = express.Router();

// Registeration and Login
router.post("/register", register);
router.post("/login", login);

// Get User, Update User, Delete User using Middleware
router.get("/me", protect, getUserData);
router.put("/update", protect, updateUser);
router.delete("/delete", protect, deleteUser);

export default router;
