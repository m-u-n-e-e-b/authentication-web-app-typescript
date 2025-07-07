import express, { Request, Response, Router } from "express";
import { register, login, deleteUser, getUserData, updateUser,
} from "../controllers/authController";
import { protect } from "../middleware/authMiddleware";

const router: Router = express.Router();

router.post("/register", register);
router.post("/login", login);

// Protected routes
router.delete("/delete", protect, deleteUser);
router.get("/me", protect, getUserData);
router.put("/update", protect, updateUser);

export default router;
