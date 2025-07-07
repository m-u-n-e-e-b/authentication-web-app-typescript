import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User";


interface AuthenticatedRequest extends Request {
  user?: any;
}

// Register Controller
export const register = async (req: Request, res: Response) => {
  const { username, name, email, password, confirmpassword } = req.body;

  if (!email) {
    res.status(400).json({ message: "Email is Required" });
    return;
  } if (!password ) {
    res.status(400).json({ message: "Password is required" });
    return;
  } if ( !username ) {
    res.status(400).json({ message: "Username is required" });
    return;
  } if (!name) {
    res.status(400).json({ message: "Name is required" });
    return;
  }




  const existingUser = await User.findOne({ email });
  if (existingUser) {
    res.status(400).json({ message: "Email already in use" });
    return;
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({ username, name, email, password: hashedPassword});
  await newUser.save();

  const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET as string, { expiresIn: "7d" });

  res.status(201).json({ message: "User registered successfully", token });
};

// Login Controller
export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required" });
    return;
  }

  const user = await User.findOne({ email });
  if (!user) {
    res.status(401).json({ message: "Invalid email or password" });
    return;
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    res.status(401).json({ message: "Invalid email or password" });
    return;
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET as string, { expiresIn: "7d" });

  res.status(200).json({ message: "Login successful", token });
};

// Get User Data
export const getUserData = async (req: AuthenticatedRequest, res: Response) => {
  try {

    const user = req.user
    res.status(200).json({user});

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

// Update User
export const updateUser = async (req: AuthenticatedRequest, res: Response)=> {
  try {
    const { name, username, email } = req.body;

    if (name && username && email) {
      const updatedUser = await User.findByIdAndUpdate(
        req.user._id,
        { name, username, email },
        { new: true }
      ).select("-password");

      res.status(200).json({ message: "User updated", user: updatedUser });
    } else {
      res.status(400).json({ message: "All fields are required" });
    }
  } catch (err) {
    console.error("Update error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// Delete User
export const deleteUser = async (req: AuthenticatedRequest, res: Response) => {
  try {
    await User.findByIdAndDelete(req.user._id);
    res.status(200).json({message: "User Deleted"});
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ message: "Server error" });
  }
};
