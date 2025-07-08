import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User, { IUser } from "../models/User";


interface AuthenticatedRequest extends Request {
  user?: IUser; 
}



//=================================================Register=================================
export const register = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const { username, name, email, password} = req.body;

  if (!email) {
    res.status(404).json({ message: "Email is Required" });
  }
  if (!password) {
    res.status(404).json({ message: "Password is required" });
  }
  if (!username) {
    res.status(404).json({ message: "Username is required" });
  }
  if (!name) {
    res.status(404).json({ message: "Name is required" });
  }


  const existingUser = await User.findOne({ email });
  if (existingUser) {
    res.status(400).json({ message: "Email already in use" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, name, email, password: hashedPassword });
  await newUser.save();

  const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET as string, { expiresIn: "7d" });

  res.status(201).json({ message: "User registered successfully", token });
};



//=================================================Login=================================

export const login = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required" });
    return;
  }

  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    res.status(401).json({ message: "Invalid email or password" });
    return;
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET as string, { expiresIn: "7d" });

  res.status(200).json({ message: "Login successful", token });
};



//=================================================Get User=================================
export const getUserData = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    res.status(200).json({ user: req.user });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};



//=================================================Update User=================================
export const updateUser = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const { name, username, email } = req.body;

    if (!name || !username || !email) {
      res.status(400).json({ message: "All fields are required" });
      return;
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user?._id,
      { name, username, email },
      { new: true }
    ).select("-password");

    res.status(200).json({ message: "User updated", user: updatedUser });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};


//=================================================Delete User=================================
export const deleteUser = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    await User.findByIdAndDelete(req.user?._id);
    res.status(200).json({ message: "User deleted" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};
