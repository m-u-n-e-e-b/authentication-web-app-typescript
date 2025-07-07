import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import User from "../models/User";

// Extend Request type to include 'user'
interface AuthenticatedRequest extends Request {
  user?: string | JwtPayload | any;
}

export const protect = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    res.status(401).json({ message: "No token provided" });
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as JwtPayload & {id: string};

    const user = await User.findById(decoded.id).select("-password");
    if(!user){
      res.status(404).json({message: "User Does Not exist"})
    }

    req.user = user;

    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};


// interface body type (error) 