import { Schema, model, Document } from "mongoose";

// 1. Interface to describe User properties
export interface IUser extends Document {
  username: string;
  name: string;
  email: string;
  password: string;
}

// 2. User Schema definition
const userSchema = new Schema<IUser>({
  username: { type: String, required: true },
  name:     { type: String, required: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// 3. Export Mongoose model using the interface
export default model<IUser>("User", userSchema);
