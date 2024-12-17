//user model

import { model, Schema } from "mongoose";
import { User, UserRole } from "./userTypes";

const userSchema = new Schema<User>(
  {
    // required data
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    role: {
      type: String,
      enum: Object.values(UserRole),
      default: UserRole.USER,
      required:true
    },
    password: { type: String, required: true },

  //  optional user data
    avatar: { type: String , default: undefined},
    bio: { type: String, default: undefined},
    phone: { type: String , default: undefined},

  // email verification
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String, default: undefined},
   
  // login metadata
    loginCount: { type: Number, default: 0 },
    lastLoginAt: { type: Date,  default: Date.now},
    loggedInDevices: {
      type: [
        {
          deviceName: { type: String, required: true },
          loginAt: { type: Date, default: Date.now },
        },
      ],
      default: [],
    },
  },

  { timestamps: true },
);

export default model<User>("User", userSchema);
