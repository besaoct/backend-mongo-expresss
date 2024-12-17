//user model

import { model, Schema } from "mongoose";
import { User, UserRole } from "./userTypes";

const userSchema = new Schema<User>(
  {
    name: { type: String, required: true },
    role: {
      type: String,
      enum: Object.values(UserRole),
      default: UserRole.USER,
      required:true
    },

    // email
    email: { type: String, unique: true, required: true },
    isEmailVerified: { type: Boolean, default: false },
    emailVerificationOTP: { type: String, default: undefined},
    emailVerificationOTPExpires:{ type: Date, default: undefined},

  // password
    password: { type: String, required: true },
    passwordResetOTP: { type: String, default: undefined},
    passwordResetExpires: { type: Date, default: undefined},
    passwordResetVerified: { type: Boolean, default: undefined},

  //  optional user data
    avatarUrl: { type: String , default: undefined},
    bio: { type: String, default: undefined},
    phone: { type: String , default: undefined},

   
  // login metadata
    loginCount: { type: Number, default: 0 },
    lastLoginAt: { type: Date,  default: Date.now},
    loggedInDevices: {
      type: [
        {
          deviceId: { type: String, required: true , default: "Unknown"},
          deviceName: { type: String, required: true, default: "Unknown" },
          sessionId: { type: String, required:true},
          loginAt: { type: Date, default: Date.now },
        },
      ],
      default: [],
    },
  },

  { timestamps: true },
);

export default model<User>("User", userSchema);
