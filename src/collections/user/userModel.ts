//user model

import { model, Schema } from "mongoose";
import { User } from "./userTypes";

// Enum for visibility
export enum Visibility {
  Private = "private",
  Public = "public",
}

// Enum for Two-Factor Authentication (TFA) status
export enum TfaEnabled {
  Yes = "yes",
  No = "no",
}

const userSchema = new Schema<User>(
  {
    name: { type: String, required: true },
    role: {
      type: String,
      default: "user",
      required: true,
    },
    visibility: {
      type: String,
      enum: Object.values(Visibility), // Enum values for validation
      default: Visibility.Private,
      required: true,
    },

    // ⁡⁣⁣⁢email⁡
    email: { type: String, unique: true, required: true },
    isEmailVerified: { type: Boolean, default: false, required: true },
    emailVerificationOTP: { type: String, default: null },
    emailOTPExpirationInMins: { type: Number, default: 10 },
    emailVerificationOTPExpires: { type: Date, default: null },

    // ⁡⁣⁣⁢password⁡
    password: { type: String, required: true },
    passwordResetVerified: { type: Boolean, default: null },
    passwordResetOTP: { type: String, default: null },
    passwordOTPExpirationInMins: { type: Number, default: 10 },
    passwordResetExpires: { type: Date, default: null },

    // ⁡⁣⁣⁢tfa (two factor authentication)⁡
    tfaEnabled: { type: String, enum: Object.values(TfaEnabled), default: TfaEnabled.No, required: true }, 
    tfaOTPVerified: { type: Boolean, default: null },
    tfaResetOTP: { type: Boolean, default: null },
    tfaOTPExpirationInMins: { type: Number, default: 10 },
    tfaResetExpires: { type: Date, default: null },

    // ⁡⁣⁣⁢ optional user data⁡
    avatarUrl: { type: String, default: null },
    bio: { type: String, default: null },
    phone: { type: String, default: null },

    // ⁡⁣⁣⁢login metadata⁡
    loginCount: { type: Number, default: 0, required: true },
    lastLoginAt: { type: Date, default: Date.now, required: true },
    LimitNumberOfLoggedInDevices: { type: Number, default: 5, required: true },
    loggedInDevices: {
      type: [
        {
          deviceId: { type: String, default: "Unknown", required: true },
          deviceName: { type: String, default: "Unknown", required: true },
          sessionId: { type: String, default: "Unknown", required: true },
          loginAt: { type: Date, default: Date.now, required: true },
        },
      ],
      default: [],
    },
  },

  { timestamps: true },
);

export default model<User>("User", userSchema);
