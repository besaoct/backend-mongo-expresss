import { model, Schema } from "mongoose";
import { AuthUser, TfaEnabled, Visibility } from "./authUserTypes";


const authUserSchema = new Schema<AuthUser>(
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
    emailVerificationOTPExpires: { type: Date, default: null },

    // ⁡⁣⁣⁢password⁡
    password: { type: String, required: true },
    passwordResetOTPVerified: { type: Boolean, default: null },
    passwordResetOTP: { type: String, default: null },
    passwordResetOTPExpires: { type: Date, default: null },

    // ⁡⁣⁣⁢tfa (two factor authentication)⁡
    tfaEnabled: {
      type: String,
      enum: Object.values(TfaEnabled),
      default: TfaEnabled.No,
      required: true,
    },
    tfaOTPVerified: { type: Boolean, default: null },
    tfaVerificationOTP: { type: Boolean, default: null },
    tfaVerificationOTPExpires: { type: Date, default: null },

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

export default model<AuthUser>("User", authUserSchema);
