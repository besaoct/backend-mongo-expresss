
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

export interface AuthUser {
  
    _id: string;
    name: string;
    role: string;
    visibility: Visibility;

    // email
    email: string;
    isEmailVerified: boolean; 
    emailVerificationOTP: string | null,
    emailVerificationOTPExpires: Date | null,

    // password
    password: string;
    passwordResetOTPVerified: boolean | null,
    passwordResetOTP: string | null,
    passwordResetOTPExpires: Date | null,

    // tfa (two factor authentication)
    tfaEnabled: TfaEnabled, //yes or no
    tfaOTPVerified: boolean | null,
    tfaVerificationOTP: string | null,
    tfaVerificationOTPExpires: Date | null,

    // optional user data
    avatarUrl: string | null;
    bio:string | null;
    phone:string | null;

    // login meta
    loginCount: number,
    lastLoginAt: Date,
    LimitNumberOfLoggedInDevices: number
    loggedInDevices: {
      deviceId:string
      deviceName: string;
      sessionId: string;
      loginAt: Date;
    }[];

    // timestamp
    createdAt: Date
    updatedAt: Date
  }