export interface User {
  
    _id: string;
    name: string;
    role: string;
    visibility: string;

    // email
    email: string;
    isEmailVerified: boolean; 
    emailVerificationOTP: string | null,
    emailOTPExpirationInMins: number,
    emailVerificationOTPExpires: Date | null,

    // password
    password: string;
    passwordResetVerified: boolean | null,
    passwordResetOTP: string | null,
    passwordOTPExpirationInMins: number,
    passwordResetExpires: Date | null,

    // tfa (two factor authentication)
    tfaEnabled: string, //yes or no
    tfaOTPVerified: boolean | null,
    tfaResetOTP: string | null,
    tfaOTPExpirationInMins: number,
    tfaResetExpires: Date | null,

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