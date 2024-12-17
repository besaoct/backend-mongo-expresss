// Define roles
export enum UserRole {
  USER = "user",
  ADMIN = "admin",
}

export interface User {
  
    _id: string;
    name: string;
    role: UserRole;

    // email
    email: string;
    isEmailVerified: boolean; 
    emailVerificationOTP?: string,
    emailVerificationOTPExpires?: Date,

    // password
    password: string;
    passwordResetVerified?: boolean,
    passwordResetOTP?: string,
    passwordResetExpires?: Date,

    // optional user data
    avatar?: string;
    bio?:string;
    phone?:string;

    // login meta
    loginCount: number,
    lastLoginAt: Date,
    loggedInDevices: {
      deviceId:string
      deviceName: string;
      token: string;
      loginAt: Date;
    }[];

    // timestamp
    createdAt: Date
    updatedAt: Date
  }