// Define roles
export enum UserRole {
  USER = "user",
  ADMIN = "admin",
}

export interface User {
  
    //  required data
    _id: string;
    name: string;
    email: string;
    role: UserRole;

    // password
    password: string;
    passwordResetToken?: string,
    passwordResetExpires?: Date,

    // optional user data
    avatar?: string;
    bio?:string;
    phone?:string;

    // email verification 
    isVerified: boolean; 
    verificationToken?: string;

    // login meta
    loginCount: number,
    lastLoginAt: Date,
    loggedInDevices: {
      deviceName: string;
      loginAt: Date;
    }[];

    // timestamp
    createdAt: Date
    updatedAt: Date
  }