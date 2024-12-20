import { NextFunction, Request, Response } from "express";
import createHttpError from "http-errors";
import bcrypt from "bcrypt";
import userModel from "./userModel";
import {  JwtPayload, sign, verify, } from "jsonwebtoken";
import { config } from "../../config";
import { User, } from "./userTypes";
import { validationResult } from "express-validator";
import { sendOTPResetEmail, sendVerificationEmail } from "../../services/node-gmail";
import DeviceDetector from "device-detector-js";
import { createHash } from "crypto";
import { v4 as uuidv4 } from "uuid"; // UUID for sessionId generation

/* 
|--------------------------------------------------------------------------
| Utility Function: Generate 6-Digit OTP
|--------------------------------------------------------------------------
*/
const generateOTP = (): string => Math.floor(100000 + Math.random() * 900000).toString();

/* 
|--------------------------------------------------------------------------
| User Registration Controller
|--------------------------------------------------------------------------
| Handles new user registration:
| 1. Validates input using express-validator.
| 2. Checks if the user already exists.
| 3. Hashes the password securely.
| 4. Generates a 6-digit OTP for email verification.
| 5. Sends the verification email.
*/
const createUser = async (req: Request, res: Response, next: NextFunction) => {
  // Input validation
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    res.status(400).json({
      message: "Validation failed",
      errors: errors.array(),
    });

    return next();
  }

  const { name, email, password, role } = req.body;

  try {
    // Check if user with the same email already exists
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return next(createHttpError(400, "User already exists with this email."));
    }

    // Hash the password using bcrypt with a cost factor of 12
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate a 6-digit OTP for email verification
    const verificationOTP = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 minutes

    // Create the user and save to database
    const newUser: User = await userModel.create({
      name,
      email,
      password: hashedPassword,
      role: role || 'user',
      emailVerificationOTP: verificationOTP,
      verificationOTPExpires: otpExpiry,
    });

    // Send a verification email
    await sendVerificationEmail(newUser.email, verificationOTP);

    // Respond with success message
    res.status(201).json({
      success: true,
      message: "User registered successfully. Please verify your email.",
    });
  } catch (err) {
    return next(createHttpError(500, `Error while creating user: ${err}`));
  }
};

/* 
|--------------------------------------------------------------------------
| Email Verification Controller (Verify OTP)
|--------------------------------------------------------------------------
| 1. Validates the OTP and its expiry.
| 2. Marks the user as verified.
| 3. Removes OTP data from the user document.
*/
const verifyEmail = async (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: errors.array(),
    });
    return next();
  }

  const { email, otp } = req.body;

  try {
    // Find the user by email
    const user = await userModel.findOne({ email });
    if (!user) {
      return next(createHttpError(404, "User not found."));
    }

    // Check if email is already verified
    if (user.isEmailVerified) {
      res.status(410).json({
        success: false,
        message: "Email is already verified. OTP is no longer valid.",
      });

      return next();
    }

    // Validate OTP and its expiry
    if (
      user.emailVerificationOTP !== otp ||
      (user.emailVerificationOTPExpires &&
        new Date() > new Date(user.emailVerificationOTPExpires))
    ) {
      return next(createHttpError(401, "OTP is expired or invalid. Please request a new OTP by logging in."));
    }

    // Mark the user as verified
    user.isEmailVerified = true;
    user.emailVerificationOTP = null;
    user.emailVerificationOTPExpires = null;
    await user.save();

    res.status(202).json({
      success: true,
      message: "Email successfully verified.",
    });
  } catch (err) {
    return next(createHttpError(500, `Error verifying email: ${err}`));
  }
};

/* 
|--------------------------------------------------------------------------
| User Login Controller
|--------------------------------------------------------------------------
| Handles user login:
| 1. Validates input.
| 2. Checks if the user exists and is verified.
| 3. Verifies the provided password.
| 4. Generates and returns an access token (JWT).
*/
const loginUser = async (req: Request, res: Response, next: NextFunction) => {
  
    // Input validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({
        success: false,
        message: "Validation failed",
        errors: errors.array(),
      });
      return next();
    }

    
  const hashDeviceId = (ip: string, deviceName: string): string => {
    const rawId = `${ip}_${deviceName}`;
    return createHash("sha256").update(rawId).digest("hex");
  };

  const deviceDetector = new DeviceDetector();
  const userAgent = req.headers["user-agent"] || ""; // Extract User-Agent header

  const deviceInfo = deviceDetector.parse(userAgent); // Parse device info

  const ipAddress =
    (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || // Extract first IP if behind proxy
    req.socket.remoteAddress || // Direct IP
    "Unknown IP";

  const deviceName = `${deviceInfo.client?.name || "Unknown Browser"} on ${
    deviceInfo.os?.name || "Unknown OS"
  } (${deviceInfo.device?.type || "Unknown Device"})`;

  // Combine and hash IP and DeviceName
  const uniqueDeviceId = hashDeviceId(ipAddress, deviceName);

  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await userModel.findOne({ email });
    if (!user) {
      return next(createHttpError(404, "User not found."));
    }

    // Check if the email is verified
    if (!user.isEmailVerified ) {
      // Generate a new OTP and update the user document
      const newOTP = generateOTP();
      const otpExpiry = new Date(Date.now() + (Number(user.emailOTPExpirationInMins) || 10)  * 60 * 1000); // OTP valid for 10 minutes (default)
      user.emailVerificationOTP = newOTP;
      user.emailVerificationOTPExpires = otpExpiry;
      await user.save();

      // Send the verification email with the new OTP
      await sendVerificationEmail(user.email, newOTP);

      res.status(400).json({
        success: false,
        message:
          "Please verify your email first. A new OTP has been sent to your email.",
      });

      return next();
    }

    // Compare the provided password with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return next(createHttpError(401, "Incorrect email or password."));
    }

    // Determine if it's the user's first login
    const isFirstLogin = user.loginCount === 0;

    // Increment login count and update last login date in one save
    user.loginCount = (user.loginCount || 0) + 1;
    user.lastLoginAt = new Date();

    // Prevent duplication: Check if the device already exists
    const existingDeviceIndex = user.loggedInDevices.findIndex(
      (device) => (device.deviceId === uniqueDeviceId),
    );


// Generate sessionId
const sessionId = uuidv4();

// Generate JWTs
const accessToken = sign(
  {
    sub: user._id,
    role: user.role,
    email: user.email,
    deviceId: uniqueDeviceId,
    sessionId,
  },
  config.jwtSecret as string,
  { expiresIn: "15m", algorithm: "HS256" }
);

const refreshToken = sign(
  {
    sub: user._id,
    role: user.role,
    email: user.email,
    deviceId: uniqueDeviceId,
    sessionId,
  },
  config.jwtSecret as string,
  { expiresIn: "7d", algorithm: "HS256" }
);


    if (existingDeviceIndex !== -1) {
      user.loggedInDevices[existingDeviceIndex].sessionId= sessionId  ; 
      user.loggedInDevices[existingDeviceIndex].loginAt = new Date();

    } else {

      // If device is new, add it to the list
      user.loggedInDevices.push({
        deviceId: uniqueDeviceId,
        deviceName: deviceName,
        sessionId: sessionId ,
        loginAt: new Date(),
      });
    }


    // Limit the number of devices (keep only the last 5)
    if (user.loggedInDevices.length > (Number(user.LimitNumberOfLoggedInDevices) || 5)) {
      user.loggedInDevices = user.loggedInDevices.slice(-(Number(user.LimitNumberOfLoggedInDevices) || 5)); // Keep only the last 5 devices(default)
    }

    // Save the updated user details
    await user.save();


     // Set the refresh token in a secure HTTP-only cookie
      res.cookie('refreshToken', refreshToken, {
            httpOnly: true, // Ensures the cookie can't be accessed via JavaScript
            secure: config.env === 'production', // Ensures it is sent over HTTPS only in production
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });


    // Respond with the access token
    res.status(200).json({
      success: true,
      newUser: isFirstLogin,
      message: isFirstLogin ? `Hey ${user.name}! Welcome` : "Login successful.",
      accessToken: accessToken,
      data: {
        name: user.name,
        email: user.email,
        role: user.role,
        loginCount: user.loginCount,
        lastLoginAt: user.lastLoginAt,
        loggedInDevices: user.loggedInDevices.map((device) => ({
          deviceId: device.deviceId ,
          deviceName: device.deviceName,
          sessionId: device.sessionId,
          loginAt: device.loginAt,
        })),
      },
    });
  } catch (err) {
    return next(createHttpError(500, `Error while logging in: ${err}`));
  }
};

/* 
|--------------------------------------------------------------------------
| Get Logged-in User Info
|--------------------------------------------------------------------------
| Fetches details of the currently logged-in user using their JWT:
| 1. Extracts the user ID from the JWT token.
| 2. Fetches and returns user data excluding sensitive information.
*/
const getLoggedInUserInfo = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    // Extract the token from the authorization header
    if (!req.user)
      throw createHttpError(401, "Unauthorized: No user found in request.");
    const userId = req.user.sub; // Decoded JWT user ID added by jwtMiddleware

    // Fetch user by ID (excluding sensitive fields)
    const user = await userModel.findById(userId).select("-password -__v");

    if (!user) {
      return next(createHttpError(404, "User not found."));
    }

    // Respond with user details
    res.status(200).json({
      success: true,
      message: "User retrieved successfully.",
      data: user,
    });
  } catch (err) {
    return next(createHttpError(500, `Error while fetching user: ${err}`));
  }
};

/*
|--------------------------------------------------------------------------
| Update User Controller
|--------------------------------------------------------------------------
| Updates user details (name, bio, avatar, password).
| 1. Validates input.
| 2. Verifies authorization (only allow users to update their own information).
| 3. Handles password hashing securely.
| 4. Updates user information in the database.
*/
const updateUser = async (req: Request, res: Response, next: NextFunction) => {
  // Validate inputs using express-validator
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: errors.array(),
    });
    return next();
  }

  if (!req.user)
    throw createHttpError(401, "Unauthorized: No user found in request.");
  const userId = req.user.sub; // Decoded JWT user ID added by jwtMiddleware
  const { name, bio, avatarUrl, phone, visibility, tfaEnabled, password } = req.body;

  try {
    // Fetch user by ID (excluding sensitive fields)
    const user = await userModel.findById(userId).select("-password -__v");

    if (!user) {
      return next(createHttpError(404, "User not found."));
    }

    // Update only provided fields
    if (name) user.name = name;
    if (bio) user.bio = bio;
    if (avatarUrl) user.avatarUrl = avatarUrl;
    if (phone) user.phone = phone;
    if (visibility) user.visibility = visibility; // ⁡⁢⁣⁣private⁡⁢⁣⁡⁣⁢⁣/⁡⁢⁣⁣public⁡
    if (tfaEnabled) user.tfaEnabled= tfaEnabled; //⁡⁢⁣⁣ yes⁡⁣⁢⁣/⁡⁢⁣⁣no⁡

    // Handle password update securely
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 12);
      user.password = hashedPassword;
    }

    // Save the updated user data
    const updatedUser = await user.save();

    // Return the updated user (excluding sensitive fields like password)
    res.status(200).json({
      success: true,
      message: "User updated successfully.",
      data: updatedUser,
    });
  } catch (err) {
    return next(createHttpError(500, `Error updating user: ${err}`));
  }
};

/*
|--------------------------------------------------------------------------
| Upload User Avatar
|--------------------------------------------------------------------------
| Upload to cloudinary and update user avatar.
*/
const updateAvatar = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    if (!req.user) {
      throw createHttpError(401, "Unauthorized: No user found in request.");
    }
    if (!req.file) {
      throw createHttpError(400, "No file uploaded.");
    }

    // Get user ID from the JWT middleware
    const userId = req.user.sub;

    // Update the user document with the new avatar URL
    const updatedUser = await userModel
      .findByIdAndUpdate(userId, { avatarUrl: req.file.path }, { new: true })
      .select("-password -__v");

    if (!updatedUser) {
      return next(createHttpError(404, "User not found."));
    }

    // Respond with the updated user data
    res.status(200).json({
      success: true,
      message: "Avatar uploaded successfully.",
      data: {
        ...updatedUser.toObject(),
        avatarUrl: req.file.path // Ensure avatar URL is in the response
      },
    });
  } catch (err) {
    return next(createHttpError(500, `Error uploading avatar: ${err}`));
  }
};


/* 
|--------------------------------------------------------------------------
| Request Password Reset Controller
|--------------------------------------------------------------------------
| 1. Generate a 6-digit OTP valid for 10 minutes.
| 2. Attach OTP and expiry to user document.
| 3. Send OTP via email.
*/
const requestPasswordReset = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: errors.array(),
    });
    return next()
  }

  const { email } = req.body;

  try {
    // Check if the user exists with the given email
    const user = await userModel.findOne({ email });
    if (!user) {
      return next(createHttpError(404, "No user found with this email."));
    }

    // Generate a 6-digit OTP and set expiry (10 minutes)
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + (Number(user.passwordOTPExpirationInMins) || 10 ) * 60 * 1000); // 10 minutes from now (default)

    // Attach OTP and expiry to user document
    user.passwordResetOTP = otp;
    user.passwordResetExpires = otpExpiry;
    await user.save();

    // Send OTP via email
    await sendOTPResetEmail(user.email, otp);

    res.status(200).json({
      success: true,
      message:
        "A 6-digit OTP has been sent to your email. It is valid for 10 minutes.",
    });
  } catch (err) {
    return next(
      createHttpError(500, `Error processing password reset: ${err}`),
    );
  }
};

/* 
|--------------------------------------------------------------------------
| Verify OTP Controller
|--------------------------------------------------------------------------
| Verifies the OTP for a given email.
| If valid, returns a success message allowing the user to reset their password.
*/
const verifyPasswordResetOTP = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: errors.array(),
    });
    return next()
  }

  const { email, otp } = req.body;

  try {
    // Find the user by email
    const user = await userModel.findOne({ email });
    if (!user || !user.passwordResetOTP) {
      return next(
        createHttpError(404, "Invalid request. Please request a new OTP."),
      );
    }

    // Verify OTP and expiry
    if (
      user.passwordResetOTP !== otp ||
      (user.passwordResetExpires &&
        new Date() > new Date(user.passwordResetExpires))
    ) {
      return next(createHttpError(400, "Invalid or expired OTP."));
    }

    // Mark OTP as verified
    user.passwordResetVerified = true;
    await user.save();

    res.status(200).json({
      success: true,
      message: "OTP verified successfully. You may now reset your password.",
    });
  } catch (err) {
    return next(createHttpError(500, `Error verifying OTP: ${err}`));
  }
};

/* 
|--------------------------------------------------------------------------
| Reset Password Controller
|--------------------------------------------------------------------------
| Resets the user's password after OTP verification:
| 1. Ensures OTP was verified.
| 2. Hashes the new password securely.
| 3. Updates the user password and clears OTP data.
*/
const resetPassword = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: errors.array(),
    });
    return next()
  }

  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await userModel.findOne({ email });
    if (!user || !user.passwordResetVerified) {
      return next(
        createHttpError(
          400,
          "OTP verification is required before resetting the password.",
        ),
      );
    }

    // Hash the new password securely
    const hashedPassword = await bcrypt.hash(password, 12);

    // Update password and clear OTP-related data
    user.password = hashedPassword;
    user.passwordResetOTP = null;
    user.passwordResetExpires = null;
    user.passwordResetVerified = null;

    await user.save();

    res.status(200).json({
      success: true,
      message: "Password has been reset successfully. You can now log in.",
    });
  } catch (err) {
    return next(createHttpError(500, `Error resetting password: ${err}`));
  }
};


/*
|--------------------------------------------------------------------------
| Refresh Token Endpoint
|--------------------------------------------------------------------------
| Handles refreshing the access token using a valid refresh token:
| 1. Validates and verifies the refresh token from the cookies.
| 2. Checks if the refresh token matches one of the user's logged-in devices.
| 3. Generates a new access token (JWT) and optionally a new refresh token.
| 4. Sets the new refresh token in the cookies and sends the new access token.
*/
const refreshToken= async (req: Request, res: Response, next: NextFunction) => {
  const { refreshToken } = req.cookies; // Extract refresh token from cookies

  if (!refreshToken) {
    return next(createHttpError(401, "Refresh token is missing or invalid."));
  }

  try {
    // Verify the refresh token
    const decoded = verify(refreshToken, config.jwtSecret as string) as JwtPayload & {
      sub: string;
      deviceId: string;
      sessionId: string;
    };

    // Validate token structure
    if (!decoded.sub || !decoded.deviceId || !decoded.sessionId) {
      return next(createHttpError(401, "Invalid refresh token payload."));
    }

    // Find the user by ID
    const user = await userModel.findById(decoded.sub);
    if (!user) {
      return next(createHttpError(404, "User not found."));
    }

    // Check if the device and session match
    const matchingDevice = user.loggedInDevices.find(
      (device) =>
        device.deviceId === decoded.deviceId && device.sessionId === decoded.sessionId
    );

    if (!matchingDevice) {
      return next(createHttpError(401, "Session is invalid or expired."));
    }

    // Generate new tokens
    const newSessionId = matchingDevice.sessionId; // Keep the existing sessionId

    const newAccessToken = sign(
      {
        sub: user._id,
        role: user.role,
        email: user.email,
        deviceId: decoded.deviceId,
        sessionId: newSessionId,
      },
      config.jwtSecret as string,
      { expiresIn: "15m", algorithm: "HS256" }
    );

    const newRefreshToken = sign(
      {
        sub: user._id,
        role: user.role,
        email: user.email,
        deviceId: decoded.deviceId,
        sessionId: newSessionId,
      },
      config.jwtSecret as string,
      { expiresIn: "7d", algorithm: "HS256" }
    );

    // Set the new refresh token in cookies
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: config.env === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Respond with the new access token
    res.status(200).json({
      success: true,
      message: "Token refreshed successfully.",
      accessToken: newAccessToken,
    });
  } catch (err) {
    console.error("Refresh token error:", err);
    return next(createHttpError(401, "Invalid or expired refresh token."));
  }
};


/*
|--------------------------------------------------------------------------
| ⁡⁣⁣⁢Todo:⁡
|--------------------------------------------------------------------------
| ⁡⁢⁣⁡⁢⁣⁣1.⁡⁡ ⁡⁢⁢⁡⁣⁢⁣To set otp expiration time for both password otp and email otp⁡
| ⁡⁢⁣⁣2.⁡ ⁡⁣⁢⁣Two factor authentication⁡
| ⁡⁢⁣⁣3.⁡ ⁡⁣⁢⁣Google auth⁡
*/


export {
  createUser,
  verifyEmail,
  loginUser,
  getLoggedInUserInfo,
  updateUser,
  updateAvatar,
  requestPasswordReset,
  verifyPasswordResetOTP,
  resetPassword,
  refreshToken
};