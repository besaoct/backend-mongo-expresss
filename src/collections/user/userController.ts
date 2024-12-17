import { NextFunction, Request, Response } from "express";
import createHttpError from "http-errors";
import bcrypt from "bcrypt";
import userModel from "./userModel";
import { sign, verify } from "jsonwebtoken";
import { config } from "../../config";
import { User, UserRole } from "./userTypes";
import { body, validationResult } from "express-validator";
import { sendResetPasswordEmail, sendVerificationEmail } from "../../services/mail";
import DeviceDetector from "device-detector-js";
import { cloudinary } from "../../config";

/* 
|--------------------------------------------------------------------------
| Input Validation Middleware 
|--------------------------------------------------------------------------
| Middleware for input validation using express-validator. 
| Ensures that the incoming data for user creation and login is valid and secure.
*/
// Validation middleware for user registration
const validateCreateUser = [
  body("name").trim().notEmpty().withMessage("Name is required"),
  body("email")
    .isEmail()
    .withMessage("A valid email is required")
    .normalizeEmail(),
  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long")
    .matches(/\d/)
    .withMessage("Password must contain at least one number")
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage("Password must contain at least one special character"),
];
// Validation middleware for user login
const validateLoginUser = [
  body("email").isEmail().withMessage("A valid email is required"),
  body("password").notEmpty().withMessage("Password is required"),
];
// Validation middleware for user update
const validateUpdateUser = [
  body("name").optional().trim().notEmpty().withMessage("Name cannot be empty."),
  body("bio").optional().trim().isLength({ max: 300 }).withMessage("Bio must be under 300 characters."),
  body("avatar").optional().isURL().withMessage("Image must be a valid URL."),
  body("phone")
    .optional()
    .matches(/^\+?[1-9]\d{1,14}$/)
    .withMessage("Phone number must be a valid international format."),
  body("password")
    .optional()
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long.")
    .matches(/\d/)
    .withMessage("Password must contain at least one number.")
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage("Password must contain at least one special character."),
];
// Validation middleware for requesting a password reset
const validatePasswordResetRequest = [
  body("email").isEmail().withMessage("A valid email is required").normalizeEmail(),
];

// Validation middleware for resetting the password
const validateResetPassword = [
  body("token").notEmpty().withMessage("Reset token is required."),
  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long.")
    .matches(/\d/)
    .withMessage("Password must contain at least one number.")
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage("Password must contain at least one special character."),
];


/* 
|--------------------------------------------------------------------------
| User Registration Controller
|--------------------------------------------------------------------------
| Handles new user registration:
| 1. Validates input using express-validator.
| 2. Checks if the user already exists.
| 3. Hashes the password securely.
| 4. Generates a verification token for email confirmation.
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

    // Generate verification token for email confirmation
    const verificationToken = sign({ email }, config.jwtSecret as string, {
      expiresIn: "1d", // Token expires in 1 day
    });

    // Create the user and save to database
    const newUser: User = await userModel.create({
      name,
      email,
      password: hashedPassword,
      role: role || UserRole.USER,
      verificationToken,
    });

    // Send a verification email with the token link
    await sendVerificationEmail(newUser.email, verificationToken);

    // Respond with success message
    res.status(201).json({
      message: "User registered successfully. Please verify your email.",
    });
  } catch (err) {
    return next(createHttpError(500, `Error while creating user: ${err}`));
  }
};

/* 
|--------------------------------------------------------------------------
| Email Verification Controller
|--------------------------------------------------------------------------
| Handles email verification via a token:
| 1. Decodes the token.
| 2. Verifies the user by email.
| 3. Updates the user’s `isVerified` status.
*/
const verifyEmail = async (req: Request, res: Response, next: NextFunction) => {
  const { token } = req.query;

  try {
    // Decode the verification token
    const decoded = verify(token as string, config.jwtSecret as string) as {
      email: string;
    };

    // Find user by email
    const user = await userModel.findOne({ email: decoded.email });

    if (!user) {
      return next(createHttpError(404, "User not found."));
    }

    // Check if email is already verified
    if (user.isVerified) {
      res.status(200).json({ message: "Email is already verified." }); // The return is valid here
      return next();
    }

    // Mark user as verified and remove the verification token
    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.status(200).json({ message: "Email verified successfully!" });
  } catch (err) {
    return next(createHttpError(400, `${err}: Invalid or expired token`));
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
  const deviceDetector = new DeviceDetector();
  const userAgent = req.headers["user-agent"] || ""; // Extract User-Agent header

  const deviceInfo = deviceDetector.parse(userAgent); // Parse device info

  const deviceName = `${deviceInfo.client?.name || "Unknown Browser"} on ${
    deviceInfo.os?.name || "Unknown OS"
  } (${deviceInfo.device?.type || "Unknown Device"})`;

  // Input validation
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(createHttpError(400, { errors: errors.array() }));
  }

  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await userModel.findOne({ email });
    if (!user) {
      return next(createHttpError(404, "User not found."));
    }

    // Check if the email is verified
    if (!user.isVerified) {
      return next(createHttpError(400, "Please verify your email first."));
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
  (device) => device.deviceName === deviceName
);

if (existingDeviceIndex !== -1) {
  // If device already exists, update its login timestamp (keep the latest login)
  user.loggedInDevices[existingDeviceIndex].loginAt = new Date();
} else {
  // If device is new, add it to the list
  user.loggedInDevices.push({
    deviceName,
    loginAt: new Date(),
  });
}

    // Limit the number of devices (keep only the last 5)
    if (user.loggedInDevices.length > 5) {
      user.loggedInDevices = user.loggedInDevices.slice(-5); // Keep only the last 5 devices
    }


    // Save the updated user details
    await user.save();

    // Generate JWT access token
    const token = sign(
      { sub: user._id, role: user.role, email: user.email },
      config.jwtSecret as string,
      { expiresIn: "7d", algorithm: "HS256" },
    );

    // Respond with the access token
    res.status(200).json({
      success: true,
      newUser: isFirstLogin,
      message: isFirstLogin ? `Hey ${user.name}! Welcome` : "Login successful.",
      accessToken: token,
      data: {
        name: user.name,
        email: user.email,
        role: user.role,
        loginCount: user.loginCount,
        lastLoginAt: user.lastLoginAt,
        loggedInDevices: user.loggedInDevices,
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
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return next(
        createHttpError(401, "No token provided or invalid token format."),
      );
    }

    const token = authHeader.split(" ")[1]; // Get the token

    // Verify the token and extract payload
    const decodedToken = verify(token, config.jwtSecret as string) as {
      sub: string;
    };

    if (!decodedToken || !decodedToken.sub) {
      return next(createHttpError(401, "Invalid or expired token."));
    }

    const userId = decodedToken.sub;

    // Fetch user by ID (excluding sensitive fields)
    const user = await userModel.findById(userId).select("-password -__v");

    if (!user) {
      return next(createHttpError(404, "User not found."));
    }

    // Respond with user details
    res.status(200).json({
      success: true,
      message: "User retrieved successfully.",
      data: user
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
    return next(createHttpError(400, { message: "Validation failed", errors: errors.array() }));
  }

  const userId = req.user?.sub; // Decoded JWT user ID added by jwtMiddleware
  const { name, bio, avatar, phone, password } = req.body;

  try {

    // Fetch user by ID (excluding sensitive fields)
    const user = await userModel.findById(userId).select("-password -__v");

    if (!user) {
      return next(createHttpError(404, "User not found."));
    }

    // Update only provided fields
    if (name) user.name = name;
    if (bio) user.bio = bio;
    if (avatar) user.avatar = avatar;
    if (phone) user.phone = phone;

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
      data:  updatedUser,
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
const uploadAvatar = async (req: Request, res: Response, next: NextFunction) => {
  try {
   
    if (!req.user) throw createHttpError(401, "Unauthorized: No user found in request.");
    if (!req.file) throw createHttpError(400, "No file uploaded.");


    // Get user ID from the JWT middleware
    const userId = req.user.sub;

     // Upload the file to Cloudinary
     const result = await cloudinary.uploader.upload(req.file.path, {
      folder: "avatars", // Cloudinary folder name
      public_id: `avatar_${userId}`, // Unique name for the avatar
      overwrite: true, // Replace the existing avatar
    });


     // Update the user document with the new avatar URL
     const updatedUser = await userModel.findByIdAndUpdate(
      userId,
      { image: result.secure_url },
      { new: true }
    ).select("-password -__v");;

    if (!updatedUser) {
      return next(createHttpError(404, "User not found."));
    }

    // Respond with the updated user data
    res.status(200).json({
      success: true,
      message: "Avatar uploaded successfully.",
      data: updatedUser,
    });
  } catch (err) {
    return next(createHttpError(500, `Error uploading avatar: ${err}`));
  }
};


/* 
|--------------------------------------------------------------------------
| Request Password Reset Controller
|--------------------------------------------------------------------------
| Handles the generation and sending of password reset tokens:
| 1. Checks if the user exists by email.
| 2. Generates a one-time-use password reset token.
| 3. Sends the token to the user via email.
*/
const requestPasswordReset = async (req: Request, res: Response, next: NextFunction) => {

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(createHttpError(400, { message: "Validation failed", errors: errors.array() }));
  }

  const { email } = req.body;

  try {
    // Check if user exists with the given email
    const user = await userModel.findOne({ email });
    if (!user) {
      return next(createHttpError(404, "No user found with this email."));
    }

    // Generate a password reset token valid for 1 hour
    const resetToken = sign({ userId: user._id }, config.jwtSecret as string, {
      expiresIn: "1h",
    });

    // Attach reset token and expiry to the user document
    user.passwordResetToken = resetToken;
    user.passwordResetExpires = new Date(Date.now() + 3600000); // 1 hour expiry
    await user.save();

    // Send password reset email
    await sendResetPasswordEmail(user.email, resetToken);

    res.status(200).json({
      success: true,
      message: "Password reset link has been sent to your email. It will be expired in 1 hour.",
    });
  } catch (err) {
    return next(createHttpError(500, `Error processing password reset: ${err}`));
  }
};

/* 
|--------------------------------------------------------------------------
| Reset Password Controller
|--------------------------------------------------------------------------
| Handles password reset:
| 1. Validates the reset token.
| 2. Hashes the new password securely.
| 3. Updates the user password in the database.
| 4. Invalidates the reset token after successful use.
*/
const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(createHttpError(400, { message: "Validation failed", errors: errors.array() }));
  }

  const { token, password } = req.body;

  try {
    // Verify and decode the reset token
    const decoded = verify(token, config.jwtSecret as string) as { userId: string };

    // Find user by ID and validate reset token
    const user = await userModel.findById(decoded.userId);
    if (!user || (user.passwordResetToken !== token) || (user.passwordResetExpires && (new Date() > new Date(user.passwordResetExpires)))) {
      return next(createHttpError(400, "Invalid or expired reset token."));
    }

    // Hash the new password securely
    const hashedPassword = await bcrypt.hash(password, 12);
    user.password = hashedPassword;

    // Invalidate the reset token
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    // Save the updated user document
    await user.save();

    res.status(200).json({
      success: true,
      message: "Password has been reset successfully. You can now log in.",
    });
  } catch (err) {
    return next(createHttpError(500, `Error resetting password: ${err}`));
  }
};

export {
  // functions
  createUser,
  verifyEmail,
  loginUser,
  getLoggedInUserInfo,
  updateUser,
  uploadAvatar,
  requestPasswordReset,
  resetPassword,
  // validations
  validateCreateUser,
  validateLoginUser,
  validateUpdateUser,
  validatePasswordResetRequest,
  validateResetPassword
};
