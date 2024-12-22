import express from "express";
import {
  createUser,
  getLoggedInUserInfo,
  loginUser,
  logoutAllDevices,
  logoutSingleDevice,
  refreshToken,
  requestPasswordResetOTP,
  requestTwoFactorAuthenticationOTP,
  resetPassword,
  updateLoggedInAvatar,
  updateLoggedInUser,
  verifyEmail,
  verifyPasswordResetOTP,
  verifyTwoFactorAuthenticationOTP,
} from "./authUserController";

import { jwtMiddleware } from "../../middlewares/jwtAuthMiddleware";

import { 
  validateCreateUser,
  validateLoginUser,
  validateRequestPasswordResetEmail,
  validateRequestTwoFactorAuthenticationEmail,
  validateResetPassword,
  validateUpdateUser,
  validateVerifyEmailOTP,
  validateVerifyPasswordResetEmailOTP,
  validateVerifyTwoFactorAuthenticationEmailOTP,
} from "./authUserValidation";
import cloudinaryUpload from "../../middlewares/cloudinaryUploadMiddleware";

const authRouter = express.Router();
const userRouter = express.Router();

// authentication routes
authRouter.post("/register", validateCreateUser, createUser);
authRouter.post("/verify-email", validateVerifyEmailOTP, verifyEmail);
authRouter.post("/login", validateLoginUser, loginUser);
authRouter.post("/refresh-token", refreshToken);
authRouter.post("/request-password-reset", validateRequestPasswordResetEmail, requestPasswordResetOTP);
authRouter.post("/verify-password-reset-otp", validateVerifyPasswordResetEmailOTP, verifyPasswordResetOTP);
authRouter.post("/reset-password", validateResetPassword, resetPassword);
authRouter.post("/request-tfa-otp", validateRequestTwoFactorAuthenticationEmail, requestTwoFactorAuthenticationOTP);
authRouter.post("/verify-tfa-otp", validateVerifyTwoFactorAuthenticationEmailOTP, verifyTwoFactorAuthenticationOTP);

// user routes with jwt auth middleware
userRouter.get("/:id/logged-in-user-info", jwtMiddleware, getLoggedInUserInfo); 
userRouter.put("/:id/update-user", jwtMiddleware, validateUpdateUser, updateLoggedInUser);
userRouter.post("/:id/upload-avatar", jwtMiddleware, cloudinaryUpload.Image({fieldName:"avatar", folder: "avatars", overwrite: true}), updateLoggedInAvatar);
userRouter.delete("/:id/logout-single-device", jwtMiddleware, logoutSingleDevice);
userRouter.delete("/:id/logout-all-devices", jwtMiddleware, logoutAllDevices);

export {authRouter, userRouter};

