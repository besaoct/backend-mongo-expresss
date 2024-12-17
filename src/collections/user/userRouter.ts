import express from "express";
import {
  createUser,
  getLoggedInUserInfo,
  loginUser,
  refreshToken,
  // refreshToken,
  requestPasswordReset,
  resetPassword,
  updateAvatar,
  updateUser,
  verifyEmail,
  verifyPasswordResetOTP,
} from "./userController";

import { jwtMiddleware } from "../../middlewares/jwtAuthMiddleware";

import { 
  validateCreateUser,
  validateLoginUser,
  validateRequestPasswordReset,
  validateResetPassword,
  validateUpdateUser,
  validateVerifyEmail,
  validateVerifyOTP,
} from "./userValidationMiddleware";
import cloudinaryUpload from "../../middlewares/cloudinaryUploadMiddleware";

const userRouter = express.Router();

// auth routes
userRouter.post("/register", validateCreateUser, createUser);
userRouter.post("/verify-email", validateVerifyEmail, verifyEmail);
userRouter.post("/login", validateLoginUser, loginUser);
userRouter.post("/refresh-token", refreshToken);

// reset password routes
userRouter.post("/request-password-reset", validateRequestPasswordReset, requestPasswordReset);
userRouter.post("/verify-otp", validateVerifyOTP, verifyPasswordResetOTP);
userRouter.post("/reset-password", validateResetPassword, resetPassword);

// with jwt auth middleware
userRouter.get("/user-info", jwtMiddleware, getLoggedInUserInfo); 
userRouter.put('/update-user', jwtMiddleware, validateUpdateUser, updateUser);
userRouter.post(
  "/upload-avatar",
  jwtMiddleware,
  cloudinaryUpload.Image({fieldName:"avatar", folder: "avatars", overwrite: true}), // Save avatars under `avatars/{userId}`
  updateAvatar
);


export default userRouter;
