import express from "express";
import {
  createUser,
  getLoggedInUserInfo,
  loginUser,
  requestPasswordReset,
  resetPassword,
  updateUser,
  uploadAvatar,
  validateCreateUser,
  validateLoginUser,
  validateRequestPasswordReset,
  validateResetPassword,
  validateUpdateUser,
  validateVerifyEmail,
  validateVerifyOTP,
  verifyEmail,
  verifyPasswordResetOTP,
} from "./userController";

import { jwtMiddleware } from "../../middlewares/jwtAuthMiddleware";
import { imageUpload } from "../../middlewares/uploadMiddlewares";

const userRouter = express.Router();

// auth routes
userRouter.post("/register", validateCreateUser, createUser);
userRouter.post("/verify-email", validateVerifyEmail, verifyEmail);
userRouter.post("/login", validateLoginUser, loginUser);

// reset password routes
userRouter.post("/request-password-reset", validateRequestPasswordReset, requestPasswordReset);
userRouter.post("/verify-otp", validateVerifyOTP, verifyPasswordResetOTP);
userRouter.post("/reset-password", validateResetPassword, resetPassword);

// with jwt auth middleware
userRouter.get("/user-info", jwtMiddleware, getLoggedInUserInfo); 
userRouter.put('/update-user', jwtMiddleware, validateUpdateUser, updateUser);
userRouter.post("/avatar", jwtMiddleware, imageUpload.single("avatar"), uploadAvatar);

export default userRouter;
