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
  validatePasswordResetRequest,
  validateResetPassword,
  validateUpdateUser,
  verifyEmail,
} from "./userController";

import { jwtMiddleware } from "../../middlewares/jwtAuthMiddleware";
import { imageUpload } from "../../middlewares/uploadMiddlewares";

const userRouter = express.Router();

// auth routes
userRouter.post("/register", validateCreateUser, createUser);
userRouter.get("/verify-email", verifyEmail);
userRouter.post("/login", validateLoginUser, loginUser);
userRouter.post("/request-password-reset", validatePasswordResetRequest, requestPasswordReset);
userRouter.post("/reset-password", validateResetPassword, resetPassword);

// with jwt auth middleware
userRouter.get("/user-info", jwtMiddleware, getLoggedInUserInfo); 
userRouter.put('/update-user', jwtMiddleware, validateUpdateUser, updateUser);
userRouter.post("/avatar", jwtMiddleware, imageUpload.single("avatar"), uploadAvatar);

export default userRouter;
