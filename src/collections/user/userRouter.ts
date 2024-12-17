import express from "express";
import {
  createUser,
  getLoggedInUserInfo,
  loginUser,
  updateUser,
  uploadAvatar,
  validateCreateUser,
  validateLoginUser,
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

// with jwt middleware
userRouter.get("/user-info", jwtMiddleware, getLoggedInUserInfo); 
userRouter.put('/update-user', jwtMiddleware, validateUpdateUser, updateUser);
userRouter.post("/avatar", jwtMiddleware, imageUpload.single("avatar"), uploadAvatar);

export default userRouter;
