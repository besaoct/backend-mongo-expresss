import { NextFunction, Request, Response } from "express";
import createHttpError from "http-errors";
import { verify, JwtPayload } from "jsonwebtoken";
import { config } from "../config"; // Adjust the path to your config file
import userModel from "../modules/auth/authUserModel";
import { TfaEnabled } from "../modules/auth/authUserTypes";

// Custom interface for JWT payload
interface DecodedUser {
  sub: string; // User ID
  role: string; // User role
  email: string; // User email
}

// Extend Express Request to include 'user'
declare global {
  namespace Express {
    interface Request {
      user?: DecodedUser;
    }
  }
}

// JWT Verification Middleware
const jwtMiddleware = async (
  req: Request,
  _res: Response,
  next: NextFunction,
) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(
      createHttpError(401, "Authentication token is missing or invalid."),
    );
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = verify(token, config.jwtSecret as string) as DecodedUser &
      JwtPayload;

    if (
      !decoded.sub ||
      !decoded.role ||
      !decoded.deviceId ||
      !decoded.sessionId
    ) {
      return next(createHttpError(401, "Invalid token payload."));
    }

    const user = await userModel.findById(decoded.sub);
    if (!user) {
      return next(createHttpError(401, "User not found."));
    }

    if ((user.tfaEnabled===TfaEnabled.Yes) && (!user.tfaOTPVerified)) {
      return next(createHttpError(403, "Access denied: TFA is enabled but TFA OTP is not verified for this user."));
    }

    const matchingDevice = user.loggedInDevices.find(
      (device) =>
        device.deviceId === decoded.deviceId &&
        device.sessionId === decoded.sessionId,
    );

    if (!matchingDevice) {
      return next(createHttpError(401, "Invalid session or device."));
    }

    req.user = {
      sub: decoded.sub,
      role: decoded.role,
      email: decoded.email,
    };

    next();
  } catch (error) {
    console.error("JWT Verification Error:", error);
    return next(createHttpError(401, "Invalid or expired token."));
  }
};

export { jwtMiddleware };
