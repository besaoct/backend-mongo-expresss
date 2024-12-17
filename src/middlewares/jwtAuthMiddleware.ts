import { NextFunction, Request, Response } from "express";
import createHttpError from "http-errors";
import { verify, JwtPayload } from "jsonwebtoken";
import { config } from "../config"; // Adjust the path to your config file

// Custom interface for JWT payload
interface DecodedUser {
  sub: string;   // User ID
  role: string;  // User role
  email: string; // User email
}

// Extend Express Request to include 'user'
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: DecodedUser;
    }
  }
}

// JWT Verification Middleware
const jwtMiddleware = (req: Request, _res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(createHttpError(401, "Authentication token is missing or invalid."));
  }

  const token = authHeader.split(" ")[1];

  try {
    // Verify the token and decode it
    const decoded = verify(token, config.jwtSecret as string) as DecodedUser & JwtPayload;

    // Validate the decoded payload fields
    if (!decoded.sub || !decoded.role || !decoded.email) {
      return next(createHttpError(401, "Invalid token payload."));
    }

    // Attach user data to req.user
    req.user = {
      sub: decoded.sub,
      role: decoded.role,
      email: decoded.email,
    };

    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    console.error("JWT Verification Error:", error);
    return next(createHttpError(401, "Invalid or expired token."));
  }
};

export { jwtMiddleware };
