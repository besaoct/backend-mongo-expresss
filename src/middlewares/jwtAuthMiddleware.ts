import { NextFunction, Request, Response } from "express";
import createHttpError from "http-errors";
import { verify } from "jsonwebtoken";
import { config } from "../config"; // Adjust the path to your config file

// JWT Verification Middleware
const jwtMiddleware = (req: Request, _res: Response, next: NextFunction) => {
  // Check for Authorization header
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(createHttpError(401, "No token provided or invalid token format."));
  }

  // Extract token from Authorization header
  const token = authHeader.split(" ")[1];

  try {
    // Verify the token and decode its payload
    const decoded = verify(token, config.jwtSecret as string) as { sub: string, role: string, email: string }; // Adjust payload type as needed

    // Ensure decoded token has all required fields
    if (!decoded.sub || !decoded.role || !decoded.email) {
      return next(createHttpError(401, "Invalid token payload."));
    }

    // Add the decoded user data to the request object (req.query)
    req.query= {
      sub: decoded.sub,   // User ID (sub)
      role: decoded.role, // User role
      email: decoded.email, // User email
    };

    // Continue to the next middleware or route handler
    next();
  } catch (err) {
    return next(createHttpError(401, `${err}: Invalid or expired token.`));
  }
};

export { jwtMiddleware };
