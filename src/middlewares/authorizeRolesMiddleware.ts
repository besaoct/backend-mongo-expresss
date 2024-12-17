import { NextFunction, Request, Response } from "express";
import { verify } from "jsonwebtoken";
import createHttpError from "http-errors"; // Importing createHttpError
import { config } from "../config";

export const authorizeRoles = (...roles: string[]) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return next(createHttpError(401, "Access denied. No token provided."));
    }

    try {
      const decoded = verify(token, config.jwtSecret as string) as { role: string };
      
      // Check if the user's role is in the allowed roles
      if (!roles.includes(decoded.role)) {
        return next(createHttpError(403, "Access denied. Unauthorized role."));
      }

      // Proceed if the role matches
      next();
    } catch (err) {
      return next(createHttpError(401, `Invalid or expired token: ${err}`));
    }
  };
};
