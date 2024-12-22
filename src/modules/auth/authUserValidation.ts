import { body } from "express-validator";
import { TfaEnabled, Visibility } from "./authUserTypes";

/* 
|--------------------------------------------------------------------------
| User Input Validation
|--------------------------------------------------------------------------
| Middlewares for input validation using express-validator. 
| Ensures that the incoming data for user creation and login is valid and secure.
*/

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

const validateLoginUser = [
  body("email").isEmail().withMessage("A valid email is required"),
  body("password").notEmpty().withMessage("Password is required"),
];

const validateUpdateUser = [
  body("name")
    .optional()
    .trim()
    .notEmpty()
    .withMessage("Name cannot be empty."),
  body("bio")
    .optional()
    .trim()
    .isLength({ max: 300 })
    .withMessage("Bio must be under 300 characters."),
  body("avatarUrl")
    .optional()
    .isURL()
    .withMessage("Image must be a valid URL."),
  body("phone")
    .optional()
    .matches(/^\+?[1-9]\d{1,14}$/)
    .withMessage("Phone number must be a valid international format."),
  body("visibility")
    .optional()
    .isIn(Object.values(Visibility)) // Validate against enum values
    .withMessage(
      `Visibility must be one of: ${Object.values(Visibility).join(", ")}`,
    ),
  body("tfaEnabled")
    .optional()
    .isIn(Object.values(TfaEnabled)) // Validate against enum values
    .withMessage(
      `TFA Enabled must be one of: ${Object.values(TfaEnabled).join(", ")}`,
    ),
  body("password")
    .optional()
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long.")
    .matches(/\d/)
    .withMessage("Password must contain at least one number.")
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage("Password must contain at least one special character."),
];

const validateVerifyEmailOTP = [
  body("email").isEmail().withMessage("A valid email is required"),
  body("otp")
    .isLength({ min: 6, max: 6 })
    .withMessage("OTP must be exactly 6 digits"),
];

const validateRequestPasswordResetEmail = [
  body("email")
    .isEmail()
    .withMessage("A valid email is required")
    .normalizeEmail(),
];

const validateVerifyPasswordResetEmailOTP = [
  body("email").isEmail().withMessage("A valid email is required"),
  body("otp")
    .isLength({ min: 6, max: 6 })
    .withMessage("OTP must be exactly 6 digits"),
];

const validateResetPassword = [
  body("email").isEmail().withMessage("A valid email is required"),
  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long.")
    .matches(/\d/)
    .withMessage("Password must contain at least one number.")
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage("Password must contain at least one special character."),
];

const validateRequestTwoFactorAuthenticationEmail = [
  body("email")
    .isEmail()
    .withMessage("A valid email is required")
    .normalizeEmail(),
];

const validateVerifyTwoFactorAuthenticationEmailOTP = [
  body("email").isEmail().withMessage("A valid email is required"),
  body("otp")
    .isLength({ min: 6, max: 6 })
    .withMessage("OTP must be exactly 6 digits"),
];


export {
  validateCreateUser,
  validateVerifyEmailOTP,
  validateLoginUser,
  validateUpdateUser,
  validateRequestPasswordResetEmail,
  validateVerifyPasswordResetEmailOTP,
  validateResetPassword,
  validateRequestTwoFactorAuthenticationEmail,
  validateVerifyTwoFactorAuthenticationEmailOTP
};
