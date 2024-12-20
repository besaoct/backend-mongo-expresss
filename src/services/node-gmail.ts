import nodemailer from "nodemailer";
import { config } from "../config";

const getEmailOTPTemplate = ({title, message, otp}:{title: string, message: string, otp: string}) => `
<!DOCTYPE html>
<html>
<head>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f4f4f4;
      margin: 0;
      padding: 0;
    }
    .email-container {
      max-width: 600px;
      margin: 20px auto;
      background: #ffffff;
      border-radius: 8px;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
      overflow: hidden;
    }
    .email-header {
      background: #007bff;
      color: #ffffff;
      padding: 20px;
      text-align: center;
    }
    .email-header h1 {
      margin: 0;
      font-size: 24px;
    }
    .email-body {
      padding: 20px;
      color: #333333;
      line-height: 1.6;
    }
    .otp-code {
      font-size: 22px;
      font-weight: bold;
      text-align: center;
      color: #007bff;
      margin: 20px 0;
    }
    .email-footer {
      text-align: center;
      padding: 15px;
      font-size: 12px;
      background: #f9f9f9;
      color: #777777;
    }
    .email-footer a {
      color: #007bff;
      text-decoration: none;
    }
    .email-footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="email-container">
    <div class="email-header">
      <h1>${title}</h1>
    </div>
    <div class="email-body">
      <p>${message}</p>
      <div class="otp-code">${otp}</div>
      <p>If you did not request this, you can safely ignore this email.</p>
    </div>
    <div class="email-footer">
      <p>&copy; ${new Date().getFullYear()} ${config.appName}. All Rights Reserved.</p>
      <p>
        <a href=${config.appDomain} target="_blank">Visit ${config.appName}</a> |
        <a href="mailto:${config.contactMail}">Contact Support</a>
      </p>
    </div>
  </div>
</body>
</html>
`;

export const sendVerificationEmail = async (email: string, otp: string) => {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: config.emailServiceUser,
      pass: config.emailServicePass,
    },
  });

  const emailHtml = getEmailOTPTemplate({
    title: "Email Verification",
    message: "Please use the OTP below to verify your email address. This OTP is valid for 10 minutes.",
    otp: otp
  }
  );

  await transporter.sendMail({
    from: config.emailServiceUser,
    to: email,
    subject: "Email Verification OTP",
    html: emailHtml,
  });
};

export const sendOTPResetEmail = async (email: string, otp: string) => {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: config.emailServiceUser,
      pass: config.emailServicePass,
    },
  });

  const emailHtml = getEmailOTPTemplate({
   title: "Password Reset Request",
   message: "We received a request to reset your password. Use the OTP below to proceed. This OTP is valid for 10 minutes.",
   otp: otp
  });

  await transporter.sendMail({
    from: config.emailServiceUser,
    to: email,
    subject: "Password Reset OTP",
    html: emailHtml,
  });
};
