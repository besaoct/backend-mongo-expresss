
import { config as dotConfig } from "dotenv";
import { v2 as cloudinary } from "cloudinary";

dotConfig()

// main config
const _config = {
    port: process.env.PORT,
    databaseUrl: process.env.MONGO_CONNECTION_STRING,
    env : process.env.NODE_ENV,
    jwtSecret: process.env.JWT_SECRET,
    appName: process.env.APP_NAME,
    appDomain: process.env.APP_DOMAIN,
    otherAppDomains:process.env.OTHER_APP_DOMAINS,
    contactMail: process.env.CONTACT_MAIL,
    emailServiceUser: process.env.EMAIL_USER,
    emailServicePass: process.env.EMAIL_PASS
}

// config for uploading to cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});


export { cloudinary };
export const config = Object.freeze(_config);

