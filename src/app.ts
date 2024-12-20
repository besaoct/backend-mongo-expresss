import express from "express";
import cors from "cors";
import path from "path";
import cookieParser from "cookie-parser";
import { ensureUploadDirectoriesExist } from "./middlewares/uploadMiddlewares"; // Ensure upload directories exist
import globalErrorHandler from "./middlewares/globalErrorHandlingMiddleware"; // Global error handler
import { config } from "./config"; // App configuration (e.g., frontend domain)
import userRouter from "./modules/user/userRouter"; // User routes
import helmet from "helmet";

/* 
|--------------------------------------------------------------------------
| APP INITIALIZATION
|--------------------------------------------------------------------------
*/
const app = express();

/* 
|--------------------------------------------------------------------------
| MIDDLEWARE SETUP
|--------------------------------------------------------------------------
*/
const setupMiddlewares = () => {
  /**
   * Enhance security by setting HTTP headers via helmet.
   */
  app.use(
    helmet({
      /**
       * Disable CSP (Content-Security-Policy):
       * CSP is mainly used to restrict resources in HTML responses.
       * For APIs that return JSON or other data formats, it’s not necessary.
       */
      contentSecurityPolicy: false,

      /**
       * Enable Cross-Origin-Embedder-Policy:
       * Prevents external domains from embedding your resources.
       * Use this if your API serves sensitive resources like images/videos.
       */
      crossOriginEmbedderPolicy: true,

      /**
       * Referrer Policy:
       * Prevents the API from leaking the referring URL.
       */
      referrerPolicy: { policy: "no-referrer" },

      /**
       * Cross-Origin Resource Policy:
       * Protects API resources from being used in cross-origin contexts.
       * For REST APIs, "cross-origin" is safe unless you need to limit resource access.
       */
      crossOriginResourcePolicy: { policy: "cross-origin" }, // Change to "same-origin" if stricter.

      /**
       * Hide X-Powered-By Header:
       * Prevents exposing that your app is powered by Express.
       */
      hidePoweredBy: true,

      /**
       * DNS Prefetch Control:
       * Disables DNS prefetching to reduce external resource leakage.
       */
      dnsPrefetchControl: { allow: false },
      /**
       * Strict-Transport-Security (HSTS):
       * Enforces HTTPS connections.
       * Recommended for production environments.
       */
      hsts: {
        maxAge: 31536000, // 1 year in seconds
        includeSubDomains: true, // Apply HSTS to subdomains
        preload: true, // Preload in browsers that support HSTS
      },

      /**
       * X-Download-Options:
       * Prevents IE from executing downloads in the site's context.
       */
      noSniff: true,

      /**
       * Frameguard:
       * Protects against clickjacking by disallowing iframes.
       */
      frameguard: { action: "deny" },
    }),
  );

  /**
   * Ensure that required directories for file uploads exist before starting the server.
   */
  ensureUploadDirectoriesExist();

  /**
   * Serve static files (e.g., images, documents) from the 'public' directory.
   */
  app.use(express.static(path.join(__dirname, "public")));

  /**
   * Cookie parser middleware to handle cookies (authentication tokens, etc.).
   */
  app.use(cookieParser());

  /**
   * Set proxy trust for scenarios involving a proxy or load balancer.
   */
  app.set("trust proxy", true);

  /**
   * CORS configuration for frontend communication with backend.
   * Only requests from the frontend domain are allowed, with credentials.
   */
  const otherAppDomains = config.otherAppDomains
    ? config.otherAppDomains.split("&").map((domain) => domain.trim())
    : [];
  const allowedOrigins = [config.appDomain, ...otherAppDomains];
  app.use(
    cors({
      origin: (origin, callback) => {
        // Allow requests with no `origin` (e.g., mobile apps, Postman)
        if (!origin) return callback(null, true);

        // Check if origin is in the whitelist
        if (allowedOrigins.includes(origin)) {
          return callback(null, true);
        } else {
          return callback(new Error("Not allowed by CORS"));
        }
      },
      credentials: true, // Allow cookies (credentials)
    }),
  );

  /**
   * Middleware to parse incoming JSON request bodies.
   * Makes request body accessible via req.body.
   */
  app.use(express.json());
};

/* 
|--------------------------------------------------------------------------
| ROUTE SETUP
|--------------------------------------------------------------------------
*/
const setupRoutes = () => {
  /**
   * Simple base route to check if the server is running.
   */
  app.get("/", (_req, res) => {
    res.json({ message: "Backend APIs Development" });
  });

  /**
   * User-related routes for operations (e.g., registration, login).
   */
  app.use("/api/users", userRouter);

  /**
   * add new routes below.
   */
};

/* 
|--------------------------------------------------------------------------
| ERROR HANDLING
|--------------------------------------------------------------------------
*/
const setupErrorHandler = () => {
  /**
   * Function to set up the global error handler for the application.
   * This ensures unhandled errors are caught and appropriate responses are sent.
   */
  app.use(globalErrorHandler);
};

/* 
|--------------------------------------------------------------------------
| APP CONFIGURATION
|--------------------------------------------------------------------------
*/
const configureApp = () => {
  setupMiddlewares();
  setupRoutes();
  setupErrorHandler();
};
configureApp();

export default app;
