import express from 'express';
import cors from 'cors';
import path from 'path';
import cookieParser from 'cookie-parser';
import { ensureUploadDirectoriesExist } from './middlewares/uploadMiddlewares'; // Ensure upload directories exist
import globalErrorHandler from './middlewares/globalErrorHandlingMiddleware'; // Global error handler
import { config } from './config'; // App configuration (e.g., frontend domain)
import userRouter from './collections/user/userRouter'; // User routes


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
   * Ensure that required directories for file uploads exist before starting the server.
   */
  ensureUploadDirectoriesExist();

  /**
   * Serve static files (e.g., images, documents) from the 'public' directory.
   */
  app.use(express.static(path.join(__dirname, 'public')));

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
  app.use(
    cors({
      origin: config.frontendDomain,  // Allowed frontend domain
      credentials: true,              // Allow cookies (credentials)
    })
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
  app.get('/', (_req, res) => {
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
