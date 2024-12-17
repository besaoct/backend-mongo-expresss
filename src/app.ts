import express from 'express';
import cors from "cors";
import globalErrorHandler from './middlewares/globalErrorHandlingMiddleware';
import userRouter from './collections/user/userRouter';
import { config } from './config';
import cookieParser from 'cookie-parser';

const app = express();

// Apply cookie parser middleware globally
app.use(cookieParser());

app.set("trust proxy", true);

app.use(
    cors({
        origin: config.frontendDomain,
        credentials: true,  // Allow credentials (cookies)
    })
);

app.use(express.json());


// Routes

// root route
app.get('/', (_req, res)=>{
    res.json({
        message:"Backend APIs Development"
    })
})


// api routes
app.use("/api/users", userRouter);

// Global error handler (should be at the end)
app.use(globalErrorHandler);


export default app;