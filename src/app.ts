import express from 'express';
import cors from "cors";
import globalErrorHandler from './middlewares/globalErrorHandlingMiddleware';
import userRouter from './collections/user/userRouter';
import { config } from './config';
import cookieParser from 'cookie-parser';
import { ensureUploadDirectoriesExist } from './middlewares/uploadMiddlewares';

const app = express();

app.use(cookieParser());

app.set("trust proxy", true);

app.use(
    cors({
        origin: config.frontendDomain,
        credentials: true,  // Allow credentials (cookies)
    })
);

app.use(express.json());

ensureUploadDirectoriesExist();

// Routes
app.get('/', (_req, res)=>{
    res.json({
        message:"Backend APIs Development"
    })
})
app.use("/api/users", userRouter);

// Global error handler (should be at the end)
app.use(globalErrorHandler);


export default app;