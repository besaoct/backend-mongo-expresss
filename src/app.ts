import express from 'express';
import cors from "cors";
import globalErrorHandler from './middlewares/globalErrorHandlingMiddleware';
import userRouter from './collections/user/userRouter';
import { config } from './config';

const app = express();


app.use(
    cors({
        origin: config.frontendDomain,
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