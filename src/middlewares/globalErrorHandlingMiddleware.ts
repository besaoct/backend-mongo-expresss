import {  Response, Request, NextFunction } from 'express';
import { HttpError } from 'http-errors';
import { config } from '../config';


// eslint-disable-next-line @typescript-eslint/no-unused-vars
const globalErrorHandler = (err: HttpError, _req: Request, res: Response, _next: NextFunction) => {
    const statusCode = err.status || 500;

    res.status(statusCode).json({
        success: false,
        message: err.message,
        errorStack: config.env === 'development' ? err.stack : undefined,
    });
};


export default globalErrorHandler;