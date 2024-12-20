import {  Response, Request, NextFunction } from 'express';
import { HttpError } from 'http-errors';
import { config } from '../config';


const globalErrorHandler = (err: HttpError, _req: Request, res: Response, _next: NextFunction) => {
    const statusCode = err.status || 500;

    res.status(statusCode).json({
        success: false,
        message: err.message,
        errorStack: config.env === 'development' ? err.stack : null,
    });

};


export default globalErrorHandler;