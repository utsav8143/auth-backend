import express from 'express';
import morgan from 'morgan';
import CookieParser from 'cookieparser';
import authRoute from './Routes/authRoute.js';
import cookieParser from 'cookie-parser';

const app=express();

app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());

app.use("/api/auth",authRoute);

export default app;