import {Router } from 'express';
import { register, getMe, refreshToken, logout} from '../controllers/authController.js';



const authRoute=Router()

// POST /api/auth/register
authRoute.post("/register",register);

//GET /api/auth/get-me
authRoute.get("/get-me", getMe);

//GET /api/auth/refreshToken
authRoute.get("/refresh-token", refreshToken);

//GET /api/auth/logout
authRoute.get("/logout",logout);

export default authRoute;