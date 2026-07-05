import {Router } from 'express';
import { register, getMe, refreshToken, logout,logoutAll,login, verifyEmail} from '../controllers/authController.js';



const authRoute=Router()

// POST /api/auth/register
authRoute.post("/register",register);

//GET /api/auth/login
authRoute.post("/login",login)

//GET /api/auth/get-me
authRoute.get("/get-me", getMe);

//GET /api/auth/refreshToken
authRoute.get("/refresh-token", refreshToken);

//GET /api/auth/logout
authRoute.get("/logout",logout);

//GET /api/auth/logout-all
authRoute.get("/logout-all",logoutAll)

//POST /api/auth/verify-email
authRoute.post("/verify-email",verifyEmail)

export default authRoute;