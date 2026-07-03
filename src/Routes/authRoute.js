import {Router } from 'express';

const authRouter=Router()

// POST /api/auth/register
authRouter.post("/register");

export default authRouter;