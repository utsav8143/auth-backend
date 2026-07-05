import userModel from "../models/userModel.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import strict from "assert/strict";
import sessionModel from "../models/sessionModel.js";
import { sendEmail } from "../services/emailService.js";
import { generateOtp, getOtpHtml } from "../utils/utils.js";
import otpModel from "../models/otpModel.js";

// @desc Register User
// @ROUTE POST /api/auth/register
// @access Public
export async function register(req, res) {
  const { username, email, password } = req.body;

  const isAlreadyRegistered = await userModel.findOne({
    $or: [{ username }, { email }],
  });

  if (isAlreadyRegistered)
    return res.status(409).json({ message: "Username or email already exists" });

  const hashedPassword = crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

  const user = await userModel.create({
    username,
    email,
    password: hashedPassword,
    verified: false
  });

  const otp = generateOtp();
  const html = getOtpHtml(otp);

  const otpHashed = crypto.createHash("sha256").update(otp.toString()).digest("hex");

  await otpModel.create({
    email,
    user: user._id,
    otpHashed,
   
  });

  await sendEmail(email, "OTP Verification", `your OTP is ${otp}`, html);

  res.status(201).json({
    message: "User registered successfully",
    user: {
      username: user.username,
      email: user.email,
      verified: user.verified,
    },
  });
}

//@desc Login User
// @ROUTE POST /api/auth/login
// @access Public
export async function login(req, res) {
  const { email, password } = req.body;

  const user = await userModel.findOne({ email });

  if (!user)
    return res.status(401).json({ message: "Invalid email or password" });

  if (!user.verified) {
    return res.status(401).json({ message: "Email not verified" });
  }

  const hashedPassword = crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

  const isPasswordValid = hashedPassword === user.password;

  if (!isPasswordValid)
    return res.status(401).json({ message: "Invalid email or password" });

  const refreshToken = jwt.sign(
    {
      id: user._id,
    },
    config.JWT_SECRET,
    {
      expiresIn: "7d",
    },
  );

  const refreshTokenHashed = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  const session = await sessionModel.create({
    user: user._id,
    refreshTokenHashed,
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });

  const accessToken = jwt.sign(
    {
      id: user._id,
    },
    config.JWT_SECRET,
    {
      expiresIn: "15m",
    },
  );

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: "Strict",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7day
  });

  res.status(200).json({
    message: "Logged in successfully",
    user: {
      username: user.username,
      email: user.email,
    },
    accessToken,
  });
}

// @desc Get the Current loggedIn user
// @ROUTE GET /api/auth/get-me
// @access Private
export async function getMe(req, res) {
  const token = req.headers.authorization?.split(" ")[1];
  console.log("Token:", token);

  if (!token) {
    return res.status(401).json({
      message: "Token not found",
    });
  }

  const decoded = jwt.verify(token, config.JWT_SECRET);

  const user = await userModel.findById(decoded.id);

  if (!user) {
    return res.status(404).json({
      message: "User not found",
    });
  }

  res.status(200).json({
    message: "User fetched successfully",
    user: {
      username: user.username,
      email: user.email,
    },
    token,
  });
}

// @desc Refresh Token
// @ROUTE GET /api/auth/refresh-token
// @access Private
export async function refreshToken(req, res) {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(404).json({
      message: "Refresh Token not found",
    });
  }

  const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

  const refreshTokenHashed = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  const session = await sessionModel.findOne({
    refreshTokenHashed,
    revoked: false,
  });

  if (!session) {
    return res.status(401).json({
      message: "Invalid or expired session",
    });

    const accessToken = jwt.sign(
      {
        id: decoded.id,
      },
      config.JWT_SECRET,
      {
        expiresIn: "15m",
      },
    );

    const newRefreshToken = jwt.sign(
      {
        id: decoded._id,
      },
      config.JWT_SECRET,
      {
        expiresIn: "7d",
      },
    );

    const newRefreshTokenHashed = crypto
      .createHash("sha256")
      .update(newRefreshToken)
      .digest("hex");

    session.refreshTokenHashed = newRefreshTokenHashed;
    await session.save();

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      strict: true,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, //7d
    });

    res.status(202).json({
      message: "Access Token refreshed successfully",
      accessToken,
    });
  }
}

// @desc Log out User
//@ROUTE /api/auth/logout
// @access Private
export async function logout(req, res) {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken)
    return res.status(400).json({
      message: "Refresh token not found",
    });

  const refreshTokenHashed = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  const session = await sessionModel.findOne({
    refreshTokenHashed,
    revoked: false,
  });

  if (!session) return res.status(400).json("Invalid refresh token");

  session.revoked = true;
  await session.save();

  res.clearCookie("refreshToken");

  res.status(200).json("Logged out successfully");
}

// @desc Logout all Users
// @ROUTE /api/auth/logout-all
// @access Private
export async function logoutAll(req, res) {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken)
    return res.status(400).json({ message: "Refresh token not found" });

  const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

  await sessionModel.updateMany(
    {
      user: decoded.id,
      revoked: false,
    },
    {
      revoked: true,
    },
  );

  res.clearCookie("refreshToken");

  res.status(200).json({
    message: "Logged out of all devices successfully",
  });
}

// @desc Verify Email
// @ROUTE /api/auth/verify-email
export async function verifyEmail(req, res) {
  const { otp, email } = req.body;

  const otpHashed = crypto.createHash("sha256").update(otp.toString()).digest("hex");

  const otpDoc = await otpModel.findOne({
    email,
    otpHashed,
    
  });
   console.log("looking for:", { email, otpHashed });
const allOtps = await otpModel.find({});
console.log("all otps in db:", allOtps);

  if (!otpDoc) {
    return res.status(401).json({ message: "Invalid or expired OTP" });
  }

  const user = await userModel.findByIdAndUpdate(
    otpDoc.user,
    { verified: true },
    { new: true }
  );

  await otpModel.deleteMany({ user: otpDoc.user });



  res.status(200).json({
    message: "Email verified successfully",
    user: {
      username: user.username,
      email: user.email,
      verified: user.verified,
    },
  });
}