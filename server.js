const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const requestLogger = require("./middleware/logger");
const authMiddleware = require("./middleware/auth");
const { generateToken } = require("./utils/tokenGenerator");
const crypto = require("crypto");


const app = express();
const PORT = process.env.PORT || 3000;

// Session storage (in-memory)
const loginSessions = {};
const otpStore = {};

// Middleware
app.use(cookieParser());
app.use(requestLogger);
app.use(express.json());


app.get("/", (req, res) => {
  res.json({
    challenge: "Complete the Authentication Flow",
    instruction:
      "Complete the authentication flow and obtain a valid access token.",
  });
});




// CHANGE 1: /auth/login endpoint
  app.post("/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;

    
    if (!email || !password) {
      return res.status(400).json({
        status: "error",
        message: "Email and password are required",
      });
    }

    
    const loginSessionId = crypto.randomBytes(16).toString("hex");

    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const now = Date.now();


loginSessions[loginSessionId] = {
  email,
  password,
  createdAt: now,
  expiresAt: now + 4 * 60 * 1000, // 4 minutes
};

  
    otpStore[loginSessionId] = otp;

    
    console.log(
      `[OTP] Session ${loginSessionId} generated. OTP: ${otp}`
    );

    
    return res.status(200).json({
      status: "success",
      message: "OTP sent",
      loginSessionId,
    });

    } catch (error) {
    console.error("Login Error:", error);

    return res.status(500).json({
      status: "error",
      message: "Login failed",
    });
  }
});




 

  app.post("/auth/verify-otp", (req, res) => {
  
    try {
    const { loginSessionId, otp } = req.body;

    
    if (!loginSessionId || !otp) {
      return res.status(400).json({
        status: "error",
        message: "loginSessionId and otp are required",
      });
    }

    const session = loginSessions[loginSessionId];

    
    if (!session) {
      return res.status(401).json({
        status: "error",
        message: "Invalid session",
      });
    }

    
    if (Date.now() > session.expiresAt) {
      delete loginSessions[loginSessionId];
      delete otpStore[loginSessionId];

      return res.status(401).json({
        status: "error",
        message: "Session expired",
      });
    }

    
    if (otp !== otpStore[loginSessionId]) {
      return res.status(401).json({
        status: "error",
        message: "Invalid OTP",
      });
    }

    
    res.cookie("session_token", loginSessionId, {
      httpOnly: true,
      secure: false, // must be false for localhost testing
      sameSite: "lax",
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    
    delete otpStore[loginSessionId];

    return res.status(200).json({
      status: "success",
      message: "OTP verified",
    });

  } catch (error) {
    console.error("OTP Verification Error:", error);

    return res.status(500).json({
      status: "error",
      message: "OTP verification failed",
    });
  }
});




 
app.post("/auth/token", (req, res) => {

  try {

    
    const sessionId = req.cookies.session_token;

    if (!sessionId) {
      return res.status(401).json({
        status: "error",
        message: "Unauthorized - valid session required",
      });
    }

    
    const session = loginSessions[sessionId];

    if (!session) {
      return res.status(401).json({
        status: "error",
        message: "Invalid session",
      });
    }

    
    if (Date.now() > session.expiresAt) {
      delete loginSessions[sessionId];

      return res.status(401).json({
        status: "error",
        message: "Session expired",
      });
    }

    
    const secret = process.env.JWT_SECRET || "default-secret-key";

    const accessToken = jwt.sign(
      {
        email: session.email,
        sessionId: sessionId,
      },
      secret,
      { expiresIn: "15m" }
    );

    return res.status(200).json({
      access_token: accessToken,
      expires_in: 900,
    });

  } catch (error) {
    console.error("Token Generation Error:", error);

    return res.status(500).json({
      status: "error",
      message: "Token generation failed",
    });
  }
});




// Protected route
app.get("/protected", authMiddleware, (req, res) => {
  try {
    if (!req.user || !req.user.email) {
      return res.status(401).json({
        status: "error",
        message: "Unauthorized access",
      });
    }

    const successFlag = `FLAG-${Buffer.from(
      `${req.user.email}_COMPLETED_ASSIGNMENT`
    ).toString("base64")}`;

    return res.status(200).json({
      status: "success",
      message: "Access granted",
      user: req.user,
      success_flag: successFlag,
    });

  } catch (error) {
    console.error("Protected Route Error:", error);

    return res.status(500).json({
      status: "error",
      message: "Something went wrong",
    });
  }
});


app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
