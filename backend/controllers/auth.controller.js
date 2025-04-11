import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import transporter from "../config/nodemailer.js";

export const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password)
    return res.json({ success: false, message: "Missing Details" });

  try {
    const existingUser = await User.findOne({ email: email });

    const hashedPassword = await bcrypt.hash(password, 10);

    if (existingUser) {
      return res.json({ success: false, message: "User already exists" });
    }

    const user = new User({
      name,
      email,
      password: hashedPassword,
    });

    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      // kada je dev kuki moze da se salje i kroz http
      secure: process.env.NODE_ENV === "production" ? true : false,
      // kuki radi samo u istom domenu kada je dev
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Sending welcome email
    const mailOptions = {
      from: process.env.USER_EMAIL,
      to: email,
      subject: "Welcome to Site",
      text: `Welcome to website. Your account has been created with id: ${email}`,
    };

    await transporter.sendMail(mailOptions);

    return res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({
      success: false,
      message: "Email and password are required",
    });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.json({ success: false, message: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.json({ success: false, message: "Invalid email or password" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export const logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });

    return res.json({ success: true, message: "Logged out" });
  } catch (error) {}
};

export const sendVerifyOtp = async (req, res) => {
  try {
    const { userId } = req.body;

    const user = await User.findById(userId);

    if (user.isAccountVerified) {
      return res.json({ success: false, message: "Acciybt akready verified" });
    }

    // Math random -> random value between 0 - 1 = 0.782341
    // * 900000 -> 0 - 899999.999... => 704 106.9
    // Shiftuje vrednost u opseg -> 100 000 - 999 999
    // Cut decimal part of number

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

    await user.save();
    const mailOptions = {
      from: process.env.USER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      text: `Your OTP is ${otp}. Verify your account using this OTP.`,
    };

    await transporter.sendMail(mailOptions);
    res.json({success: true, message: "Mail sent"})
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export const verifyEmail = async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp) {
    res.json({ success: false, message: "Missing details" });
  }

  try {
    const user = await User.findById(userId);
    
    if(!user){
      return res.json({ success: false, message: "User not found" })
    }

    const isMatch = user.verifyOtp === otp ? true : false;

    if(!isMatch){
      res.json({ success: false, message: "OTP is not valid" });  
    }

    if(user.verifyOtpExpireAt < Date.now()){
      res.json({ success: false, message: "OTP expired" });  
    }

    user.isAccountVerified = true;
    user.verifyOtp= '';
    user.verifyOtpExpireAt= 0;
    await user.save();
    res.json({ success: true, message: "User verified successfully" });  

  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};
