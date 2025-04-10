import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    requred: true,
  },
  email: {
    type: String,
    requred: true,
    unique: true,
  },
  password: {
    type: String,
    requred: true,
  },
  verifyOtp: { // 6-cifreni kod
    type: String,
    default: '',
  },
  verifyOtpExpireAt: { // timestamp u milisekundama
    type: Number, 
    default: 0
  },
  isAccountVerified: { // korisnik verifikovao nalog putem mejla
    type: Boolean,
    default: false
  },
  resetOtp: { // OTP kod koji se koristi kad korisnik hoće da resetuje lozinku
    type: String,
    default: ''
  },
  resetOtpExpireAt: {
    type: Number, 
    default: 0
  }
});

const User = mongoose.models.user || mongoose.model("User", userSchema);
export default User;