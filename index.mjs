import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mongoSanitize from "express-mongo-sanitize";
import Razorpay from "razorpay";
import crypto from "crypto";
import axios from "axios";

const app = express();

// ---------------- 2Factor SMS Configuration ----------------
const TWO_FACTOR_API_KEY = process.env.TWO_FACTOR_API_KEY;
const TWO_FACTOR_SENDER_ID = process.env.TWO_FACTOR_SENDER_ID || "BSHBEL";
const TWO_FACTOR_TEMPLATE_NAME = process.env.TWO_FACTOR_TEMPLATE_NAME || "BSHB";

/**
 * Function to send SMS via 2Factor.in
 */
const sendSMS = async (mobile, message) => {
  if (!TWO_FACTOR_API_KEY) {
    console.error("TWO_FACTOR_API_KEY is missing in environment variables");
    throw new Error("SMS service configuration missing");
  }
  try {
    // 2Factor.in API endpoint for sending OTP
    // API Format: https://2factor.in/API/V1/{api_key}/SMS/{phone_number}/{otp}/{template_name}
    
    // Clean mobile number (remove +91 if present)
    const cleanMobile = mobile.replace("+91", "").trim();
    const otp = message.match(/\d{6}/)[0];

    const url = `https://2factor.in/API/V1/${TWO_FACTOR_API_KEY}/SMS/${cleanMobile}/${otp}/${TWO_FACTOR_TEMPLATE_NAME}`;
    
    console.log(`Sending OTP via 2Factor (Template: ${TWO_FACTOR_TEMPLATE_NAME})...`);
    const response = await axios.get(url);

    console.log("2Factor Response:", response.data);
    return response.data;
  } catch (error) {
    console.error("2Factor API Error:", error.response?.data || error.message);
    throw new Error(error.response?.data?.Details || "Failed to send SMS via 2Factor");
  }
};

// ---------------- Razorpay Setup ----------------

if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.warn("⚠️  RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET is missing. Payment features will fail.");
} else {
  console.log("✅ Razorpay Keys found. Key ID starts with:", process.env.RAZORPAY_KEY_ID.substring(0, 8));
}

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ---------------- Security Middleware ----------------

// Trust proxy for Render (so rate limiting works correctly)
app.set("trust proxy", 1);

app.use(helmet()); // Security headers
app.use(cors()); // Cross-origin resource sharing
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ limit: "25mb", extended: true }));
app.use(mongoSanitize()); // Prevent NoSQL injection

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again after 15 minutes"
});
app.use("/api", limiter); // Changed from "/api/" to "/api"

const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI;

console.log("Server starting...");
console.log("Port:", PORT);
console.log("MongoDB URI found:", MONGODB_URI ? "Yes (length: " + MONGODB_URI.length + ")" : "No");

// ---------------- Middleware (Already handled above) ----------------

// ---------------- Root Route ----------------

app.get("/", (req, res) => {
  res.json({
    name: "BSHB Admin API",
    status: "running",
    port: PORT
  });
});

// ---------------- Health Check ----------------

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

// ---------------- Mongoose Schemas ----------------

const notificationSchema = new mongoose.Schema(
  {
    title: String,
    titleHi: String,
    description: String,
    date: String,
    status: { type: String, enum: ["active", "closed"], default: "active" },
    schemeType: String
  },
  { timestamps: true }
);

const tenderSchema = new mongoose.Schema(
  {
    title: String,
    description: String,
    date: String,
    lastDate: String,
    status: { type: String, enum: ["open", "closed"], default: "open" },
    department: String,
    fileName: String,
    mimeType: String,
    dataUrl: String
  },
  { timestamps: true }
);

const downloadFormatSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    description: String,
    url: String,
    fileName: String,
    mimeType: String,
    dataUrl: String
  },
  { timestamps: true }
);

const portalStatsSchema = new mongoose.Schema(
  {
    landAcquired: String,
    divisionsCovered: String,
    districtTowns: String,
    housingUnits: String,
    residentialPlots: String,
    visitorCount: { type: Number, default: 0 },
    marqueeText: String,
    heroSlides: [
      {
        title: String,
        titleHi: String,
        desc: String
      }
    ]
  },
  { timestamps: true }
);

// --- Simplified User Schema (Basic Login & Identity) ---
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    regNo: { type: String, unique: true },
    hasRegistrationProfile: { type: Boolean, default: false },
    hasHousingApplication: { type: Boolean, default: false },
    resetPasswordOTP: String,
    resetPasswordExpires: Date
  },
  { timestamps: true }
);

const registrationSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    regNo: { type: String, required: true },
    // Profile Details
    category: String,
    exServiceman: String,
    disability: String,
    gender: String,
    fatherHusbandName: String,
    idProofType: String,
    idProofNumber: String,
    casteCertificateNo: String,
    village: String,
    postOffice: String,
    policeStation: String,
    district: String,
    state: String,
    pincode: String,
    // Documents (Supabase URLs)
    identityDoc: { name: String, data: String },
    signatureDoc: { name: String, data: String },
    identityDocUrl: String,
    signatureDocUrl: String,
    // Payment
    transactionId: String,
    paymentStatus: String,
    paymentDate: String,
    formSubmittedDate: String,
    createdAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

const applicationSchema = new mongoose.Schema(
  {
    registrationId: String,
    notificationId: { type: String, required: true },
    applicationId: { type: String, unique: true },
    status: { type: String, default: "submitted" },
    submissionDate: { type: Date, default: Date.now },
    
    // Form Data
    jointAccount: String,
    flatPlotType: String,
    landline: String,
    applicantName: String,
    applicantDOB: String,
    applicantAge: String,
    email: String,
    mobile: String,
    casteCertificateNo: String,
    
    coApplicantName: String,
    coApplicantDOB: String,
    coApplicantAge: String,
    coApplicantRelationship: String,
    
    guardianName: String,
    guardianVillage: String,
    guardianPostOffice: String,
    guardianPoliceStation: String,
    guardianDistrict: String,
    guardianPincode: String,
    
    permanentVillage: String,
    permanentPostOffice: String,
    permanentPoliceStation: String,
    permanentDistrict: String,
    permanentState: String,
    permanentPincode: String,
    
    correspondenceVillage: String,
    correspondencePostOffice: String,
    correspondencePoliceStation: String,
    correspondenceDistrict: String,
    correspondencePincode: String,
    
    coGuardianName: String,
    coGuardianVillage: String,
    coGuardianPostOffice: String,
    coGuardianPoliceStation: String,
    coGuardianDistrict: String,
    coGuardianPincode: String,
    coGuardianState: String,
    
    coPermanentVillage: String,
    coPermanentPostOffice: String,
    coPermanentPoliceStation: String,
    coPermanentDistrict: String,
    coPermanentPincode: String,
    
    coCorrespondenceVillage: String,
    coCorrespondencePostOffice: String,
    coCorrespondencePoliceStation: String,
    coCorrespondenceDistrict: String,
    coCorrespondencePincode: String,
    
    bankName: String,
    bankBranch: String,
    bankIFSC: String,
    accountNumber: String,
    accountHolderName: String,
    
    applicantPAN: String,
    coApplicantPAN: String,
    
    regNo: String,
    regAmount: String,
    regDate: String,
    regBank: String,
    regTxnId: String,
    regMode: String,
    
    nomineeName: String,
    annualIncomeGroup: String,
    
    specialClaims: {
      scSt: Boolean,
      disabled: Boolean,
      exServiceman: Boolean
    },
    
    declarationName: String,
    
    formFeeStatus: String,
    formFeeTxnId: String,
    formFeeDate: String,
    formFeeMethod: String,
    
    emdStatus: String,
    emdTxnId: String,
    emdDate: String,
    emdMethod: String,
    
    // Documents (URLs from Supabase)
    applicantPhoto: { name: String, data: String },
    applicantSignature: { name: String, data: String },
    coApplicantPhoto: { name: String, data: String },
    coApplicantSignature: { name: String, data: String },
    
    // Explicit Document URLs
    applicantPhotoUrl: String,
    applicantSignatureUrl: String,
    casteCertUrl: String,
    aadhaarCardUrl: String,
    panCardUrl: String,
    residentialCertUrl: String,
    incomeCertUrl: String,
    affidavitUrl: String,
    bankPassbookUrl: String,
    
    annexures: {
      casteCert: { name: String, data: String },
      aadhaarCard: { name: String, data: String },
      panCard: { name: String, data: String },
      residentialCert: { name: String, data: String },
      affidavit: { name: String, data: String },
      depositProof: { name: String, data: String },
      incomeCert: { name: String, data: String },
      applicantAffidavit: { name: String, data: String },
      bankPassbook: { name: String, data: String },
      exServicemanDocs: { name: String, data: String },
      disabilityCert: { name: String, data: String },
      coAffidavit: { name: String, data: String },
      voterId: { name: String, data: String }
    }
  },
  { timestamps: true }
);

// ---------------- Models ----------------

const Notification = mongoose.model("Notification", notificationSchema);
const Tender = mongoose.model("Tender", tenderSchema);
const DownloadFormat = mongoose.model("DownloadFormat", downloadFormatSchema);
const PortalStats = mongoose.model("PortalStats", portalStatsSchema);
const User = mongoose.model("User", userSchema, "users");
const Registration = mongoose.model("Registration", registrationSchema, "applicants_registrations");
const Application = mongoose.model("Application", applicationSchema, "housing_applications");

// ---------------- OTP Store (Temporary for validation) ----------------
// In a real production app, use Redis or a DB collection with TTL
const otpStore = new Map();

// ---------------- OTP APIs ----------------

app.post("/api/otp/send", async (req, res) => {
  try {
    const { mobile } = req.body;
    if (!mobile) return res.status(400).json({ error: "Mobile number is required" });

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store OTP with 5-minute expiry
    otpStore.set(mobile, {
      otp,
      expires: Date.now() + 5 * 60 * 1000
    });

    const message = `Your BSHB Bihar Housing Connect verification code is: ${otp}. Valid for 5 minutes.`;
    
    // Send via Fast2SMS
    try {
      await sendSMS(mobile, message);
      res.json({ success: true, message: "OTP sent successfully" });
    } catch (smsErr) {
      console.error("SMS Service Error:", smsErr.message);
      res.status(502).json({ error: "SMS gateway failed: " + smsErr.message });
    }
  } catch (err) {
    console.error("OTP API Error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/otp/verify", async (req, res) => {
  try {
    const { mobile, otp } = req.body;
    if (!mobile || !otp) return res.status(400).json({ error: "Mobile and OTP are required" });

    const storedData = otpStore.get(mobile);
    
    if (!storedData) {
      return res.status(400).json({ error: "No OTP found for this number" });
    }

    if (Date.now() > storedData.expires) {
      otpStore.delete(mobile);
      return res.status(400).json({ error: "OTP expired" });
    }

    if (storedData.otp === otp) {
      otpStore.delete(mobile);
      res.json({ success: true, message: "OTP verified successfully" });
    } else {
      res.status(400).json({ error: "Invalid OTP" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------- Payment Schema ----------------

const paymentSchema = new mongoose.Schema(
  {
    orderId: { type: String, required: true },
    paymentId: String,
    signature: String,
    amount: { type: Number, required: true },
    currency: { type: String, default: "INR" },
    status: {
      type: String,
      enum: ["created", "success", "failed"],
      default: "created",
    },
    registrationId: String,
    regNo: String,
    paymentType: {
      type: String,
      enum: ["registration", "application_fee", "emd"],
      required: true,
    },
  },
  { timestamps: true }
);

const Payment = mongoose.model("Payment", paymentSchema, "payments_history");

// ---------------- Notifications ----------------

app.get("/api/notifications", async (req, res) => {
  try {
    const data = await Notification.find().sort({ createdAt: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/notifications", async (req, res) => {
  try {
    const item = await Notification.create(req.body);
    res.status(201).json(item);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/notifications/:id", async (req, res) => {
  try {
    await Notification.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------- Tenders ----------------

app.get("/api/tenders", async (req, res) => {
  try {
    const data = await Tender.find().sort({ createdAt: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/tenders", async (req, res) => {
  try {
    const item = await Tender.create(req.body);
    res.status(201).json(item);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/tenders/:id", async (req, res) => {
  try {
    await Tender.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------- Download Formats ----------------

app.get("/api/download-formats", async (req, res) => {
  try {
    const data = await DownloadFormat.find().sort({ createdAt: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/download-formats", async (req, res) => {
  try {
    const bodySize = JSON.stringify(req.body).length;
    console.log("Saving download format:", req.body.name, "| Size:", (bodySize / 1024).toFixed(2), "KB");
    const item = await DownloadFormat.create(req.body);
    console.log("Saved download format ID:", item._id);
    res.status(201).json(item);
  } catch (err) {
    console.error("Error saving download format:", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/download-formats/:id", async (req, res) => {
  try {
    await DownloadFormat.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------- Portal Stats ----------------

app.get("/api/portal-stats", async (req, res) => {
  try {
    let stats = await PortalStats.findOne();

    if (!stats) {
      stats = await PortalStats.create({});
    }

    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/portal-stats", async (req, res) => {
  try {
    const stats = await PortalStats.findOneAndUpdate({}, req.body, {
      new: true,
      upsert: true
    });

    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/registrations/reg/:regNo", async (req, res) => {
  try {
    const registration = await Registration.findOne({ regNo: req.params.regNo });
    if (!registration) return res.status(404).json({ error: "Registration not found" });
    res.json(registration);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------- Users (Simplified Accounts) ----------------

app.get("/api/users", async (req, res) => {
  try {
    const data = await User.find().sort({ createdAt: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/users/login", async (req, res) => {
  try {
    const { emailOrPhone, password } = req.body;
    
    if (!emailOrPhone || !password) {
      return res.status(400).json({ error: "Credentials are required" });
    }

    // 1. Try finding in the simplified 'User' collection first
    let user = await User.findOne({
      $or: [
        { email: emailOrPhone }, 
        { phone: emailOrPhone },
        { regNo: emailOrPhone }
      ]
    });

    // 2. Fallback: If not found in 'User', check 'Registration' (for older users)
    if (!user) {
      const registration = await Registration.findOne({
        $or: [
          { email: emailOrPhone }, 
          { phone: emailOrPhone },
          { regNo: emailOrPhone }
        ]
      });
      
      if (registration) {
        // Found in registrations, check password
        const isMatch = await bcrypt.compare(password, registration.password);
        if (isMatch) {
          // Success, create a simplified User record for future logins
          user = await User.create({
            name: registration.name,
            email: registration.email,
            phone: registration.phone,
            password: registration.password, // already hashed
            regNo: registration.regNo,
            hasRegistrationProfile: true
          });
        }
      }
    } else {
      // User found in 'User' collection, check password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: "Authentication failed: Invalid credentials" });
    }

    if (!user) return res.status(401).json({ error: "Authentication failed: Invalid credentials" });
    
    const result = user.toObject();
    delete result.password;
    res.json(result);
  } catch (err) {
    console.error("Login API Error:", err);
    res.status(500).json({ error: "Internal Server Error during login." });
  }
});

app.post("/api/users/update-password", async (req, res) => {
  try {
    const { emailOrPhone, newPassword } = req.body;
    
    // 1. Try finding in 'User' collection
    let user = await User.findOne({
      $or: [{ email: emailOrPhone }, { phone: emailOrPhone }, { regNo: emailOrPhone }]
    });

    // 2. Try finding in 'Registration' collection if not in 'User'
    let registration = await Registration.findOne({
      $or: [{ email: emailOrPhone }, { phone: emailOrPhone }, { regNo: emailOrPhone }]
    });

    if (!user && !registration) {
      return res.status(404).json({ error: "User not found in our records" });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update in User collection if exists
    if (user) {
      user.password = hashedPassword;
      await user.save();
    }

    // Update in Registration collection if exists
    if (registration) {
      registration.password = hashedPassword;
      await registration.save();
      
      // If user record didn't exist, create it now to sync
      if (!user) {
        await User.create({
          name: registration.name,
          email: registration.email,
          phone: registration.phone,
          password: hashedPassword,
          regNo: registration.regNo,
          hasRegistrationProfile: true
        });
      }
    }

    res.json({ success: true, message: "Password updated successfully" });
  } catch (error) {
    console.error("Update Password Error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---------------- Registrations (Full Profile) ----------------

app.get("/api/registrations", async (req, res) => {
  try {
    const data = await Registration.find().sort({ createdAt: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/registrations", async (req, res) => {
  try {
    const regData = { ...req.body };
    const { name, email, phone, password, regNo, identityDoc, signatureDoc } = regData;

    // --- Mandatory Field Check ---
    if (!name || !email || !phone || !password || !regNo) {
      return res.status(400).json({ error: "Missing mandatory fields: name, email, phone, password, and regNo are required." });
    }

    if (!identityDoc?.data || !signatureDoc?.data) {
      return res.status(400).json({ error: "Mandatory documents (Identity Proof and Signature) are required." });
    }

    // 1. Create User (Basic Login)
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await User.create({
      name,
      email,
      phone,
      password: hashedPassword,
      regNo,
      hasRegistrationProfile: true
    });

    // 2. Create Registration Profile
    const profileData = { ...regData };
    delete profileData.password;
    
    // Add explicit URL fields for documents if present
    if (profileData.identityDoc?.data) profileData.identityDocUrl = profileData.identityDoc.data;
    if (profileData.signatureDoc?.data) profileData.signatureDocUrl = profileData.signatureDoc.data;

    const item = await Registration.create(profileData);
    
    const result = newUser.toObject();
    delete result.password;
    res.status(201).json(result);
  } catch (err) {
    console.error("Registration Error:", err);
    // Handle Duplicate Key Errors (MongoDB 11000)
    if (err.code === 11000) {
      return res.status(409).json({ error: "Registration failed: Email, Phone, or Registration Number already exists." });
    }
    res.status(500).json({ error: "Internal Server Error during registration." });
  }
});

// ---------------- Applications ----------------

app.get("/api/applications", async (req, res) => {
  try {
    const data = await Application.find().sort({ createdAt: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/applications/:applicationId", async (req, res) => {
  try {
    const application = await Application.findOne({ applicationId: req.params.applicationId });
    if (!application) return res.status(404).json({ error: "Application not found" });
    res.json(application);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/applications", async (req, res) => {
  try {
    const appData = { ...req.body };
    
    // --- Mandatory Field Check (Government Compliance) ---
    const requiredFields = [
      'applicantName', 'mobile', 'email', 'notificationId', 'applicationId', 
      'permanentVillage', 'permanentDistrict', 'permanentState', 'permanentPincode',
      'bankName', 'accountNumber', 'bankIFSC', 'applicantPAN'
    ];

    for (const field of requiredFields) {
      if (!appData[field]) {
        return res.status(400).json({ error: `Mandatory field missing: ${field} is required for government compliance.` });
      }
    }

    // Check mandatory document URLs
    if (!appData.applicantPhoto?.data || !appData.applicantSignature?.data) {
      return res.status(400).json({ error: "Applicant Photo and Signature are mandatory documents." });
    }
    
    // Extract URLs for easy access
    if (appData.applicantPhoto?.data) appData.applicantPhotoUrl = appData.applicantPhoto.data;
    if (appData.applicantSignature?.data) appData.applicantSignatureUrl = appData.applicantSignature.data;
    if (appData.annexures) {
      const { annexures } = appData;
      if (annexures.casteCert?.data) appData.casteCertUrl = annexures.casteCert.data;
      if (annexures.aadhaarCard?.data) appData.aadhaarCardUrl = annexures.aadhaarCard.data;
      if (annexures.panCard?.data) appData.panCardUrl = annexures.panCard.data;
      if (annexures.residentialCert?.data) appData.residentialCertUrl = annexures.residentialCert.data;
      if (annexures.incomeCert?.data) appData.incomeCertUrl = annexures.incomeCert.data;
      if (annexures.affidavit?.data) appData.affidavitUrl = annexures.affidavit.data;
      if (annexures.bankPassbook?.data) appData.bankPassbookUrl = annexures.bankPassbook.data;
    }

    const item = await Application.create(appData);
    
    // Update User flag to indicate they have filled an application
    if (appData.regNo) {
      await User.findOneAndUpdate(
        { regNo: appData.regNo },
        { hasHousingApplication: true }
      );
    }
    
    res.status(201).json(item);
  } catch (err) {
    console.error("Application Submission Error:", err);
    res.status(500).json({ error: "Internal Server Error during application submission." });
  }
});

// ---------------- Razorpay Payment APIs ----------------

app.get("/api/payments/test", (req, res) => {
  res.json({ message: "Payment routes are active" });
});

app.post("/api/payments/create-order", async (req, res) => {
  try {
    const { amount, userId, regNo, paymentType } = req.body;

    if (!amount || !paymentType) {
      return res.status(400).json({ error: "Amount and paymentType are required" });
    }

    const options = {
      amount: Math.round(amount * 100), // Convert to paise
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
    };

    const order = await razorpay.orders.create(options);

    // Save to DB
    await Payment.create({
      orderId: order.id,
      amount: amount,
      registrationId: req.body.registrationId || userId,
      regNo: regNo,
      paymentType: paymentType,
      status: "created",
    });

    res.json(order);
  } catch (err) {
    console.error("Razorpay Create Order Error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/payments/verify", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const key_secret = process.env.RAZORPAY_KEY_SECRET;

    const generated_signature = crypto
      .createHmac("sha256", key_secret)
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest("hex");

    if (generated_signature === razorpay_signature) {
      // Update Payment Record
      await Payment.findOneAndUpdate(
        { orderId: razorpay_order_id },
        {
          paymentId: razorpay_payment_id,
          signature: razorpay_signature,
          status: "success",
        }
      );

      res.json({ success: true, message: "Payment verified successfully" });
    } else {
      await Payment.findOneAndUpdate(
        { orderId: razorpay_order_id },
        { status: "failed" }
      );

      res.status(400).json({ success: false, message: "Invalid signature" });
    }
  } catch (err) {
    console.error("Razorpay Verify Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------------- MongoDB Connection ----------------

const connectDB = async () => {
  if (!MONGODB_URI) {
    console.error("❌ MONGODB_URI not found in environment variables");
    return;
  }

  try {
    await mongoose.connect(MONGODB_URI, { 
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000
    });
    console.log("✅ MongoDB Connected Successfully");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err.message);
    console.log("Retrying connection in 5 seconds...");
    setTimeout(connectDB, 5000);
  }
};

// Start the server first (Better for Render.com to avoid boot timeouts)
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  console.log("Attempting to connect to MongoDB...");
  connectDB();
});