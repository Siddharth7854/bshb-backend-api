import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mongoSanitize from "express-mongo-sanitize";

const app = express();

// ---------------- Security Middleware ----------------

// Trust proxy for Render (so rate limiting works correctly)
app.set("trust proxy", 1);

app.use(helmet()); // Security headers
app.use(mongoSanitize()); // Prevent NoSQL injection

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again after 15 minutes"
});
app.use("/api/", limiter); // Apply rate limiting to API routes

const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI;

console.log("Server starting...");
console.log("Port:", PORT);
console.log("MongoDB URI found:", MONGODB_URI ? "Yes (length: " + MONGODB_URI.length + ")" : "No");

// ---------------- Middleware ----------------

app.use(cors());
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ limit: "25mb", extended: true }));

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

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    aadhaar: String,
    address: String,
    district: String,
    pincode: String,
    category: String,
    annualIncome: String,
    photo: String,
    bankAccount: String,
    ifsc: String,
    idProofType: String,
    idProofNumber: String,
    fatherHusbandName: String,
    exServiceman: String,
    disability: String,
    gender: String,
    casteCertificateNo: String,
    village: String,
    postOffice: String,
    policeStation: String,
    state: String,
    paymentMethod: String,
    transactionId: String,
    paymentStatus: String,
    paymentDate: String,
    formSubmittedDate: String,
    regNo: String,
    identityDoc: {
      name: String,
      data: String
    },
    signatureDoc: {
      name: String,
      data: String
    },
    createdAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

const applicationSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true },
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
const User = mongoose.model("User", userSchema);
const Application = mongoose.model("Application", applicationSchema);

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

app.get("/api/users/reg/:regNo", async (req, res) => {
  try {
    const user = await User.findOne({ regNo: req.params.regNo });
    if (!user) return res.status(404).json({ error: "User not found" });
    const result = user.toObject();
    delete result.password;
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------- Users ----------------

app.get("/api/users", async (req, res) => {
  try {
    const data = await User.find().sort({ createdAt: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/users", async (req, res) => {
  try {
    const userData = { ...req.body };
    if (userData.password) {
      const salt = await bcrypt.genSalt(10);
      userData.password = await bcrypt.hash(userData.password, salt);
    }
    const item = await User.create(userData);
    const result = item.toObject();
    delete result.password;
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/users/login", async (req, res) => {
  try {
    const { emailOrPhone, password } = req.body;
    const user = await User.findOne({
      $or: [{ email: emailOrPhone }, { phone: emailOrPhone }]
    });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });
    
    const result = user.toObject();
    delete result.password;
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
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

app.post("/api/applications", async (req, res) => {
  try {
    const item = await Application.create(req.body);
    res.status(201).json(item);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------- MongoDB Connection ----------------

if (!MONGODB_URI) {
  console.error("MONGODB_URI not found in .env");
  process.exit(1);
}

mongoose
  .connect(MONGODB_URI, { serverSelectionTimeoutMS: 5000 })
  .then(() => {
    console.log("MongoDB Connected");

    app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
  });