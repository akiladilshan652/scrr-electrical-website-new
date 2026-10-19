require('dotenv').config();
const dns = require('dns');
try {
  dns.setServers(['8.8.8.8', '8.8.4.4']);
} catch (e) {
  // Fallback to default system DNS if setServers is restricted
}
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const csvParser = require('csv-parser');
const rateLimit = require('express-rate-limit');
const { Readable } = require('stream');

const Job = require('./models/Job');
const Admin = require('./models/Admin');

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'scrr_electrical_jwt_secret_2024';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';

// Trust proxy for rate limiter when behind reverse proxies
app.set('trust proxy', 1);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate Limiter for API endpoints
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // Limit each IP to 300 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Too many requests from this IP, please try again after 15 minutes.',
  },
});

app.use('/api', apiLimiter);

// Multer memory storage for CSV parsing
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Seed sample jobs helper
const initialJobs = [
  {
    jobId: 'S2670',
    projectName: 'Chevallum Industrial Park Phase 2 - Main Switchboard 1600A',
    clientRef: 'Apex Electrical Contracting Pty Ltd',
    phase: 4,
    phaseName: 'AS/NZS 61439 QA & Dielectric Testing',
    statusType: 'amber',
    statusLabel: 'Factory Testing & QA Verification',
    eta: 'Dispatched in 48 Hours (2 Business Days)',
    completionRate: 80,
    enclosure: 'Elsteel Techno Module Form 3b (IP54)',
    rating: '1600A 50kA/1s 3-Phase 415V',
    leadEngineer: 'Grant H., B.Eng (Elec)',
    compliance: 'AS/NZS 61439.1 & 2 Type-Tested',
    lastUpdated: 'Today at 08:45 AM AEST',
  },
  {
    jobId: 'S2540',
    projectName: 'Regional Pumping Station Upgrade - 400A Weatherproof Control Assembly',
    clientRef: 'Coastline Water & Civil Infrastructure',
    phase: 5,
    phaseName: 'FAT Certified & Dispatched / Ready for Delivery',
    statusType: 'green',
    statusLabel: 'Ready for Collection & Freight Staging',
    eta: 'Ready for Immediate Dispatch',
    completionRate: 100,
    enclosure: '316 Marine Grade Stainless Steel (IP66)',
    rating: '400A 25kA/1s Rainproof Enclosure',
    leadEngineer: 'Marcus V., Senior Systems Engineer',
    compliance: 'AS/NZS 61439.2 & IP66 Certified',
    lastUpdated: 'Today at 11:20 AM AEST',
  },
  {
    jobId: 'S2710',
    projectName: 'Maroochydore Commercial Complex - Energex 630A CT Metering Suite',
    clientRef: 'Q-Elec Industrial Contractors',
    phase: 2,
    phaseName: 'CNC Laser Cutting & Metal Fabrication',
    statusType: 'blue',
    statusLabel: 'Active Enclosure Fabrication',
    eta: '6 Business Days (Estimated Oct 24)',
    completionRate: 40,
    enclosure: '2.0mm Zincanneal Powder Coated Pebble Grey (IP54)',
    rating: '630A CT Metering Chamber (QECM Spec)',
    leadEngineer: 'Liam K., Switchgear Specialist',
    compliance: 'Energex Approved & QECM Compliant',
    lastUpdated: 'Yesterday at 04:15 PM AEST',
  },
  {
    jobId: 'S2895',
    projectName: 'Kawana Health & Specialist Suites - Distribution Boards (x4 Units)',
    clientRef: 'ProActive Power & Energy Solutions',
    phase: 1,
    phaseName: 'CAD Schematics & Engineering Approval',
    statusType: 'blue',
    statusLabel: 'Engineering Submittal Approved',
    eta: '10 Business Days (Estimated Oct 28)',
    completionRate: 20,
    enclosure: 'Modular Distribution Chassis (IP54)',
    rating: '250A Encapsulated Chassis (48-Pole)',
    leadEngineer: 'Grant H., B.Eng (Elec)',
    compliance: 'AS/NZS 61439 Compliant',
    lastUpdated: '2 Days Ago',
  },
];

async function seedInitialDatabase() {
  try {
    for (const job of initialJobs) {
      await Job.findOneAndUpdate(
        { jobId: job.jobId },
        { ...job, updatedAt: new Date() },
        { upsert: true, new: true }
      );
    }
    console.log('[Database] Seeded 4 reference production jobs successfully.');

    // Create a default administrator if none exists
    const adminCount = await Admin.countDocuments();
    if (adminCount === 0) {
      const defaultEmail = 'admin@scrr.com.au';
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash('SCRRpower2024!', salt);
      await Admin.create({
        email: defaultEmail,
        passwordHash,
        name: 'SCRR Master Administrator',
        role: 'superadmin',
      });
      console.log(`[Database] Default administrator created: ${defaultEmail} (Password: SCRRpower2024!)`);
    }
  } catch (err) {
    console.error('[Database] Seeding error:', err.message);
  }
}

// Authentication Middleware: Verify JWT & @scrr.com.au email domain
function verifyAdminToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ status: 'error', message: 'Access denied. No token provided.' });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ status: 'error', message: 'Token format must be Bearer <token>' });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.email || !decoded.email.toLowerCase().endsWith('@scrr.com.au')) {
      return res.status(403).json({
        status: 'error',
        message: 'Forbidden. Access restricted to verified @scrr.com.au accounts.',
      });
    }
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ status: 'error', message: 'Invalid or expired session token.' });
  }
}

/* ==========================================================================
   PUBLIC API ROUTES
   ========================================================================== */

// 1. Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    server: 'SCRR Electrical (Pty) Ltd Production API v1.0',
    dbState: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString(),
  });
});

// 2. Public Live Job Tracker Lookup
app.get('/api/jobs/:jobId', async (req, res) => {
  try {
    const jobId = req.params.jobId.trim().toUpperCase();
    const job = await Job.findOne({ jobId });

    if (!job) {
      return res.status(404).json({
        found: false,
        message: `Job ID ${jobId} not found in live production database.`,
      });
    }

    res.json({
      found: true,
      job,
    });
  } catch (err) {
    res.status(500).json({
      found: false,
      message: 'Failed to query production database.',
      error: err.message,
    });
  }
});

/* ==========================================================================
   ADMIN AUTHENTICATION & MANAGEMENT ROUTES
   ========================================================================== */

// 3. Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ status: 'error', message: 'Email and password are required.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail.endsWith('@scrr.com.au')) {
      return res.status(403).json({
        status: 'error',
        message: 'Security validation failed: Access is strictly restricted to @scrr.com.au accounts.',
      });
    }

    let admin = await Admin.findOne({ email: cleanEmail });

    // If no admin exists yet with this email, but it's an authorized @scrr.com.au address, create it
    if (!admin) {
      const adminCount = await Admin.countDocuments();
      if (adminCount === 0 || cleanEmail === 'admin@scrr.com.au') {
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        admin = await Admin.create({
          email: cleanEmail,
          passwordHash,
          name: cleanEmail.split('@')[0].toUpperCase(),
          role: 'superadmin',
        });
      } else {
        return res.status(401).json({ status: 'error', message: 'Invalid credentials provided.' });
      }
    }

    const isMatch = await bcrypt.compare(password, admin.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ status: 'error', message: 'Invalid credentials provided.' });
    }

    admin.lastLogin = new Date();
    await admin.save();

    const token = jwt.sign(
      {
        id: admin._id,
        email: admin.email,
        name: admin.name,
        role: admin.role,
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      status: 'success',
      token,
      admin: {
        email: admin.email,
        name: admin.name,
        role: admin.role,
      },
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: 'Login failed', error: err.message });
  }
});

// 4. Admin - Fetch All Jobs
app.get('/api/admin/jobs', verifyAdminToken, async (req, res) => {
  try {
    const jobs = await Job.find().sort({ updatedAt: -1 });
    res.json({ status: 'success', count: jobs.length, jobs });
  } catch (err) {
    res.status(500).json({ status: 'error', message: 'Failed to retrieve jobs', error: err.message });
  }
});

// 5. Admin - Upsert Single Job
app.post('/api/admin/jobs/upsert', verifyAdminToken, async (req, res) => {
  try {
    const data = req.body;
    if (!data.jobId) {
      return res.status(400).json({ status: 'error', message: 'Job ID is required.' });
    }

    const jobId = data.jobId.trim().toUpperCase();
    const phaseNames = [
      'CAD Schematics & Engineering Approval',
      'CNC Laser Cutting & Metal Fabrication',
      'Copper Busbar Looming & Component Wiring',
      'AS/NZS 61439 QA & Dielectric Testing',
      'FAT Certified & Dispatched / Ready for Delivery',
    ];

    const statusLabels = [
      'Engineering Submittal Approved',
      'Active Enclosure Fabrication',
      'Wiring & Looming Phase',
      'Factory Testing & QA Verification',
      'Ready for Collection & Freight Staging',
    ];

    const phase = parseInt(data.phase) || 1;
    const phaseName = data.phaseName || phaseNames[phase - 1] || 'In Production';
    const statusType = data.statusType || (phase === 5 ? 'green' : phase === 4 ? 'amber' : 'blue');
    const statusLabel = data.statusLabel || statusLabels[phase - 1] || 'In Progress';
    const completionRate = data.completionRate !== undefined ? Number(data.completionRate) : phase * 20;

    const updatePayload = {
      ...data,
      jobId,
      phase,
      phaseName,
      statusType,
      statusLabel,
      completionRate,
      lastUpdated: data.lastUpdated || new Date().toLocaleString('en-AU', { timeZone: 'Australia/Brisbane' }),
      updatedAt: new Date(),
    };

    const savedJob = await Job.findOneAndUpdate({ jobId }, updatePayload, {
      upsert: true,
      new: true,
      runValidators: true,
    });

    res.json({ status: 'success', message: `Job ${jobId} saved successfully.`, job: savedJob });
  } catch (err) {
    res.status(500).json({ status: 'error', message: 'Failed to upsert job', error: err.message });
  }
});

// 6. Admin - Bulk CSV Upload
app.post('/api/admin/jobs/upload-csv', verifyAdminToken, upload.single('csvFile'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ status: 'error', message: 'No CSV file uploaded.' });
  }

  const results = [];
  const bufferStream = new Readable();
  bufferStream.push(req.file.buffer);
  bufferStream.push(null);

  bufferStream
    .pipe(csvParser({ mapHeaders: ({ header }) => header.trim() }))
    .on('data', (row) => results.push(row))
    .on('end', async () => {
      let processed = 0;
      let errors = 0;

      for (const row of results) {
        try {
          const rawId = row.jobId || row.JobId || row.JobID || row.id || row['Job ID'];
          if (!rawId) continue;

          const jobId = String(rawId).trim().toUpperCase();
          const phase = parseInt(row.phase || row.Phase) || 1;
          const phaseNames = [
            'CAD Schematics & Engineering Approval',
            'CNC Laser Cutting & Metal Fabrication',
            'Copper Busbar Looming & Component Wiring',
            'AS/NZS 61439 QA & Dielectric Testing',
            'FAT Certified & Dispatched / Ready for Delivery',
          ];
          const statusLabels = [
            'Engineering Submittal Approved',
            'Active Enclosure Fabrication',
            'Wiring & Looming Phase',
            'Factory Testing & QA Verification',
            'Ready for Collection & Freight Staging',
          ];

          const payload = {
            jobId,
            projectName: row.projectName || row.ProjectName || row['Project Name'] || `Switchboard Assembly (${jobId})`,
            clientRef: row.clientRef || row.ClientRef || row['Client Ref'] || 'On File',
            phase,
            phaseName: row.phaseName || phaseNames[phase - 1],
            statusType: row.statusType || (phase === 5 ? 'green' : phase === 4 ? 'amber' : 'blue'),
            statusLabel: row.statusLabel || statusLabels[phase - 1],
            eta: row.eta || row.ETA || 'Dispatched per schedule',
            completionRate: parseInt(row.completionRate) || phase * 20,
            enclosure: row.enclosure || row.Enclosure || 'Standard AS/NZS 61439 Enclosure',
            rating: row.rating || row.Rating || 'Standard LV Busbar System',
            leadEngineer: row.leadEngineer || row.LeadEngineer || 'SCRR Engineering Division',
            compliance: row.compliance || row.Compliance || 'AS/NZS 61439 Verified',
            lastUpdated: new Date().toLocaleString('en-AU', { timeZone: 'Australia/Brisbane' }),
            updatedAt: new Date(),
          };

          await Job.findOneAndUpdate({ jobId }, payload, { upsert: true, new: true });
          processed++;
        } catch (err) {
          errors++;
        }
      }

      res.json({
        status: 'success',
        processed,
        errors,
        totalRows: results.length,
        message: `Successfully processed ${processed} jobs from CSV.`,
      });
    })
    .on('error', (err) => {
      res.status(500).json({ status: 'error', message: 'Failed to parse CSV file', error: err.message });
    });
});

// 7. Admin - Delete Job
app.delete('/api/admin/jobs/:jobId', verifyAdminToken, async (req, res) => {
  try {
    const jobId = req.params.jobId.trim().toUpperCase();
    const result = await Job.findOneAndDelete({ jobId });

    if (!result) {
      return res.status(404).json({ status: 'error', message: `Job ${jobId} not found.` });
    }

    res.json({ status: 'success', message: `Job ${jobId} deleted successfully.` });
  } catch (err) {
    res.status(500).json({ status: 'error', message: 'Failed to delete job', error: err.message });
  }
});

// 8. Admin - Seed Database
app.post('/api/admin/seed', verifyAdminToken, async (req, res) => {
  try {
    for (const job of initialJobs) {
      await Job.findOneAndUpdate(
        { jobId: job.jobId },
        { ...job, updatedAt: new Date() },
        { upsert: true, new: true }
      );
    }
    res.json({
      status: 'success',
      message: `Database successfully seeded with ${initialJobs.length} reference jobs.`,
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: 'Database seeding failed', error: err.message });
  }
});

/* ==========================================================================
   STATIC FILE SERVING & SPA FALLBACK
   ========================================================================== */

const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

app.get('*', (req, res) => {
  res.sendFile(path.join(publicPath, 'index.html'));
});

// Connect to MongoDB Atlas and start server
mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log('[MongoDB Atlas] Connected successfully to scrr_db cluster.');
    await seedInitialDatabase();
    app.listen(PORT, () => {
      console.log(`[SCRR Electrical Server] Master server active on http://localhost:${PORT}`);
      console.log(`[Static Files] Serving production assets from ${publicPath}`);
    });
  })
  .catch((err) => {
    console.error('[MongoDB Atlas] Connection failed:', err.message);
    // Still start server to serve static assets and fallback data
    app.listen(PORT, () => {
      console.log(`[SCRR Electrical Server] Server active on http://localhost:${PORT} (Offline DB mode)`);
    });
  });
