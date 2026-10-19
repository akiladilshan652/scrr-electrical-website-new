const mongoose = require('mongoose');

const JobSchema = new mongoose.Schema(
  {
    jobId: {
      type: String,
      required: [true, 'Job ID is required'],
      unique: true,
      uppercase: true,
      trim: true,
    },
    projectName: {
      type: String,
      required: [true, 'Project Name is required'],
      trim: true,
    },
    clientRef: {
      type: String,
      default: 'On File',
      trim: true,
    },
    phase: {
      type: Number,
      enum: [1, 2, 3, 4, 5],
      default: 1,
    },
    phaseName: {
      type: String,
      default: 'CAD Schematics & Engineering Approval',
    },
    statusType: {
      type: String,
      enum: ['blue', 'amber', 'green'],
      default: 'blue',
    },
    statusLabel: {
      type: String,
      default: 'Engineering Submittal Approved',
    },
    eta: {
      type: String,
      default: 'TBC',
    },
    completionRate: {
      type: Number,
      min: 0,
      max: 100,
      default: 20,
    },
    enclosure: {
      type: String,
      default: 'AS/NZS 61439 Industrial Enclosure',
    },
    rating: {
      type: String,
      default: 'Standard LV Busbar System',
    },
    leadEngineer: {
      type: String,
      default: 'SCRR Engineering Division',
    },
    compliance: {
      type: String,
      default: 'AS/NZS 61439 Standard Verified',
    },
    lastUpdated: {
      type: String,
      default: () => new Date().toLocaleString('en-AU', { timeZone: 'Australia/Brisbane' }),
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('Job', JobSchema);
