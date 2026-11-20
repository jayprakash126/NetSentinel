
import express from "express";

import {
  getAnalyticsOverview,
  getProtocolAnalytics,
  getSeverityAnalytics,
  getTimelineAnalytics,
  getTopIPAnalytics
} from "../controllers/analyticsController.js";

const router = express.Router();

router.get("/overview", getAnalyticsOverview);
router.get("/protocols", getProtocolAnalytics);
router.get("/severity", getSeverityAnalytics);
router.get("/timeline", getTimelineAnalytics);
router.get("/top-ips", getTopIPAnalytics);

export default router;
