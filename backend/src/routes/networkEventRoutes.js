
import express from "express";

import {
  getNetworkEvents,
} from "../controllers/networkEventController.js";

const router = express.Router();

router.get("/", getNetworkEvents);

export default router;
