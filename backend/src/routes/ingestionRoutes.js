
import express from 'express';
import { ingestSuricataLogs } from '../controllers/ingestionController.js';

const router = express.Router();

router.post('/import', ingestSuricataLogs);

export default router;
