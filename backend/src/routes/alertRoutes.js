
import express from 'express';
import {
  getAlerts,
  updateAlertStatus
} from '../controllers/alertController.js';

const router = express.Router();

router.get('/', getAlerts);

router.patch('/:id/status', updateAlertStatus);

export default router;
