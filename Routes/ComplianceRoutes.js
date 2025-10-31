/**
 * COMPLIANCE API ROUTES
 * Provides SOC compliance dashboard data
 */

import express from 'express';
import { complianceMonitor } from '../security-fixes/soc-monitoring.js';

const ComplianceRouter = express.Router();

// Get compliance status
ComplianceRouter.get('/status', async (req, res) => {
    try {
        const period = req.query.period || 'daily';
        const report = await complianceMonitor.generateComplianceReport();
        
        res.status(200).json({
            success: true,
            period,
            ...report
        });
    } catch (error) {
        console.error('Compliance status error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch compliance status',
            error: error.message
        });
    }
});

// Get compliance analytics
ComplianceRouter.get('/analytics', async (req, res) => {
    try {
        const period = req.query.period || 'daily';
        const report = await complianceMonitor.generateComplianceReport();
        
        // Generate analytics data
        const analytics = {
            totalChecks: report.results?.length || 0,
            passedChecks: report.results?.filter(r => r.passed).length || 0,
            failedChecks: report.results?.filter(r => !r.passed).length || 0,
            complianceRate: report.results?.length > 0 
                ? ((report.results.filter(r => r.passed).length / report.results.length) * 100).toFixed(2)
                : 100,
            lastChecked: report.timestamp,
            period
        };
        
        res.status(200).json({
            success: true,
            ...analytics
        });
    } catch (error) {
        console.error('Compliance analytics error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch compliance analytics',
            error: error.message
        });
    }
});

// Get compliance events/audit log
ComplianceRouter.get('/events', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const type = req.query.type || 'all';
        
        const auditLog = complianceMonitor.getAuditLog(limit);
        
        // Filter by type if specified
        const filteredEvents = type === 'all' 
            ? auditLog 
            : auditLog.filter(e => e.action?.toLowerCase().includes(type.toLowerCase()));
        
        res.status(200).json({
            success: true,
            events: filteredEvents,
            total: filteredEvents.length
        });
    } catch (error) {
        console.error('Compliance events error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch compliance events',
            error: error.message,
            events: []
        });
    }
});

export default ComplianceRouter;
