/**
 * SOC COMPLIANCE CONTROLS (Optimized & Simplified)
 * SOC 1, 2, 3 implementation
 */

import chalk from 'chalk';
import mongoose from 'mongoose';
import crypto from 'crypto';

// ============================================================================
// SCHEMAS (Optimized - Moved to top)
// ============================================================================

const base = { timestamp: { type: Date, default: Date.now, index: true }, eventType: String, controlId: String };

// Financial (7yr)
const FinancialSchema = new mongoose.Schema({
    ...base, transactionId: String, userId: String, amount: Number, currency: { type: String, default: 'USD' },
    type: String, status: String, ipAddress: String, metadata: mongoose.Schema.Types.Mixed
}, { collection: 'financial_audit_logs', timestamps: true });
FinancialSchema.index({ timestamp: 1 }, { expireAfterSeconds: 220752000 });

// Security (90d)
const SecuritySchema = new mongoose.Schema({
    ...base, userId: String, action: String, resource: String, result: String, ipAddress: String,
    userAgent: String, severity: String, details: mongoose.Schema.Types.Mixed, errorMessage: String
}, { collection: 'security_audit_logs', timestamps: true });
SecuritySchema.index({ timestamp: 1 }, { expireAfterSeconds: 7776000 });

// Confidential (90d)
const ConfidentialSchema = new mongoose.Schema({
    ...base, userId: String, action: String, dataType: String, dataId: String, classification: String,
    ipAddress: String, userAgent: String, result: String, severity: String
}, { collection: 'confidential_access_logs', timestamps: true });
ConfidentialSchema.index({ timestamp: 1 }, { expireAfterSeconds: 7776000 });

// Privacy (7yr)
const PrivacySchema = new mongoose.Schema({
    ...base, userId: String, details: mongoose.Schema.Types.Mixed, ipAddress: String, severity: String
}, { collection: 'privacy_audit_logs', timestamps: true });
PrivacySchema.index({ timestamp: 1 }, { expireAfterSeconds: 220752000 });

// Reviews
const ReviewSchema = new mongoose.Schema({
    transactionId: String, reason: String, details: mongoose.Schema.Types.Mixed,
    status: { type: String, default: 'PENDING_REVIEW' }, reviewedBy: String, reviewedAt: Date,
    flaggedAt: { type: Date, default: Date.now }
}, { collection: 'transaction_reviews', timestamps: true });

// Discrepancies
const DiscrepancySchema = new mongoose.Schema({
    transactionId: String, localAmount: Number, stripeAmount: Number, difference: Number,
    status: String, resolvedBy: String, resolvedAt: Date, reportedAt: { type: Date, default: Date.now }
}, { collection: 'payment_discrepancies', timestamps: true });

export const FinancialAuditLog = mongoose.model('FinancialAuditLog', FinancialSchema);
export const SecurityAuditLog = mongoose.model('SecurityAuditLog', SecuritySchema);
export const ConfidentialAccessLog = mongoose.model('ConfidentialAccessLog', ConfidentialSchema);
export const PrivacyAuditLog = mongoose.model('PrivacyAuditLog', PrivacySchema);
export const TransactionReview = mongoose.model('TransactionReview', ReviewSchema);
export const PaymentDiscrepancy = mongoose.model('PaymentDiscrepancy', DiscrepancySchema);

// ============================================================================
// AUDIT LOGGER (Simplified)
// ============================================================================

const colors = { CRITICAL: chalk.red, HIGH: chalk.yellow, MEDIUM: chalk.blue, LOW: chalk.gray, INFO: chalk.white };
const log = async (Model, data, emoji, label) => {
    console.log(chalk.blue(`${emoji} [${label}]`), { id: data.transactionId || data.userId, type: data.type || data.action });
    try { await Model.create(data); } catch (e) { console.error(chalk.red('❌ Log failed:'), e.message); }
    return data;
};

export const auditLogger = {
    logFinancialTransaction: async (t) => log(FinancialAuditLog, {
        timestamp: new Date(), eventType: 'FINANCIAL_TRANSACTION', controlId: 'CC2.1',
        transactionId: t.id, userId: t.userId, amount: t.amount, currency: t.currency || 'USD',
        type: t.type, status: t.status, ipAddress: t.ip, metadata: t.metadata || {}
    }, '💰', 'FINANCIAL'),

    logSecurityEvent: async (e) => {
        const data = {
            timestamp: new Date(), eventType: 'SECURITY_EVENT', controlId: 'CC6.1',
            userId: e.userId, action: e.action, resource: e.resource, result: e.result,
            ipAddress: e.ip, userAgent: e.userAgent, severity: e.severity || 'INFO', details: e.details || {}
        };
        const color = colors[data.severity] || chalk.white;
        console.log(color(`🔐 [SECURITY-${data.severity}]`), { action: data.action, result: data.result });
        try { await SecurityAuditLog.create(data); } catch (err) { console.error(chalk.red('❌'), err.message); }
        return data;
    },

    logUnauthorizedAccess: async (a) => log(SecurityAuditLog, {
        timestamp: new Date(), eventType: 'UNAUTHORIZED_ACCESS', controlId: 'CC6.1',
        ipAddress: a.ip, action: a.path, resource: a.method, result: a.reason, userAgent: a.userAgent, severity: 'HIGH'
    }, '🚫', 'UNAUTHORIZED'),

    logConfidentialAccess: async (a) => {
        const data = {
            timestamp: new Date(), eventType: 'CONFIDENTIAL_ACCESS', controlId: 'C1.2',
            userId: a.userId, action: a.action, dataType: a.dataType, dataId: a.dataId, classification: a.classification,
            ipAddress: a.ip, userAgent: a.userAgent, result: a.result, severity: a.classification === 'RESTRICTED' ? 'HIGH' : 'MEDIUM'
        };
        await log(ConfidentialAccessLog, data, '🔐', 'CONFIDENTIAL');
        
        if (a.classification === 'RESTRICTED') {
            const recent = await ConfidentialAccessLog.find({
                userId: a.userId, classification: 'RESTRICTED', timestamp: { $gte: new Date(Date.now() - 300000) }
            });
            if (recent.length > 10) {
                console.log(chalk.red('🚨 [SUSPICIOUS]'), { userId: a.userId, count: recent.length });
                await auditLogger.logSecurityEvent({
                    userId: a.userId, action: 'SUSPICIOUS_ACCESS', resource: 'CONFIDENTIAL_DATA',
                    result: 'ALERT', ip: a.ip, severity: 'CRITICAL', details: { count: recent.length }
                });
            }
        }
        return data;
    },

    logPrivacyEvent: async (e) => log(PrivacyAuditLog, {
        timestamp: new Date(), eventType: e.type, controlId: e.type.startsWith('CONSENT') ? 'P2.1' : 'P3.1',
        userId: e.userId, details: e.details, ipAddress: e.ip, severity: 'INFO'
    }, '🔒', 'PRIVACY')
};

// ============================================================================
// FRAUD DETECTION (Simplified)
// ============================================================================

export class FraudDetectionSystem {
    constructor() { this.thresholds = { HIGH_VALUE: 1000, VELOCITY: 5 }; }

    async analyzeTransaction(t) {
        let score = 0, flags = [];
        console.log(chalk.cyan('🔍 [FRAUD]'), { id: t.id, amount: t.amount });

        const recent = await this.getRecentTransactions(t.userId, 600000);
        if (recent.length >= this.thresholds.VELOCITY) { score += 30; flags.push('HIGH_VELOCITY'); }
        if (t.amount > this.thresholds.HIGH_VALUE) { score += 20; flags.push('HIGH_VALUE'); }
        if (recent.filter(r => r.amount === t.amount).length > 0) { score += 25; flags.push('DUPLICATE'); }

        const ip = await this.checkIPReputation(t.ip);
        if (ip.isProxy || ip.isTor) { score += 40; flags.push('SUSPICIOUS_IP'); }

        const decision = score > 50 ? 'BLOCKED' : 'APPROVED';
        await auditLogger.logSecurityEvent({
            userId: t.userId, action: 'FRAUD_CHECK', resource: 'TRANSACTION', result: decision,
            ip: t.ip, severity: decision === 'BLOCKED' ? 'CRITICAL' : 'INFO',
            details: { transactionId: t.id, score, flags, review: score > 30 && score <= 50 }
        });

        console.log(decision === 'BLOCKED' ? chalk.red('🚫 BLOCKED') : chalk.green('✅ APPROVED'), { score });
        return { approved: score <= 50, riskScore: score, flags, requiresManualReview: score > 30 && score <= 50, decision };
    }

    async getRecentTransactions(userId, ms) {
        try { return await Transaction.find({ userId, createdAt: { $gte: new Date(Date.now() - ms) } }).sort({ createdAt: -1 }); }
        catch { return []; }
    }

    async checkIPReputation(ip) {
        const suspicious = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./];
        const isProxy = suspicious.some(p => p.test(ip));
        return { ip, isProxy, isTor: false, isVPN: false, riskScore: isProxy ? 20 : 0 };
    }
}

// ============================================================================
// TRANSACTION MONITOR (Simplified)
// ============================================================================

export const transactionMonitor = {
    async monitor(t) {
        console.log(chalk.cyan('📊 [MONITOR]'), { id: t.id, amount: t.amount });
        const history = await this.getUserTransactionHistory(t.userId);
        if (history.length > 0) {
            const avg = history.reduce((s, h) => s + h.amount, 0) / history.length;
            if (t.amount > avg * 3) {
                await this.flagForReview({
                    transactionId: t.id, reason: 'AMOUNT_DEVIATION', deviation: t.amount / avg,
                    userAverage: avg, currentAmount: t.amount
                });
                console.log(chalk.yellow('⚠️ Deviation'), { avg: avg.toFixed(2), current: t.amount });
            }
        }
    },

    async getUserTransactionHistory(userId) {
        try { return await Transaction.find({ userId, status: 'COMPLETED' }).sort({ createdAt: -1 }).limit(10); }
        catch { return []; }
    },

    async flagForReview(d) {
        console.log(chalk.yellow('🚩 [FLAGGED]'), d);
        try { await TransactionReview.create({ transactionId: d.transactionId, reason: d.reason, details: d, status: 'PENDING_REVIEW', flaggedAt: new Date() }); }
        catch (e) { console.error(chalk.red('❌'), e.message); }
    }
};

// ============================================================================
// RBAC (Simplified)
// ============================================================================

export const FINANCIAL_ROLES = {
    PAYMENT_PROCESSOR: ['process_payment', 'view_transaction'],
    FINANCIAL_REVIEWER: ['review_transaction', 'approve_refund', 'view_reports'],
    FINANCIAL_ADMIN: ['generate_report', 'reconcile_accounts', 'view_all_transactions'],
    SUPER_ADMIN: ['all_permissions']
};

export const checkFinancialPermission = async (user, action) => {
    const roles = user.financialRoles || [];
    if (roles.includes('SUPER_ADMIN')) {
        await auditLogger.logSecurityEvent({ userId: user.id, action: `CHECK_PERMISSION:${action}`, resource: 'FINANCIAL_SYSTEM', result: 'GRANTED', ip: user.ip || '127.0.0.1', severity: 'INFO', details: { role: 'SUPER_ADMIN' } });
        return true;
    }

    for (const role of roles) {
        if ((FINANCIAL_ROLES[role] || []).includes(action)) {
            await auditLogger.logSecurityEvent({ userId: user.id, action: `CHECK_PERMISSION:${action}`, resource: 'FINANCIAL_SYSTEM', result: 'GRANTED', ip: user.ip || '127.0.0.1', severity: 'INFO', details: { role } });
            return true;
        }
    }

    await auditLogger.logSecurityEvent({ userId: user.id, action: `CHECK_PERMISSION:${action}`, resource: 'FINANCIAL_SYSTEM', result: 'DENIED', ip: user.ip || '127.0.0.1', severity: 'MEDIUM', details: { roles } });
    return false;
};

// ============================================================================
// UTILITIES
// ============================================================================

export const maskEmail = (e) => {
    if (!e) return '';
    const [u, d] = e.split('@');
    return `${u[0]}***${u[u.length - 1]}@${d}`;
};

export const encryptSensitiveData = (data, key) => {
    const k = Buffer.from(key || process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'), 'hex');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', k.slice(0, 32), iv);
    let enc = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
    return { encrypted: enc, iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex'), algorithm: 'aes-256-gcm' };
};

export const decryptSensitiveData = (ed, key) => {
    const k = Buffer.from(key || process.env.ENCRYPTION_KEY || '', 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', k.slice(0, 32), Buffer.from(ed.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(ed.authTag, 'hex'));
    return decipher.update(ed.encrypted, 'hex', 'utf8') + decipher.final('utf8');
};

console.log(chalk.green('✅ SOC controls loaded'));
