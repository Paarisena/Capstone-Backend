/**
 * SECURITY FIX #4: Rate Limiting & Account Lockout (Optimized)
 */

import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';

// Helper for rate limit handler
const handler = (msg, retry) => (req, res) => {
    console.warn(`🚨 Rate limit: ${req.ip} on ${req.path}`);
    res.status(429).json({ success: false, message: msg, retryAfter: retry });
};

// Auth rate limiter (5 attempts/15min)
export const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    handler: handler('Too many login attempts. Try again in 15 minutes.', 900)
});

// Progressive delay for auth
export const authSpeedLimiter = slowDown({
    windowMs: 15 * 60 * 1000,
    delayAfter: 2,
    delayMs: () => 1000,
    maxDelayMs: 20000
});

// API limiter (100 requests/15min)
export const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false
});

// Password reset limiter (3 attempts/hour)
export const passwordResetLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    handler: handler('Too many password reset attempts. Try again in 1 hour.', 3600)
});

// Email limiter (5 emails/hour)
export const emailLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    handler: handler('Too many emails sent. Try again later.', 3600)
});

// Upload limiter (20 uploads/hour)
export const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20
});

// Review limiter (10 reviews/hour)
export const reviewLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10
});

// Account Lockout (optimized)
class AccountLockout {
    constructor() {
        this.attempts = new Map();
        this.max = 5;
        this.lockTime = 30 * 60 * 1000;
        this.resetTime = 15 * 60 * 1000;
        setInterval(() => this.cleanup(), 60 * 60 * 1000);
    }
    
    recordFailedAttempt(email, ip) {
        const now = Date.now();
        const key = email.toLowerCase();
        const record = this.attempts.get(key);
        
        if (!record || now - record.last > this.resetTime) {
            this.attempts.set(key, { count: 1, last: now, ips: [ip], locked: null });
        } else {
            record.count++;
            record.last = now;
            record.ips.push(ip);
            if (record.count >= this.max) {
                record.locked = now + this.lockTime;
                console.error(`🚨 Locked: ${email} (${this.max} attempts)`);
            }
        }
    }
    
    recordSuccessfulLogin(email) {
        this.attempts.delete(email.toLowerCase());
    }
    
    isLocked(email) {
        const record = this.attempts.get(email.toLowerCase());
        if (!record?.locked) return { locked: false };
        
        const now = Date.now();
        if (now < record.locked) {
            return { 
                locked: true, 
                remainingMinutes: Math.ceil((record.locked - now) / 60000),
                unlockAt: new Date(record.locked).toISOString()
            };
        }
        
        this.attempts.delete(email.toLowerCase());
        return { locked: false };
    }
    
    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        for (const [key, rec] of this.attempts) {
            if (rec.locked && rec.locked < now && now - rec.last > this.resetTime) {
                this.attempts.delete(key);
                cleaned++;
            }
        }
        if (cleaned) console.log(`🧹 Cleaned ${cleaned} lockout records`);
    }
    
    unlockAccount(email) {
        const key = email.toLowerCase();
        if (this.attempts.has(key)) {
            this.attempts.delete(key);
            console.log(`🔓 Unlocked: ${email}`);
            return true;
        }
        return false;
    }
    
    getLockedAccounts() {
        const now = Date.now();
        const locked = [];
        for (const [email, rec] of this.attempts) {
            if (rec.locked && rec.locked > now) {
                locked.push({
                    email,
                    attempts: rec.count,
                    lockedUntil: new Date(rec.locked).toISOString(),
                    remainingMinutes: Math.ceil((rec.locked - now) / 60000)
                });
            }
        }
        return locked;
    }
}

export const accountLockout = new AccountLockout();

// Lockout check middleware
export const checkAccountLockout = (req, res, next) => {
    const email = req.body?.email;
    if (!email) return next();
    
    const status = accountLockout.isLocked(email.toLowerCase().trim());
    if (status.locked) {
        console.warn(`🚨 Blocked: ${email}`);
        return res.status(423).json({
            success: false,
            message: `Account locked. Try again in ${status.remainingMinutes} minutes.`,
            lockedUntil: status.unlockAt,
            remainingMinutes: status.remainingMinutes
        });
    }
    next();
};
