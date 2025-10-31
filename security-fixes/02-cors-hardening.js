/**
 * SECURITY FIX #2: CORS Configuration Hardening
 * 
 * Replace CORS configuration in server.js
 * Location: server.js (lines 54-69)
 */

import chalk from 'chalk';

// Allowed origins configuration
const allowedOrigins = [
    "http://localhost:5173",
    "https://www.avgallery.shop",
    "https://avgallery.shop"
];

// Dynamic origin validation function
const corsOriginValidator = (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    // But only in development mode
    if (!origin) {
        if (process.env.NODE_ENV === 'development') {
            console.log(chalk.yellow('⚠️  Request with no origin (allowed in development)'));
            return callback(null, true);
        } else {
            console.warn(chalk.red(`🚨 Blocked request with no origin in production`));
            return callback(new Error('Not allowed by CORS'));
        }
    }
    
    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
        console.log(chalk.green(`✅ CORS allowed for origin: ${origin}`));
        callback(null, true);
    } else {
        console.warn(chalk.red(`🚨 CORS blocked request from unauthorized origin: ${origin}`));
        callback(new Error('Not allowed by CORS'));
    }
};

// Secure CORS configuration
export const secureCorsOptions = {
    origin: corsOriginValidator,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'Accept',
        'Origin',
        'X-Requested-With',
        'Cache-Control'
    ],
    exposedHeaders: ['Set-Cookie'],
    credentials: true,
    maxAge: 86400, // 24 hours in seconds
    optionsSuccessStatus: 204,
    preflightContinue: false
};

// Additional security middleware for production
export const additionalCorsSecurityMiddleware = (req, res, next) => {
    const origin = req.headers.origin;
    
    // In production, be extra strict
    if (process.env.NODE_ENV === 'production') {
        // Block if origin exists but not in whitelist
        if (origin && !allowedOrigins.includes(origin)) {
            console.error(chalk.red(`🚨 Production: Blocked unauthorized origin: ${origin}`));
            return res.status(403).json({
                success: false,
                message: 'Access denied - Unauthorized origin'
            });
        }
        
        // Require Origin header for state-changing requests
        const stateChangingMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
        if (stateChangingMethods.includes(req.method) && !origin) {
            console.error(chalk.red(`🚨 Blocked ${req.method} request without Origin header`));
            return res.status(403).json({
                success: false,
                message: 'Access denied - Origin header required'
            });
        }
    }
    
    next();
};

// Helper function to add new allowed origin (for admins)
export const addAllowedOrigin = (newOrigin) => {
    if (!allowedOrigins.includes(newOrigin)) {
        allowedOrigins.push(newOrigin);
        console.log(chalk.green(`✅ Added new allowed origin: ${newOrigin}`));
    } else {
        console.log(chalk.yellow(`⚠️  Origin already exists: ${newOrigin}`));
    }
};


