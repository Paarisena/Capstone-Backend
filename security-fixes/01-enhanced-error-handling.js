/**
 * SECURITY FIX #1: Enhanced Error Handling
 * 
 * Replace the error handler in server.js with this secure version
 * Location: server.js (lines 183-201)
 */

import chalk from 'chalk';

// Secure error handling middleware
export const secureErrorHandler = (err, req, res, next) => {
    // Log detailed error server-side for debugging
    console.error(chalk.red('🚨 Error occurred:'));
    console.error(chalk.red('Timestamp:', new Date().toISOString()));
    console.error(chalk.red('Error name:', err.name));
    console.error(chalk.red('Error message:', err.message));
    console.error(chalk.red('Error stack:', err.stack));
    console.error(chalk.red('Request path:', req.path));
    console.error(chalk.red('Request method:', req.method));
    console.error(chalk.red('IP Address:', req.ip));
    console.error(chalk.red('User Agent:', req.get('user-agent')));
    
    // Determine environment
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    // Generic error messages for production
    const errorMessages = {
        400: 'Bad Request - Invalid input provided',
        401: 'Unauthorized - Authentication required',
        403: 'Forbidden - Access denied',
        404: 'Not Found - Resource does not exist',
        429: 'Too Many Requests - Please try again later',
        500: 'Internal Server Error - Something went wrong'
    };
    
    // Determine status code
    const statusCode = err.status || err.statusCode || 500;
    
    // Build response
    const response = {
        success: false,
        message: isDevelopment 
            ? err.message 
            : errorMessages[statusCode] || 'An error occurred',
        timestamp: new Date().toISOString(),
        path: req.path
    };
    
    // Only include error details in development
    if (isDevelopment) {
        response.error = {
            name: err.name,
            message: err.message,
            stack: err.stack
        };
    } else {
        // In production, log to monitoring service
        // Example: Sentry, LogRocket, etc.
        // logToMonitoringService(err, req);
    }
    
    res.status(statusCode).json(response);
};

// 404 handler
export const notFoundHandler = (req, res) => {
    console.warn(chalk.yellow(`⚠️  404 Not Found: ${req.method} ${req.path}`));
    
    res.status(404).json({
        success: false,
        message: 'Route not found',
        path: req.path,
        method: req.method
    });
};

export const sanitizeInput = (input) => {
    if (typeof input === 'string') {
        return input.replace(/[\$\.]/g, '');
    }
    return input;
};