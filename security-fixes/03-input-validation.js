/**
 * SECURITY FIX #3: Optimized Input Validation (Minimal Code)
 */

import validator from 'validator';
import mongoose from 'mongoose';

// Cached regex patterns
const R = {
    upper: /[A-Z]/,
    lower: /[a-z]/,
    num: /\d/,
    special: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/,
    name: /^[a-zA-Z\s'-]+$/
};

// Validation limits
const L = { pwd: [8, 128], name: [2, 100], qty: [0, 99] };

// Email validation
export const validateEmail = (email) => {
    if (!email || typeof email !== 'string') return { valid: false, error: 'Email is required' };
    const sanitized = email.trim().toLowerCase();
    return validator.isEmail(sanitized) 
        ? { valid: true, sanitized } 
        : { valid: false, error: 'Invalid email format' };
};

// Password validation
export const validatePassword = (pwd) => {
    if (!pwd || typeof pwd !== 'string') return { valid: false, error: 'Password is required' };
    const len = pwd.length;
    if (len < L.pwd[0]) return { valid: false, error: `Password must be ${L.pwd[0]}+ characters` };
    if (len > L.pwd[1]) return { valid: false, error: `Password max ${L.pwd[1]} characters` };
    
    if (!R.upper.test(pwd) || !R.lower.test(pwd) || !R.num.test(pwd) || !R.special.test(pwd)) {
        return { valid: false, error: 'Password needs uppercase, lowercase, number & special char' };
    }
    return { valid: true };
};

// Name validation
export const validateName = (name) => {
    if (!name || typeof name !== 'string') return { valid: false, error: 'Name is required' };
    const trimmed = name.trim();
    const len = trimmed.length;
    if (len < L.name[0]) return { valid: false, error: `Name must be ${L.name[0]}+ characters` };
    if (len > L.name[1]) return { valid: false, error: `Name max ${L.name[1]} characters` };
    
    const sanitized = validator.escape(trimmed);
    return R.name.test(sanitized) 
        ? { valid: true, sanitized } 
        : { valid: false, error: 'Name contains invalid characters' };
};

// ObjectId validation
export const validateObjectId = (id, field = 'ID') => 
    !id ? { valid: false, error: `${field} is required` } :
    mongoose.Types.ObjectId.isValid(id) ? { valid: true } :
    { valid: false, error: `Invalid ${field} format` };

// Quantity validation
export const validateQuantity = (qty) => {
    if (qty == null) return { valid: false, error: 'Quantity is required' };
    const num = +qty;
    if (!Number.isInteger(num)) return { valid: false, error: 'Quantity must be integer' };
    if (num < L.qty[0] || num > L.qty[1]) return { valid: false, error: `Quantity: ${L.qty[0]}-${L.qty[1]}` };
    return { valid: true, sanitized: num };
};

// Sanitize input
export const sanitizeInput = (input) => 
    (!input || typeof input !== 'string') ? input : validator.escape(input.trim());

// Login validation
export const validateLoginInput = ({ email, password }) => {
    const errors = [];
    const emailResult = validateEmail(email);
    if (!emailResult.valid) errors.push(emailResult.error);
    if (!password || !password.length) errors.push('Password is required');
    return { isValid: !errors.length, errors, sanitizedEmail: emailResult.sanitized };
};

// Registration validation
export const validateRegistrationInput = ({ name, email, password, confirmpassword }) => {
    const errors = [];
    const nameResult = validateName(name);
    const emailResult = validateEmail(email);
    const pwdResult = validatePassword(password);
    
    if (!nameResult.valid) errors.push(nameResult.error);
    if (!emailResult.valid) errors.push(emailResult.error);
    if (!pwdResult.valid) errors.push(pwdResult.error);
    if (password !== confirmpassword) errors.push('Passwords do not match');
    
    return {
        isValid: !errors.length,
        errors,
        sanitizedName: nameResult.sanitized,
        sanitizedEmail: emailResult.sanitized
    };
};
