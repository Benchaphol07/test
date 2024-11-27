import { securityConfig } from '../config/security';

// Password validation
export const validatePassword = (password) => {
    const errors = [];
    
    // Check length
    if (password.length < securityConfig.PASSWORD_MIN_LENGTH) {
        errors.push(`Password must be at least ${securityConfig.PASSWORD_MIN_LENGTH} characters long`);
    }
    if (password.length > securityConfig.PASSWORD_MAX_LENGTH) {
        errors.push(`Password must not exceed ${securityConfig.PASSWORD_MAX_LENGTH} characters`);
    }

    // Check for required characters
    if (securityConfig.PASSWORD_REQUIREMENTS.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    if (securityConfig.PASSWORD_REQUIREMENTS.requireLowercase && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    if (securityConfig.PASSWORD_REQUIREMENTS.requireNumbers && !/\d/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    if (securityConfig.PASSWORD_REQUIREMENTS.requireSpecial && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }

    // Check for consecutive characters
    const consecutivePattern = new RegExp(`(.)\\1{${securityConfig.PASSWORD_REQUIREMENTS.maxConsecutiveChars},}`);
    if (consecutivePattern.test(password)) {
        errors.push(`Password must not contain more than ${securityConfig.PASSWORD_REQUIREMENTS.maxConsecutiveChars} consecutive identical characters`);
    }

    // Check for common passwords (you should expand this list)
    const commonPasswords = ['password123', 'admin123', '12345678', 'qwerty123'];
    if (commonPasswords.includes(password.toLowerCase())) {
        errors.push('This password is too common. Please choose a more unique password');
    }

    return {
        isValid: errors.length === 0,
        errors
    };
};

// Rate limiting for login attempts
const loginAttempts = new Map();

export const checkLoginAttempts = (userId) => {
    const attempts = loginAttempts.get(userId) || { count: 0, lastAttempt: 0 };
    const now = Date.now();

    // Reset attempts if lockout time has passed
    if (now - attempts.lastAttempt > securityConfig.LOCKOUT_TIME) {
        loginAttempts.set(userId, { count: 0, lastAttempt: now });
        return { allowed: true, remainingAttempts: securityConfig.MAX_LOGIN_ATTEMPTS };
    }

    // Check if user is locked out
    if (attempts.count >= securityConfig.MAX_LOGIN_ATTEMPTS) {
        const timeRemaining = securityConfig.LOCKOUT_TIME - (now - attempts.lastAttempt);
        return { 
            allowed: false, 
            timeRemaining,
            message: `Too many login attempts. Please try again in ${Math.ceil(timeRemaining / 60000)} minutes`
        };
    }

    return { 
        allowed: true, 
        remainingAttempts: securityConfig.MAX_LOGIN_ATTEMPTS - attempts.count 
    };
};

export const recordLoginAttempt = (userId, success) => {
    const attempts = loginAttempts.get(userId) || { count: 0, lastAttempt: 0 };
    
    if (success) {
        // Reset attempts on successful login
        loginAttempts.delete(userId);
    } else {
        // Increment attempts on failed login
        loginAttempts.set(userId, {
            count: attempts.count + 1,
            lastAttempt: Date.now()
        });
    }
};

// Sanitize user input
export const sanitizeInput = (input) => {
    if (typeof input !== 'string') return input;
    return input
        .replace(/[<>]/g, '') // Remove < and > to prevent HTML injection
        .trim(); // Remove leading/trailing whitespace
};

// Generate CSRF token
export const generateCSRFToken = () => {
    const buffer = new Uint8Array(32);
    crypto.getRandomValues(buffer);
    return Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join('');
};

// Hash sensitive data (for demonstration - in production use bcrypt or similar)
export const hashData = async (data) => {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    return Array.from(new Uint8Array(hashBuffer))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
};
