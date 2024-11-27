// Security configuration
export const securityConfig = {
    // Password requirements
    PASSWORD_MIN_LENGTH: 8,
    PASSWORD_MAX_LENGTH: 128, // Prevent excessive long passwords
    PASSWORD_REQUIREMENTS: {
        minLength: 8,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecial: true,
        maxConsecutiveChars: 3, // Prevent 'aaaa' patterns
    },
    
    // Login attempt limits
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_TIME: 15 * 60 * 1000, // 15 minutes in milliseconds
    
    // Token configuration
    TOKEN_EXPIRY: '1h',
    
    // CSRF Token settings
    CSRF_HEADER: 'X-CSRF-Token',
    
    // Secure headers
    SECURE_HEADERS: {
        'Content-Security-Policy': "default-src 'self'; img-src 'self' https://upload.wikimedia.org; style-src 'self' 'unsafe-inline';",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }
};
