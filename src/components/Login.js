import React, { useState, useEffect } from 'react';
import './Login.css';
import { validatePassword, sanitizeInput, checkLoginAttempts, recordLoginAttempt, generateCSRFToken, hashData } from '../utils/security';

const Login = () => {
    const [formData, setFormData] = useState({
        email: '',
        password: ''
    });
    const [showPassword, setShowPassword] = useState(false);
    const [passwordStrength, setPasswordStrength] = useState({
        score: 0,
        message: '',
        errors: []
    });
    const [csrfToken, setCsrfToken] = useState('');
    const [loginStatus, setLoginStatus] = useState({
        attempts: 5,
        locked: false,
        message: ''
    });

    useEffect(() => {
        // Generate CSRF token on component mount
        setCsrfToken(generateCSRFToken());
    }, []);

    const handleChange = async (e) => {
        const { name, value } = e.target;
        // Sanitize input
        const sanitizedValue = sanitizeInput(value);
        
        setFormData(prevState => ({
            ...prevState,
            [name]: sanitizedValue
        }));

        if (name === 'password') {
            const validation = validatePassword(sanitizedValue);
            const score = validation.errors.length === 0 ? 5 : 
                         validation.errors.length <= 1 ? 4 :
                         validation.errors.length <= 2 ? 3 :
                         validation.errors.length <= 3 ? 2 : 1;

            setPasswordStrength({
                score,
                message: score === 5 ? 'Very Strong' :
                         score === 4 ? 'Strong' :
                         score === 3 ? 'Medium' :
                         'Weak',
                errors: validation.errors
            });
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        
        // Check login attempts
        const userId = formData.email; // Using email as userId for demonstration
        const attemptCheck = checkLoginAttempts(userId);
        
        if (!attemptCheck.allowed) {
            setLoginStatus({
                attempts: 0,
                locked: true,
                message: attemptCheck.message
            });
            return;
        }

        // Validate input
        if (!formData.email || !formData.password) {
            setLoginStatus({
                ...loginStatus,
                message: 'Please fill in all fields'
            });
            return;
        }

        // Validate password strength
        const validation = validatePassword(formData.password);
        if (!validation.isValid) {
            setLoginStatus({
                ...loginStatus,
                message: validation.errors[0]
            });
            recordLoginAttempt(userId, false);
            return;
        }

        try {
            // Hash password before sending
            const hashedPassword = await hashData(formData.password);
            
            // Here you would typically make an API call with:
            // - Hashed password
            // - CSRF token in header
            // - Rate limiting headers
            console.log('Login attempt with:', {
                email: formData.email,
                hashedPassword,
                csrfToken
            });

            // Simulate successful login
            recordLoginAttempt(userId, true);
            setLoginStatus({
                attempts: 5,
                locked: false,
                message: 'Login successful!'
            });
        } catch (error) {
            recordLoginAttempt(userId, false);
            setLoginStatus({
                attempts: attemptCheck.remainingAttempts - 1,
                locked: false,
                message: 'Login failed. Please try again.'
            });
        }
    };

    const togglePasswordVisibility = () => {
        setShowPassword(!showPassword);
    };

    return (
        <div className="login-container">
            <div className="login-box">
                <h1>Welcome Back</h1>
                <p className="subtitle">Please enter your details</p>
                
                {loginStatus.message && (
                    <div className={`status-message ${loginStatus.locked ? 'error' : ''}`}>
                        {loginStatus.message}
                    </div>
                )}
                
                <form onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label htmlFor="email">Email</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            value={formData.email}
                            onChange={handleChange}
                            placeholder="Enter your email"
                            required
                            disabled={loginStatus.locked}
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="password">Password</label>
                        <div className="password-input-container">
                            <input
                                type={showPassword ? "text" : "password"}
                                id="password"
                                name="password"
                                value={formData.password}
                                onChange={handleChange}
                                placeholder="Enter your password"
                                required
                                disabled={loginStatus.locked}
                            />
                            <button 
                                type="button" 
                                className="toggle-password"
                                onClick={togglePasswordVisibility}
                                disabled={loginStatus.locked}
                            >
                                {showPassword ? "Hide" : "Show"}
                            </button>
                        </div>
                        {formData.password && (
                            <div className="password-feedback">
                                <div className="strength-meter">
                                    {[...Array(5)].map((_, index) => (
                                        <div 
                                            key={index} 
                                            className={`strength-bar ${
                                                index < passwordStrength.score ? 
                                                `strength-${passwordStrength.message.toLowerCase()}` : ''
                                            }`}
                                        />
                                    ))}
                                </div>
                                <span className={`strength-text strength-${passwordStrength.message.toLowerCase()}`}>
                                    {passwordStrength.message}
                                </span>
                                {passwordStrength.errors.length > 0 && (
                                    <ul className="password-errors">
                                        {passwordStrength.errors.map((error, index) => (
                                            <li key={index}>{error}</li>
                                        ))}
                                    </ul>
                                )}
                            </div>
                        )}
                    </div>

                    <div className="form-options">
                        <label className="remember-me">
                            <input 
                                type="checkbox" 
                                disabled={loginStatus.locked}
                            /> Remember me
                        </label>
                        <a href="#forgot" className="forgot-password">Forgot password?</a>
                    </div>

                    <button 
                        type="submit" 
                        className="login-button"
                        disabled={loginStatus.locked}
                    >
                        Sign in
                    </button>

                    <button 
                        type="button" 
                        className="google-button"
                        disabled={loginStatus.locked}
                    >
                        <img src="https://upload.wikimedia.org/wikipedia/commons/5/53/Google_%22G%22_Logo.svg" alt="Google" />
                        Sign in with Google
                    </button>
                </form>

                <p className="signup-link">
                    Don't have an account? <a href="#signup">Sign up</a>
                </p>
            </div>
        </div>
    );
};

export default Login;
