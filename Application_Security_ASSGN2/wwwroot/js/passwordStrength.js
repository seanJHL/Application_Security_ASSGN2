/**
 * Password Strength Checker
 * Provides real-time feedback on password strength
 * Modern Apple-inspired design
 */

(function () {
    'use strict';

    // Password requirements
    const requirements = {
        length: {
            regex: /.{12,}/,
            element: 'req-length',
            message: 'At least 12 characters'
        },
        lowercase: {
            regex: /[a-z]/,
            element: 'req-lower',
            message: 'One lowercase letter'
        },
        uppercase: {
            regex: /[A-Z]/,
            element: 'req-upper',
            message: 'One uppercase letter'
        },
        number: {
            regex: /[0-9]/,
            element: 'req-number',
            message: 'One number'
        },
        special: {
            regex: /[!@#$%^&*(),.?":{}|<>]/,
            element: 'req-special',
            message: 'One special character'
        }
    };

    // Initialize password strength checker
    function init() {
        const passwordInput = document.getElementById('password');
        if (!passwordInput) return;

        const strengthContainer = document.getElementById('passwordStrength');
        const strengthBar = document.getElementById('strengthBar');
        const strengthText = document.getElementById('strengthText');

        // Show strength indicator on focus
        passwordInput.addEventListener('focus', function () {
            if (strengthContainer) {
                strengthContainer.style.display = 'block';
            }
        });

        // Check password strength on input
        passwordInput.addEventListener('input', function () {
            const password = this.value;
            const result = checkPasswordStrength(password);
            
            updateUI(result, strengthBar, strengthText);
            updateRequirements(result.checks);
        });
    }

    // Check password against all requirements
    function checkPasswordStrength(password) {
        const checks = {};
        let score = 0;

        for (const [key, req] of Object.entries(requirements)) {
            const passed = req.regex.test(password);
            checks[key] = passed;
            if (passed) score++;
        }

        // Calculate strength level
        let strength, color, percentage;
        if (score === 0) {
            strength = '';
            color = '';
            percentage = 0;
        } else if (score < 3) {
            strength = 'Weak';
            color = '#ff3b30';
            percentage = 25;
        } else if (score < 4) {
            strength = 'Fair';
            color = '#ff9500';
            percentage = 50;
        } else if (score < 5) {
            strength = 'Good';
            color = '#34c759';
            percentage = 75;
        } else {
            strength = 'Strong';
            color = '#30d158';
            percentage = 100;
        }

        return { score, checks, strength, color, percentage };
    }

    // Update the strength bar and text
    function updateUI(result, strengthBar, strengthText) {
        if (!strengthBar || !strengthText) return;

        // Update bar
        strengthBar.style.width = result.percentage + '%';
        strengthBar.style.backgroundColor = result.color || '#e5e5e7';

        // Update text
        if (result.strength) {
            strengthText.textContent = 'Password strength: ' + result.strength;
            strengthText.style.color = result.color;
        } else {
            strengthText.textContent = '';
        }
    }

    // Update individual requirement indicators
    function updateRequirements(checks) {
        for (const [key, req] of Object.entries(requirements)) {
            const element = document.getElementById(req.element);
            if (!element) continue;

            const passed = checks[key];
            
            // Update icon and styling
            const icon = passed 
                ? '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="#34c759" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>'
                : '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="#86868b" viewBox="0 0 16 16"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/></svg>';
            
            element.innerHTML = icon + ' ' + req.message;
            element.className = passed ? 'text-success' : '';
            element.style.color = passed ? '#34c759' : '#86868b';
        }
    }

    // Expose for external use
    window.PasswordStrength = {
        check: checkPasswordStrength,
        init: init
    };

    // Auto-initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
