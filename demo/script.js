document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const otpInput = document.getElementById('otp-input');
    const backBtn = document.getElementById('back-btn');
    const resetBtn = document.getElementById('reset-btn');
    
    const loginCard = document.getElementById('login-card');
    const otpCard = document.getElementById('otp-card');
    const successCard = document.getElementById('success-card');
    const otpLoader = document.getElementById('otp-loader');
    
    // Switch between cards with animation
    function showCard(cardToShow) {
        [loginCard, otpCard, successCard].forEach(card => {
            if (card === cardToShow) {
                card.classList.remove('hidden');
            } else {
                card.classList.add('hidden');
            }
        });
    }

    // Step 1: Handle Login Submission
    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        // Mock validation delay
        const btn = loginForm.querySelector('button');
        const originalText = btn.textContent;
        btn.textContent = 'Verifying...';
        btn.disabled = true;

        setTimeout(() => {
            btn.textContent = originalText;
            btn.disabled = false;
            
            // Transition to OTP screen
            showCard(otpCard);
            
            // Critical for hardware key: Auto-focus the OTP input field
            // The ESP32 acts as a keyboard and needs focus to type the OTP
            setTimeout(() => {
                otpInput.focus();
            }, 500); // Wait for transition
        }, 800);
    });

    // Step 2: Handle OTP Input (Hardware Key Typing)
    // Hardware keys typically type the code and press 'Enter' automatically
    // or we can detect when 6 characters are typed.
    
    otpInput.addEventListener('input', (e) => {
        // Remove non-numeric characters just in case
        e.target.value = e.target.value.replace(/\D/g, '');
        
        // Auto-submit when 6 digits are reached
        if (e.target.value.length === 6) {
            verifyOTP();
        }
    });

    // Also handle 'Enter' key if the hardware key sends an Enter keystroke
    otpInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            if (otpInput.value.length === 6) {
                verifyOTP();
            }
        }
    });

    function verifyOTP() {
        otpInput.disabled = true;
        otpLoader.classList.remove('hidden');
        
        // Mock server verification delay
        setTimeout(() => {
            otpLoader.classList.add('hidden');
            showCard(successCard);
        }, 1500);
    }

    // Navigation Buttons
    backBtn.addEventListener('click', () => {
        otpInput.value = '';
        otpInput.disabled = false;
        showCard(loginCard);
    });

    resetBtn.addEventListener('click', () => {
        otpInput.value = '';
        otpInput.disabled = false;
        document.getElementById('password').value = '';
        showCard(loginCard);
    });
});
