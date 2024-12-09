document.getElementById('registrationForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    const messageDiv = document.getElementById('message');
    messageDiv.textContent = ''; // Clear any previous messages

    try {
        const response = await fetch('/user_register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password, confirm_password: confirmPassword })
        });

        const result = await response.json();

        if (response.ok) {
            messageDiv.className = 'text-success';
            messageDiv.textContent = 'Registration successful! Check your email for a welcome message.';
            document.getElementById('registrationForm').reset();
        } else {
            messageDiv.className = 'text-danger';
            messageDiv.textContent = result.error || 'An error occurred. Please try again.';
        }
    } catch (error) {
        messageDiv.className = 'text-danger';
        messageDiv.textContent = 'An unexpected error occurred.';
    }
});
