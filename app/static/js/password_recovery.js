document.getElementById('password-recovery-form').addEventListener('submit', async function (event) {
    event.preventDefault();
    const email = document.getElementById('email').value;

    try {
        const response = await fetch('/password_recovery', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email }),
        });

        const result = await response.json();
        document.getElementById('response-message').textContent = result.message || result.error;
    } catch (error) {
        document.getElementById('response-message').textContent = 'An error occurred.';
    }
});
