document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('create-admin-form');
    const messageBox = document.getElementById('message-box');
    const adminTableBody = document.querySelector('#admin-table tbody');

    // Fetch admins and display them
    const fetchAdmins = async () => {
        try {
            const response = await fetch('/get_admins');
            const admins = await response.json();

            // Clear the table
            adminTableBody.innerHTML = '';

            admins.forEach(admin => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${admin.username}</td>
                    <td>${admin.email}</td>
                    <td>
                        <button class="btn btn-danger btn-sm delete-btn" data-username="${admin.username}">Delete</button>
                    </td>
                `;
                adminTableBody.appendChild(row);
            });

            // Attach delete event listeners
            const deleteButtons = document.querySelectorAll('.delete-btn');
            deleteButtons.forEach(button => {
                button.addEventListener('click', () => {
                    deleteAdmin(button.getAttribute('data-username'));
                });
            });
        } catch (error) {
            console.error('Failed to fetch admins:', error);
        }
    };

    // Create admin
    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value.trim();

        try {
            const response = await fetch('/create_admin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password })
            });

            const result = await response.json();
            if (response.ok) {
                messageBox.className = 'success';
                messageBox.textContent = result.message;
                fetchAdmins();
            } else {
                messageBox.className = 'error';
                messageBox.textContent = result.error;
            }
            messageBox.style.display = 'block';
        } catch (error) {
            messageBox.className = 'error';
            messageBox.textContent = `Unexpected error: ${error.message}`;
            messageBox.style.display = 'block';
        }
    });

    // Delete admin
    const deleteAdmin = async (username) => {
        try {
            const response = await fetch('/delete_admin', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username })
            });

            const result = await response.json();
            if (response.ok) {
                alert(result.message);
                fetchAdmins();
            } else {
                alert(result.error);
            }
        } catch (error) {
            alert(`Unexpected error: ${error.message}`);
        }
    };

    // Initial load
    fetchAdmins();
});
