document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('create-admin-form');
    const messageBox = document.getElementById('message-box');
    const adminTableBody = document.querySelector('#admin-table tbody');

    // Fetch admins and display them
    const fetchAdmins = async () => {
        try {
            const response = await fetch('/admin/get_admins');
            if (!response.ok) throw new Error('Failed to fetch admins.');
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
            console.error('Error:', error);
        }
    };

    // Create admin
    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value.trim();

        try {
            const response = await fetch('/admin/create_admin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password })
            });

            const result = await response.json();
            messageBox.style.display = 'block';
            if (response.ok) {
                messageBox.className = 'alert alert-success';
                messageBox.textContent = result.message;
                fetchAdmins();
            } else {
                messageBox.className = 'alert alert-danger';
                messageBox.textContent = result.error;
            }
        } catch (error) {
            messageBox.className = 'alert alert-danger';
            messageBox.textContent = `Unexpected error: ${error.message}`;
        }
    });

    // Delete admin
    const deleteAdmin = async (username) => {
        try {
            const response = await fetch('/admin/delete_user_only_super_admin', {
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
