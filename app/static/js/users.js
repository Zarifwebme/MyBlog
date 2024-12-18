document.addEventListener('DOMContentLoaded', function() {
    loadUsers();
});

function loadUsers() {
    fetch('/get_all_users')
        .then(response => response.json())
        .then(data => {
            const usersTable = document.getElementById('usersTable').getElementsByTagName('tbody')[0];
            usersTable.innerHTML = '';
            data.forEach(user => {
                const row = usersTable.insertRow();
                row.innerHTML = `
                    <td>${user.id}</td>
                    <td>${user.username}</td>
                    <td>${user.email}</td>
                    <td>${user.is_admin}</td>
                    <td>${user.is_super_admin}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="deleteUser(${user.id})">Delete</button>
                    </td>
                `;
            });
        })
        .catch(error => console.error('Error loading users:', error));
}

function deleteUser(userId) {
        if (confirm('Are you sure you want to delete this user?')) {
            fetch(`/delete_user`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ id: userId })
            })
            .then(response => response.json())
            .then(data => {
                if (response.ok) {
                    alert(data.message || 'User deleted successfully');
                    loadUsers();
                } else {
                    alert(data.error || 'Failed to delete user.');
                }
            })
            .catch(error => console.error('Error deleting user:', error));
        }
    }