document.addEventListener('DOMContentLoaded', () => {
    // Simulate fetching data for dashboard metrics
    const dashboardData = {
        totalUsers: 1200,
        newComments: 45,
        totalPosts: 150,
        totalAdmins: 8
    };

    // Update the metrics dynamically
    document.getElementById('total-users').textContent = dashboardData.totalUsers;
    document.getElementById('new-comments').textContent = dashboardData.newComments;
    document.getElementById('total-posts').textContent = dashboardData.totalPosts;
    document.getElementById('total-admins').textContent = dashboardData.totalAdmins;
});
