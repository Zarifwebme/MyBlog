import base64
import logging
from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from app.models import User, db

admin_bp = Blueprint('admin', __name__)
logging.basicConfig(level=logging.ERROR)
logging.basicConfig(level=logging.INFO)

@admin_bp.route('/admin_panel', methods=['GET'])
@login_required
def admin_panel():
    try:
        if not current_user.is_admin:
            return "Access Denied", 403
        return render_template('admin_panel.html')
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500
    
@admin_bp.route('/create_admin_form', methods=['GET'])
@login_required
def create_admin_form():
    try:
        if not current_user.is_super_admin:
            return "Access Denied. Only Super Admins can access this page.", 403
        return render_template('create_admin.html')
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500

@admin_bp.route('/all_users', methods=['GET'])
@login_required
def all_users():
    try:
        if not current_user.is_super_admin:
            return "Access Denied. Only Super Admins can access this page.", 403
        return render_template('users.html')
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500


@admin_bp.route('/create_admin', methods=['POST'])
@login_required
def create_admin():
    try:
        # Check if the logged-in user is a super admin
        if not current_user.is_super_admin:
            return jsonify({'error': 'Access denied. Only Super Admins can create Admin accounts.'}), 403

        data = request.get_json()

        if not data or not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing required fields'}), 400

        username = data['username']
        email = data['email']
        password = data['password']

        # Check if the admin already exists
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({'error': 'Admin already exists'}), 400

        # Create the new admin
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_admin = User(username=username, email=email, password=hashed_password, is_admin=True)

        db.session.add(new_admin)
        db.session.commit()

        return jsonify({'message': f'Admin {username} created successfully'}), 201

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@admin_bp.route('/delete_admin', methods=['DELETE'])
@login_required
def delete_admin():
    try:
        # Check if the logged-in user is a super admin
        if not current_user.is_super_admin:
            return jsonify({'error': 'Access denied. Only Super Admins can delete Admin accounts.'}), 403

        data = request.get_json()

        if not data or not data.get('username'):
            return jsonify({'error': 'Missing required fields'}), 400

        username = data['username']

        # Find the admin by username
        admin = User.query.filter_by(username=username, is_admin=True).first()
        if not admin:
            return jsonify({'error': 'Admin not found'}), 404

        # Delete the admin
        db.session.delete(admin)
        db.session.commit()

        return jsonify({'message': f'Admin {username} deleted successfully'}), 200

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@admin_bp.route('/get_admins', methods=['GET'])
@login_required
def get_admins():
    try:
        # Ensure only Super Admins can view admin accounts
        if not current_user.is_super_admin:
            return jsonify({'error': 'Access denied. Only Super Admins can view Admin accounts.'}), 403

        # Fetch all admins where `is_admin=True` and `is_super_admin=False`
        admins = User.query.filter_by(is_admin=True, is_super_admin=False).all()

        # Serialize the list of admins
        admin_list = [
            {
                'username': admin.username,
                'email': admin.email
            } for admin in admins
        ]

        return jsonify(admin_list), 200

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@admin_bp.route('/api/admin_profile', methods=['GET'])
@login_required
def admin_profile_api():
    try:
        if not current_user.is_admin and not current_user.is_super_admin:
            return jsonify({'error': 'Access Denied. Only Admins and Super Admins can access this page.'}), 403

        user_data = {
            'username': current_user.username,
            'email': current_user.email,
            'is_admin': current_user.is_admin,
            'is_super_admin': current_user.is_super_admin,
            'picture': base64.b64encode(current_user.picture).decode('utf-8') if current_user.picture else None,
            'mimetype': current_user.mimetype
        }
        return jsonify(user_data), 200
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@admin_bp.route('/admin_profile', methods=['GET'])
@login_required
def admin_profile_page():
    try:
        if not current_user.is_admin and not current_user.is_super_admin:
            return "Access Denied. Only Admins and Super Admins can access this page.", 403

        return render_template('admin_profile.html'), 200
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500

@admin_bp.route('/api/admin_profile/edit', methods=['POST'])
@login_required
def edit_admin_profile():
    try:
        if not (current_user.is_admin or current_user.is_super_admin):
            return jsonify({'success': False, 'message': 'Access denied.'}), 403

        data = request.form

        # Update text fields
        if 'username' in data:
            current_user.username = data['username']
        if 'email' in data:
            current_user.email = data['email']
        if 'password' in data and data['password']:
            current_user.password = generate_password_hash(data['password'])  # Hash the new password

        # Handle profile picture
        if 'picture' in request.files:
            picture = request.files['picture']
            if picture.filename != '':
                current_user.picture = picture.read()
                current_user.mimetype = picture.mimetype

        db.session.commit()
        return jsonify({'success': True, 'message': 'Profile updated successfully.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred: {str(e)}'}), 500

@admin_bp.route('/get_all_users_for_admin_panel', methods=['GET'])
@login_required
def get_all_users_for_admin_panel():
    try:
        # Ensure only admins or super admins can view all users
        if not current_user.is_admin and not current_user.is_super_admin:
            return jsonify({'error': 'Access denied. Only Admins and Super Admins can view all users.'}), 403

        # Fetch all users
        users = User.query.filter_by(is_admin=False, is_super_admin=False).all()

        # Serialize the list of users
        user_list = [
            {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_super_admin': user.is_super_admin
            } for user in users
        ]

        return jsonify(user_list), 200

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@admin_bp.route('/delete_user_only_super_admin', methods=['DELETE'])
@login_required
def delete_user_only_super_admin():
    try:
        data = request.get_json()

        if not data or not data.get('id'):
            return jsonify({'error': 'Missing required fields'}), 400

        user_id = data['id']

        # Ensure only admins or super admins can delete users
        if not current_user.is_admin and not current_user.is_super_admin:
            return jsonify({'error': 'Access denied. Only Admins and Super Admins can delete users.'}), 403

        # Find the user by ID
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Delete the user
        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': 'User deleted successfully'}), 200

    except Exception as e:
        # Log the error for debugging
        admin_bp.logger.error(f"Error deleting user: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500