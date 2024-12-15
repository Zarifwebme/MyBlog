import base64
import logging
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, abort
from .models import db, Post, User, Comment
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_required, login_user, logout_user
from flask_mail import Message
from .extensions import mail

bp = Blueprint('main', __name__)
logging.basicConfig(level=logging.ERROR)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'bmp', 'ico', 'tiff', 'psd', 'raw', 'heif', 'indd'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@bp.route('/admin_panel', methods=['GET'])
@login_required
def admin_panel():
    if not current_user.is_admin:
        return "Access Denied", 403
    return render_template('admin_panel.html')

@bp.route('/test')
def test():
    return render_template('test.html')

@bp.route('/register')
def regs():
    return render_template('register.html')

@bp.route('/user_register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or not data.get('username') or not data.get('email') or not data.get('password') or not data.get('confirm_password'):
            return jsonify({'error': 'Missing required fields'}), 400

        username = data['username']
        email = data['email']
        password = data['password']
        confirm_password = data['confirm_password']

        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({'error': 'User already exists'}), 400

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Send the welcome email
        msg = Message("Welcome to Our Platform!", sender="baxtiyorovzarif@gmail.com", recipients=[email])
        msg.body = f"Hi {username},\n\nThank you for registering on our platform! We are excited to have you on board.\n\nBest regards,\nYour Team"
        mail.send(msg)

        return jsonify({'message': 'User registered successfully'}), 201

    except KeyError as e:
        return jsonify({'error': f'Missing key: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': 'An error occurred while processing your request. Please try again.'}), 500

@bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing email or password'}), 400

        email = data['email']
        password = data['password']

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not check_password_hash(user.password, password):
            return jsonify({'error': 'Invalid email or password'}), 401

        login_user(user)

        role = "user"
        redirect_url = url_for('main.profile')
        if user.is_admin:
            role = "admin"
            redirect_url = url_for('main.admin_panel')
        if user.is_super_admin:
            role = "super_admin"
            redirect_url = url_for('main.admin_panel')

        return jsonify({
            'message': 'Login successful',
            'role': role,
            'redirect_url': redirect_url  # Return the redirect URL
        }), 200

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    try:
        logout_user()
        return jsonify({'message': 'Logout successful'}), 200
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@bp.route('/get_all_users', methods=['GET'])
@login_required
def get_all_users():
    try:
        # Ensure only admins or super admins can view all users
        if not current_user.is_admin and not current_user.is_super_admin:
            return jsonify({'error': 'Access denied. Only Admins and Super Admins can view all users.'}), 403

        # Fetch all users
        users = User.query.all()

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

@bp.route('/delete_user', methods=['DELETE'])
@login_required
def delete_user():
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
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@bp.route('/create_admin', methods=['POST'])
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


@bp.route('/get_admins', methods=['GET'])
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


@bp.route('/delete_admin', methods=['DELETE'])
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

@bp.route('/profile', methods=['GET'])
@login_required
def profile():
    return jsonify({'message': 'Welcome to your profile page'}), 200

@bp.route('/create_admin_form', methods=['GET'])
@login_required
def create_admin_form():
    if not current_user.is_super_admin:
        return "Access Denied. Only Super Admins can access this page.", 403
    return render_template('create_admin.html')

@bp.route('/all_users', methods=['GET'])
@login_required
def all_users():
    if not current_user.is_super_admin:
        return "Access Denied. Only Super Admins can access this page.", 403
    return render_template('users.html')


@bp.route('/password_recovery')
def password_recovery():
    return render_template('password_recovery.html')