import base64
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, abort
from .models import db, Post, User, Comment
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_required, login_user

bp = Blueprint('main', __name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'bmp', 'ico', 'tiff', 'psd', 'raw', 'heif', 'indd'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@bp.route('/user_register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing required fields'}), 400

        username = data['username']
        email = data['email']
        password = data['password']

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({'error': 'User already exists'}), 400
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 201

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
        if user.is_admin:
            role = "admin"
        if user.is_super_admin:
            role = "super_admin"

        return jsonify({
            'message': 'Login successful',
            'role': role,  # Return the user role
        }), 200

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

        # Validate input
        if not data or not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing required fields'}), 400

        username = data['username']
        email = data['email']
        password = data['password']

        # Check if the admin already exists
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({'error': 'Admin already exists'}), 400

        # Create the new admin
        hashed_password = generate_password_hash(password, method='sha256')
        new_admin = User(username=username, email=email, password=hashed_password, is_admin=True)

        db.session.add(new_admin)
        db.session.commit()

        return jsonify({'message': f'Admin {username} created successfully'}), 201

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500


@bp.route('/admin_dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)  # Restrict access to Admins and Super Admins
    return jsonify({'message': 'Welcome to the Admin Dashboard'}), 200


@bp.route('/super_admin_panel', methods=['GET'])
@login_required
def super_admin_panel():
    if not current_user.is_super_admin:
        abort(403)  # Restrict access to Super Admins only
    return jsonify({'message': 'Welcome to the Super Admin Panel'}), 200
