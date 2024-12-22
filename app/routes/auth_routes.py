import logging
from flask import Blueprint, request, jsonify, render_template, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from flask_mail import Message
from app.models import User, db
from app.extensions import mail

auth_bp = Blueprint('auth', __name__)
logging.basicConfig(level=logging.ERROR)
logging.basicConfig(level=logging.INFO)

@auth_bp.route('/test')
def test():
    return render_template('test.html')

@auth_bp.route('/register')
def regs():
    return render_template('register.html')

@auth_bp.route('/user_register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or not all(key in data for key in ('username', 'email', 'password', 'confirm_password')):
            return jsonify({'error': 'Missing required fields'}), 400

        if data['password'] != data['confirm_password']:
            return jsonify({'error': 'Passwords do not match'}), 400

        if User.query.filter_by(username=data['username']).first() or User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'User already exists'}), 400

        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        new_user = User(username=data['username'], email=data['email'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        msg = Message(
            "Welcome to Our Platform!",
            sender="baxtiyorovzarif@gmail.com",
            recipients=[data['email']]
        )
        msg.body = f"Hi {data['username']},\n\nWelcome to our platform!\n\nBest regards,\nYour Team"
        mail.send(msg)

        return jsonify({'message': 'User registered successfully'}), 201

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or not all(key in data for key in ('email', 'password')):
            return jsonify({'error': 'Missing required fields'}), 400

        user = User.query.filter_by(email=data['email']).first()
        if user and check_password_hash(user.password, data['password']):
            login_user(user)
            redirect_url = url_for('user.profile') if not user.is_admin else url_for('admin.admin_panel')
            return jsonify({'redirect': redirect_url}), 200
        return jsonify({'error': 'Invalid email or password'}), 401
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

@auth_bp.route('/password_recovery')
def password_recovery():
    return render_template('password_recovery.html')
