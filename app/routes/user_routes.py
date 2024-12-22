import logging
from flask import Blueprint, jsonify, render_template
from flask_login import login_required, current_user

user_bp = Blueprint('user', __name__)
logging.basicConfig(level=logging.ERROR)
logging.basicConfig(level=logging.INFO)

@user_bp.route('/profile', methods=['GET'])
@login_required
def profile():
    return jsonify({'message': f'Welcome, {current_user.username} to your profile page.'}), 200

@user_bp.route('/test')
def test():
    return render_template('test.html')

@user_bp.route('/register')
def regs():
    return render_template('register.html')