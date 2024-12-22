import os
import logging
from werkzeug.security import generate_password_hash
from app import db, User

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_super_admin():
    try:
        # Load super admin credentials from environment variables
        super_admin_username = os.getenv('SUPER_ADMIN_USERNAME', 'Zarif')
        super_admin_email = os.getenv('SUPER_ADMIN_EMAIL', 'baxtiyorovzarif@gmail.com')
        super_admin_password = os.getenv('SUPER_ADMIN_PASSWORD', '20021210')

        # Check if the super admin already exists
        if User.query.filter_by(username=super_admin_username).first() or User.query.filter_by(email=super_admin_email).first():
            logger.info('Super admin already exists.')
            return

        # Create the super admin
        hashed_password = generate_password_hash(super_admin_password, method='pbkdf2:sha256')
        super_admin = User(
            username=super_admin_username,
            email=super_admin_email,
            password=hashed_password,
            is_admin=True,
            is_super_admin=True
        )

        db.session.add(super_admin)
        db.session.commit()
        logger.info('Super admin created successfully.')

    except Exception as e:
        db.session.rollback()  # Rollback the transaction on error
        logger.error(f'Error creating super admin: {e}')
