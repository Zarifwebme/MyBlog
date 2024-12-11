from werkzeug.security import generate_password_hash

from app import db, User
from app.routes import logger


def create_super_admin():
    try:
        # Define super admin credentials
        super_admin_username = 'Zarif_Baxtiyorov'
        super_admin_email = 'baxtiyorovzarif@gmail.com'
        super_admin_password = 'Jizzax20021210!'

        # Check if the super admin already exists
        if User.query.filter_by(username=super_admin_username).first() or User.query.filter_by(email=super_admin_email).first():
            logger.info('Super admin already exists.')
            return

        # Create the super admin
        hashed_password = generate_password_hash(super_admin_password, method='pbkdf2:sha256')
        super_admin = User(username=super_admin_username, email=super_admin_email, password=hashed_password, is_admin=True, is_super_admin=True)

        db.session.add(super_admin)
        db.session.commit()
        logger.info('Super admin created successfully.')

    except Exception as e:
        logger.error(f'Error creating super admin: {e}')