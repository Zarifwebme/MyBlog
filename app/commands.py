from flask import Flask
from werkzeug.security import generate_password_hash
from app.models import db, User

def register_commands(app: Flask):
    @app.cli.command('create_super_admin')
    def create_super_admin():
        """Command to create the initial Super Admin."""
        username = "Zarif"
        email = "baxtiyorovzarif@gmail.com"
        password = "zarif4864"

        if User.query.filter_by(email=email).first():
            print("Super Admin already exists.")
            return

        hashed_password = generate_password_hash(password, method='sha256')
        super_admin = User(
            username=username,
            email=email,
            password=hashed_password,
            is_admin=True,
            is_super_admin=True
        )

        db.session.add(super_admin)
        db.session.commit()
        print("Super Admin created successfully.")
