from flask import Flask
from flask_cors import CORS
from flask_swagger_ui import get_swaggerui_blueprint
from config import Config
from .extensions import db, migrate, login_manager, mail
from .models import User
from .commands import create_super_admin

def create_app():
    app = Flask(__name__)
    CORS(app)
    app.debug = True

    # Load configurations from a separate Config class or environment variables
    app.config.from_object(Config)

    # Mail configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your SMTP server
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'baxtiyorovzarif@gmail.com'  # Replace with your email
    app.config['MAIL_PASSWORD'] = 'lrtoborfekauiypm'  # Replace with your email password
    app.config['MAIL_DEFAULT_SENDER'] = 'baxtiyorovzarif@gmail.com'

    # Initialize Flask extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    mail.init_app(app)

    # Swagger setup
    SWAGGER_URL = '/swagger'
    API_URL = '/static/swagger.yaml'
    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={'app_name': "Marketplace API Documentation"}
    )
    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

    # Load user for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register commands and routes
    from . import routes
    app.register_blueprint(routes.bp)

    # Create super admin on first app context
    with app.app_context():
        create_super_admin()
        db.create_all()

    return app
