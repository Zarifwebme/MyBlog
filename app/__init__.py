from flask import Flask
from flask_cors import CORS
from flask_swagger_ui import get_swaggerui_blueprint
from config import Config
from .extensions import db, migrate, login_manager
from .models import User
from app.commands import register_commands
from .routes import create_super_admin


def create_app():
    app = Flask(__name__)
    CORS(app)
    app.debug = True
    app.config.from_object(Config)

    # Swagger setup
    SWAGGER_URL = '/swagger'  # URL for accessing Swagger UI
    API_URL = '/static/swagger.yaml'  # Static path to your YAML file

    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={'app_name': "Marketplace API Documentation"}
    )
    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

    db.init_app(app)
    migrate.init_app(app, db)
    register_commands(app)
    # Initialize LoginManager with the app
    login_manager.init_app(app)
    login_manager.login_view = 'main.account'  # Redirect unauthorized users to the login page

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from . import routes
    app.register_blueprint(routes.bp)

    with app.app_context():
        create_super_admin()
        db.create_all()


    return app