from .admin_routes import admin_bp as admin_routes_bp
from .auth_routes import auth_bp
from .user_routes import user_bp

all_blueprints = [admin_routes_bp, auth_bp, user_bp]
