import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'my_secret_key_zarif')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///myblog.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
