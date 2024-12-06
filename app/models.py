from .extensions import db
from flask_login import UserMixin
from datetime import datetime


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    snippet = db.Column(db.String(200), nullable=False)
    classification = db.Column(db.String(1000), nullable=False)
    picture = db.Column(db.LargeBinary, nullable=True)
    mimetype = db.Column(db.String(50), nullable=True)
    tag = db.Column(db.String(50), nullable=True)
    data_created = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)
    source = db.Column(db.String(300), nullable=True)
    comments = db.relationship('Comment', backref='post', lazy=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Admin yoki oddiy foydalanuvchi
    is_super_admin = db.Column(db.Boolean, default=False)  # True for super admin
    comments = db.relationship('Comment', backref='author', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)