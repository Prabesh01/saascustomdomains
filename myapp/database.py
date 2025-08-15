from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from passlib.hash import pbkdf2_sha256


db = SQLAlchemy()


class User(db.Model):
    username = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password = pbkdf2_sha256.hash(password)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password)

class Upstream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), db.ForeignKey('user.username'), nullable=False)
    user = db.relationship('User', backref=db.backref('upstreams', lazy=True))
    domain = db.Column(db.String(100), nullable=False)
    secret = db.Column(db.String(50), nullable=False, unique=True)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    upstream = db.Column(db.String(100), db.ForeignKey('upstream.domain'), nullable=False)
    domain = db.Column(db.String(50), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
