from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
jwt = JWTManager()
crypt = Bcrypt()


class User(db.Model):
    __tablename__ = "otp_user"
    __table_args__ = {'mysql_collate': 'utf8_general_ci'}

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)


class Permission(db.Model):
    __tablename__ = "otp_permission"
    __table_args__ = {'mysql_collate': 'utf8_general_ci'}

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('otp_user.id'))
    otp_id = db.Column(db.Integer, db.ForeignKey('otp_list.id'))

    user = db.relationship('User', backref="otp_permission")
    otp = db.relationship('OtpList', backref="otp_permission")


class OtpList(db.Model):
    __tablename__ = "otp_list"
    __table_args__ = {'mysql_collate': 'utf8_general_ci'}

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    comment = db.Column(db.String(64), nullable=False)
    secret = db.Column(db.String(64), nullable=False)
    authid = db.Column(db.String(64), nullable=False)
