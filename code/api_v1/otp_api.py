from flask import Blueprint, request, jsonify
from flask_jwt_extended import *
from pyotp import TOTP

from models import User, OtpList, Permission, db, crypt, jwt
from .valid import valid_login, valid_register

api = Blueprint('api', __name__)


@jwt.expired_token_loader
def expired_token_callback(expired_token):
    return jsonify({'status': 401, 'msg': 'This Token has expired'}), 401


@jwt.invalid_token_loader
def invalid_token_callback(invalid_token):
    return jsonify({'status': 422, 'msg': 'This Token is invalid'}), 422


@jwt.revoked_token_loader
def revoked_token_callback(revoked_token):
    return jsonify({'status': 401, 'msg': 'This Token has been revoked'}), 401


@jwt.unauthorized_loader
def unauthorized_callback(unauthorized_call):
    return jsonify({'status': 401, 'msg': 'This Endpoint required jwt token'}), 401


@api.route('/login', methods=['POST'])
def login():
    data = valid_login(request.get_json())

    if data['status']:
        data = data['data']
        user = User.query.filter(User.email == data['email']).first()

        if user and crypt.check_password_hash(user.password, data['password']):
            del data['password']
            access_token = create_access_token(identity=data)
            refresh_token = create_refresh_token(identity=data)

            data['access_token'] = access_token
            data['refresh_token'] = refresh_token

            return jsonify({'status': 'ok', 'data': data}), 200

        else:
            return jsonify({'status': 401, 'msg': 'Invalid email or password'}), 401

    else:
        return jsonify({'status': 400, 'msg': data['msg']}), 400


@api.route('/register', methods=['POST'])
def register():
    data = valid_register(request.get_json())

    if data['status']:
        data = data['data']
        if data['password'] != data['repassword']:
            return jsonify({'status': 400, 'msg': 'Password Not Match'}), 400

        if User.query.filter(User.email == data['email']).first():
            return jsonify({'status': 403, 'msg': 'Email Already Used'}), 403

        otp_list = OtpList.query.filter(OtpList.authid == data['authid']).all()

        if not otp_list:
            return jsonify({'status': 403, 'msg': 'Invalid AuthID'})

        user = User()
        user.name = data['name']
        user.email = data['email']
        user.password = crypt.generate_password_hash(data['password'])
        db.session.add(user)
        db.session.commit()

        for each_otp in otp_list:
            permission = Permission()
            permission.user_id = user.id
            permission.otp_id = each_otp.id
            db.session.add(permission)

        db.session.commit()

        return jsonify({'status': 'ok'}), 200

    else:
        return jsonify({'status': 400, 'msg': data['msg']}), 400


@api.route('/otp', methods=['GET'])
@jwt_required
def otp():
    identity = get_jwt_identity()
    user = User.query.filter(User.email == identity['email']).first()
    permission_list = Permission.query.filter(Permission.user_id == user.id).all()
    result = {'otp_list': [], 'otp_num': []}

    for perm in permission_list:
        result['otp_num'].append(TOTP(perm.otp.secret).now())
        result['otp_comment'].append(perm.otp.comment)

    return jsonify({'status': 'ok', 'data': result})


@api.route('/refresh', methods=['GET'])
@jwt_refresh_token_required
def token_refresh():
    identity = get_jwt_identity()
    result = {'access_token': create_access_token(identity=identity)}
    return jsonify({'status': 'ok', 'data': result}), 200
