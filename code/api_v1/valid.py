from jsonschema import validate, ValidationError, SchemaError

login_schema = {
    "type": "object",
    "properties": {
        "email": {
            "type": "string",
            "minLength": 4,
            "maxLength": 120
        },
        "password": {
            "type": "string",
            "minLength": 4,
            "maxLength": 60
        }
    },
    "required": ["email", "password"]
}

register_schema = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 30
        },
        "email": {
            "type": "string",
            "minLength": 4,
            "maxLength": 120
        },
        "password": {
            "type": "string",
            "minLength": 4,
            "maxLength": 60
        },
        "repassword": {
            "type": "string",
            "minLength": 4,
            "maxLength": 60
        },
        "authid": {
            "type": "string",
            "minLength": 4,
            "maxLength": 60
        }
    },
    "required": ["name", "email", "password", "repassword", "authid"]
}

logout_schema = {
    "type": "object",
    "properties": {
        "access_token": {
            "type": "string"
        },
        "refresh_token": {
            "type": "string"
        }
    },
    "required": ["access_token", "refresh_token"]
}


def valid_login(data):
    try:
        validate(data, login_schema)
    except ValidationError as e:
        return {'status': False, 'msg': 'ValidationError'}
    except SchemaError as e:
        return {'status': False, 'msg': 'SchemaError'}
    return {'status': True, 'data': data}


def valid_register(data):
    try:
        validate(data, register_schema)
    except ValidationError as e:
        return {'status': False, 'msg': 'ValidationError'}
    except SchemaError as e:
        return {'status': False, 'msg': 'SchemaError'}
    return {'status': True, 'data': data}


def valid_logout(data):
    try:
        validate(data, logout_schema)
    except ValidationError as e:
        return {'status': False, 'msg': 'ValidationError'}
    except SchemaError as e:
        return {'status': False, 'msg': 'SchemaError'}
    return {'status': True, 'data': data}
