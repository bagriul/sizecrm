from flask import Flask, request, jsonify, Response
import jwt
import datetime
from pymongo import MongoClient
from bson import json_util
from flask_cors import CORS
import re
import config

application = Flask(__name__)
CORS(application)
application.config['SECRET_KEY'] = config.SECRET_KEY
SECRET_KEY = config.SECRET_KEY
client = MongoClient(config.MONGO_STRING)
db = client['size_crm']
users_collection = db['users']


@application.route('/', methods=['GET'])
def test():
    return 'SizeCRM API v1.0'


# Sample function to verify access token
def verify_access_token(access_token):
    try:
        decoded_token = jwt.decode(access_token, SECRET_KEY, algorithms=['HS256'])
        # If the token is successfully decoded, it is valid
        return True
    except jwt.ExpiredSignatureError:
        # Token has expired
        return False
    except jwt.InvalidTokenError:
        # Invalid token
        return False


# Sample function to verify refresh token
def verify_refresh_token(refresh_token):
    try:
        decoded_token = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
        # If the token is successfully decoded, it is valid
        return True
    except jwt.ExpiredSignatureError:
        # Token has expired
        return False
    except jwt.InvalidTokenError:
        # Invalid token
        return False


@application.route('/validate_tokens', methods=['POST'])
def validate_tokens():
    data = request.get_json()
    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')

    if not access_token and not refresh_token:
        response = jsonify({'message': 'Access token or refresh token is missing'}), 401
        return response

    access_token_valid = verify_access_token(access_token) if access_token else False
    refresh_token_valid = verify_refresh_token(refresh_token) if refresh_token else False

    if access_token_valid:
        response = jsonify({'message': 'Access token is valid', 'valid': True}), 200
    elif refresh_token_valid:
        response = jsonify({'message': 'Refresh token is valid', 'valid': True}), 200
    else:
        response = jsonify({'message': 'Access token or refresh token is invalid', 'valid': False}), 401

    return response


# Endpoint for user login
@application.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Check if the user exists in the database and the password matches
    user = users_collection.find_one({'email': email, 'password': password})

    if user:
        # Generate tokens
        access_token = jwt.encode(
            {'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            application.config['SECRET_KEY'], algorithm='HS256')
        refresh_token = jwt.encode(
            {'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)},
            application.config['SECRET_KEY'], algorithm='HS256')

        response = jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
        return response
    else:
        response = jsonify({'message': 'Invalid credentials'}), 401
        return response


# Endpoint for user registration
@application.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    phone = data.get('phone')
    email = data.get('email')
    password = data.get('password')
    password2 = data.get('password2')

    document = {'name': name,
                'phone': phone,
                'email': email,
                'password': password,
                'password2': password2}
    is_present = users_collection.find_one({'email': email})
    if (is_present is None) and (password == password2):
        users_collection.insert_one(document)
        response = jsonify({'message': 'User created successfully'}), 200
        return response
    elif password != password2:
        response = jsonify({'message': 'Not matching passwords'}), 401
        return response
    elif is_present is not None:
        response = jsonify({'message': 'User already exists'}), 409
        return response
    else:
        response = jsonify({'message': 'Unknown error'}), 401
        return response


if __name__ == '__main__':
    application.run()
