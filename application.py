from flask import Flask, request, jsonify, Response
import jwt
import datetime
from pymongo import MongoClient
from bson import json_util, ObjectId
from flask_cors import CORS
import re
import config
from datetime import datetime
import base64

application = Flask(__name__)
CORS(application)
application.config['SECRET_KEY'] = config.SECRET_KEY
SECRET_KEY = config.SECRET_KEY
client = MongoClient(config.MONGO_STRING)
db = client['size_crm']
users_collection = db['users']
clients_collection = db['clients']


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


# Endpoint to add new client
@application.route('/add_client', methods=['POST'])
def add_client():
    data = request.form.to_dict()  # Get form data including image
    userpic = request.files.get('userpic')

    name = data.get('name', None)
    phone = data.get('phone', None)
    additional_phone = data.get('additional_phone', None)
    email = data.get('email', None)
    gender = data.get('gender', None)
    birthday = data.get('birthday', None)
    instagram = data.get('instagram', None)
    telegram = data.get('telegram', None)
    comment = data.get('comment', None)
    status = data.get('status', None)

    # Process image file
    if userpic:
        userpic = base64.b64encode(userpic.read()).decode('utf-8')
    else:
        userpic = None

    document = {
        'name': name,
        'phone': phone,
        'additional_phone': additional_phone,
        'email': email,
        'gender': gender,
        'birthday': datetime.strptime(birthday, '%d-%m-%Y'),
        'instagram': instagram,
        'telegram': telegram,
        'comment': comment,
        'status': status,
        'userpic': userpic  # Store the image data as base64 string
    }

    is_present = clients_collection.find_one({'phone': phone})
    if is_present is None:
        clients_collection.insert_one(document)
        response = jsonify({'message': 'Client created successfully'}), 200
        return response
    else:
        response = jsonify({'message': 'Client already exists'}), 409
        return response


# Endpoint to get clients list
@application.route('/clients', methods=['GET'])
def clients():
    data = request.get_json()
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {}
    if keyword:
        clients_collection.create_index([("$**", "text")])
        filter_criteria['$text'] = {'$search': keyword}

    # Count the total number of clients that match the filter criteria
    total_clients = clients_collection.count_documents(filter_criteria)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(clients_collection.find(filter_criteria).skip(skip).limit(per_page))

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_clients)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'clients': documents, 'total_clients': total_clients, 'start_range': start_range, 'end_range': end_range},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


# Endpoint to delete client
@application.route('/delete_client', methods=['POST'])
def delete_client():
    data = request.get_json()
    client_id = data.get('client_id')

    # Convert the client_id to ObjectId type
    client_object_id = ObjectId(client_id)

    # Find and delete the document by its ObjectId
    result = clients_collection.delete_one({'_id': client_object_id})

    if result.deleted_count == 1:
        return jsonify({'message': 'Client deleted successfully'}), 200
    else:
        return jsonify({'message': 'Client not found'}), 404


# Endpoint to edit client
@application.route('/update_client/<client_id>', methods=['PUT'])
def update_client(client_id):
    try:
        # Convert the client_id to ObjectId type
        client_object_id = ObjectId(client_id)

        # Retrieve the existing client document from MongoDB
        existing_client = clients_collection.find_one({'_id': client_object_id})

        if existing_client:
            # Get data from the request
            userpic = request.files.get('userpic')
            data = request.form.to_dict()

            # Update fields if new data is provided in the request
            if 'name' in data:
                existing_client['name'] = data['name']
            if 'phone' in data:
                existing_client['phone'] = data['phone']
            if 'additional_phone' in data:
                existing_client['additional_phone'] = data['additional_phone']
            if 'email' in data:
                existing_client['email'] = data['email']
            if 'gender' in data:
                existing_client['gender'] = data['gender']
            if 'birthday' in data:
                existing_client['birthday'] = data['birthday']
            if 'instagram' in data:
                existing_client['instagram'] = data['instagram']
            if 'telegram' in data:
                existing_client['telegram'] = data['telegram']
            if 'comment' in data:
                existing_client['comment'] = data['comment']
            if 'status' in data:
                existing_client['status'] = data['status']

            # Update userpic if a new userpic is provided in the request
            def process_and_store_userpic(userpic):
                if userpic:
                    try:
                        # Read the image file as binary data
                        image_data = userpic.read()

                        # Encode the binary image data as base64
                        base64_image = base64.b64encode(image_data).decode('utf-8')

                        # Return the base64 encoded image data for MongoDB storage
                        return base64_image

                    except Exception as e:
                        # Handle any potential errors while processing the image
                        print(f"Error processing image: {str(e)}")
                        return None

                else:
                    # Handle invalid or missing userpic files
                    return None
            if userpic:
                existing_client['userpic'] = process_and_store_userpic(userpic)

            # Update the client document in MongoDB
            clients_collection.find_one_and_update({'_id': client_object_id}, {'$set': existing_client})

            return jsonify({'message': 'Client updated successfully'}), 200

        else:
            return jsonify({'message': 'Client not found'}), 404

    except Exception as e:
        # Handle errors
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    application.run()
