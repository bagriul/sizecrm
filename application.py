from flask import Flask, request, jsonify, Response, session
import jwt
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson import json_util, ObjectId
from flask_cors import CORS
import re
import config
from datetime import datetime, timedelta
import base64
import json
import math
from flask import Flask, redirect, url_for, render_template
from flask_mail import Mail, Message
from flask_dance.contrib.google import make_google_blueprint, google
import requests
from io import BytesIO
from uuid import uuid4
from flask_bcrypt import Bcrypt
import telebot
import random
import string

application = Flask(__name__)
CORS(application)
application.config['SECRET_KEY'] = config.SECRET_KEY
SECRET_KEY = config.SECRET_KEY
client = MongoClient(config.MONGO_STRING)
db = client['size_crm']
users_collection = db['users']
clients_collection = db['clients']
statuses_collection = db['statuses']
orders_collection = db['orders']
tasks_collection = db['tasks']
products_collection = db['products']
warehouses_collection = db['warehouses']
variations_collection = db['variations']
transactions_collection = db['transactions']
cashiers_collection = db['cashiers']
counterparties_collection = db['counterparties']
auto_transactions_collection = db['auto_transactions']
demo_users_collection = db['demo_users']
mailing_history_collection = db['mailing_history']
task_participants_collection = db['task_participants']
products_categories_collection = db['products_categories']
shipping_methods_collection = db['shipping_methods']
order_sources_collection = db['order_sources']
payment_methods_collection = db['payment_methods']
loyalty_collection = db['loyalty']
notifications_collection = db['notifications']

google_bp = make_google_blueprint(client_id='YOUR_GOOGLE_CLIENT_ID',
                                  client_secret='YOUR_GOOGLE_CLIENT_SECRET',
                                  redirect_to='google_login')
application.register_blueprint(google_bp, url_prefix='/google_login')

application.config['MAIL_SERVER'] = 'smtp.gmail.com'
application.config['MAIL_PORT'] = 465  # Use your mail server's port
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USE_SSL'] = True
application.config['MAIL_USERNAME'] = 'size.crm@gmail.com'
application.config['MAIL_PASSWORD'] = 'wchg bcif xkkr oqga'
application.config['MAIL_DEFAULT_SENDER'] = 'size.crm@gmail.com'
mail = Mail(application)

bcrypt = Bcrypt(application)
bot = telebot.TeleBot('')


@application.route('/', methods=['GET'])
def test():
    return 'SizeCRM API v1.0'


def decode_access_token(access_token, secret_key):
    try:
        payload = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        # Handle expired token
        return None
    except jwt.InvalidTokenError:
        # Handle invalid token
        return None


def decode_refresh_token(refresh_token, secret_key):
    try:
        payload = jwt.decode(refresh_token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        # Handle expired token
        return None
    except jwt.InvalidTokenError:
        # Handle invalid token
        return None


# Sample function to verify access token
def verify_access_token(access_token):
    try:
        decoded_token = decode_access_token(access_token, SECRET_KEY)
        if decoded_token:
            user_id = decoded_token.get('user_id')
            # Fetch user data from the database using the user_id
            user = users_collection.find_one({'_id': ObjectId(user_id)})
            if user:
                name = user['name']
                userpic = user['userpic']
                role = user['role']
                email = user['email']
                return jsonify({'user_id': user_id, 'name': name, 'userpic': userpic, 'role': role,
                                'email': email}), 200
            # User is authenticated, proceed with processing the request
            else:
                return jsonify({'message': 'User not found'}), 404
        # User not found, handle the error
    except jwt.ExpiredSignatureError:
        # Token has expired
        return False
    except jwt.InvalidTokenError:
        # Invalid token
        return False


# Sample function to verify refresh token
def verify_refresh_token(refresh_token):
    try:
        decoded_token = decode_refresh_token(refresh_token, SECRET_KEY)
        if decoded_token:
            user_id = decoded_token.get('user_id')
            # Fetch user data from the database using the user_id
            user = users_collection.find_one({'_id': ObjectId(user_id)})
            if user:
                name = user['name']
                userpic = user['userpic']
                return jsonify({'name': name, 'userpic': userpic}), 200
            # User is authenticated, proceed with processing the request
            else:
                return jsonify({'message': 'User not found'}), 404
        # User not found, handle the error
    except jwt.ExpiredSignatureError:
        # Token has expired
        return False
    except jwt.InvalidTokenError:
        # Invalid token
        return False


def check_token(access_token):
    if not access_token:
        response = jsonify({'token': False}), 401
        return False
    try:
        # Verify the JWT token
        decoded_token = jwt.decode(access_token, SECRET_KEY, algorithms=['HS256'])
        return True
    except jwt.ExpiredSignatureError:
        response = jsonify({'token': False}), 401
        return False
    except jwt.InvalidTokenError:
        response = jsonify({'token': False}), 401
        return False


@application.route('/validate_tokens', methods=['POST'])
def validate_tokens():
    data = request.get_json()
    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')

    if not access_token and not refresh_token:
        response = jsonify({'message': 'Access token or refresh token is missing'}), 401
        return response

    if access_token:
        return verify_access_token(access_token)
    if refresh_token:
        return verify_refresh_token(refresh_token)


# Endpoint for user login
@application.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    remember_me = data.get('remember_me', False)  # Assuming remember_me is a boolean field in the request

    # Check if the user exists in the database
    user = users_collection.find_one({'email': email})

    if user:
        hashed_password_in_db = user.get('password', '')  # Assuming the field name is 'password'

        if bcrypt.check_password_hash(hashed_password_in_db, password):
            user_id = str(user['_id'])  # Assuming user ID is stored as ObjectId in MongoDB

            # Set expiration time based on remember_me
            if remember_me:
                expiration_time = datetime.utcnow() + timedelta(days=1)
            else:
                expiration_time = datetime.utcnow() + timedelta(minutes=30)

            # Generate tokens based on user ID
            access_token = jwt.encode(
                {'user_id': user_id, 'exp': expiration_time},
                application.config['SECRET_KEY'], algorithm='HS256')

            # Save user's email if remember_me is checked
            if remember_me:
                session.permanent = True
                session['user_email'] = email
                session['user_password'] = password

            response = jsonify({'access_token': access_token}), 200
            return response

    response = jsonify({'message': False}), 401
    return response


# Endpoint for user registration
@application.route('/register', methods=['POST'])
def register():
    default_userpic = ''
    data = request.get_json()
    name = data.get('name')
    phone = data.get('phone')
    email = data.get('email')
    password = data.get('password')
    password2 = data.get('password2')

    if password != password2:
        return ({'message': False}), 409

    # Hash the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    document = {
        'name': name,
        'phone': phone,
        'email': email,
        'password': hashed_password,
        'password2': hashed_password,
        'userpic': default_userpic,
        'role': 'all',
        'subscription': True,
        'subscription_end': datetime.today() + timedelta(days=30)
    }

    is_present = users_collection.find_one({'email': email})

    if (is_present is None) and (bcrypt.check_password_hash(hashed_password, password)):
        users_collection.insert_one(document)
        response = jsonify({'message': True}), 200
        return response
    else:
        response = jsonify({'message': False}), 401
        return response


@application.route('/demo_register', methods=['POST'])
def demo_register():
    # Replace with your GitHub PDF link
    github_pdf_link = 'https://github.com/bagriul/sizecrm/blob/main/presentation_size.pdf'

    # Download PDF from GitHub
    pdf_response = requests.get(github_pdf_link)
    pdf_data = BytesIO(pdf_response.content)

    # Create Flask-Mail message
    subject = 'Презентація СРМ для вашого бізнесу'
    sender_email = 'size.crm@gmail.com'
    data = request.get_json()
    to_email = data.get('email')
    message_body = ''

    msg = Message(subject, sender=sender_email, recipients=[to_email])
    msg.body = message_body
    pdf_data.seek(0)
    msg.attach('presentation_size.pdf', 'application/pdf', pdf_data.getvalue())

    # Send the email
    try:
        mail.send(msg)
        name = data.get('name')
        phone = data.get('phone')
        brand = data.get('brand')
        position = data.get('position')
        document = {'name': name,
                    'phone': phone,
                    'brand': brand,
                    'position': position,
                    'email': to_email}
        is_present = demo_users_collection.find_one(document)
        if is_present is None:
            demo_users_collection.insert_one(document)
        return 'Email sent successfully!'
    except Exception as e:
        return f'Error sending email: {str(e)}'


def generate_random_credentials():
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=12))
    return username, password


def check_credentials_exist(username, password):
    existing_user = users_collection.find_one({'username': username, 'password': password})
    return existing_user is not None


def generate_tokens(user_id):
    access_token_payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(minutes=30)  # Token expires in 30 minutes
    }
    access_token = jwt.encode(access_token_payload, SECRET_KEY, algorithm='HS256')

    refresh_token_payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)  # Token expires in 30 days
    }
    refresh_token = jwt.encode(refresh_token_payload, SECRET_KEY, algorithm='HS256')

    return access_token, refresh_token


@application.route('/temporary_user_register', methods=['POST'])
def temporary_user_register():
    # Generate random username and password
    username, password = generate_random_credentials()

    # Check if credentials already exist
    while check_credentials_exist(username, password):
        username, password = generate_random_credentials()

    # Hash the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Insert user data into the database
    document = {
        'username': username,
        'password': hashed_password,
        'type': 'temporary'
    }
    users_collection.insert_one(document)

    # Generate access and refresh tokens
    access_token, refresh_token = generate_tokens(username)  # You can use username as user_id here

    # Return access and refresh tokens
    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200


@application.route('/temporary_user_delete', methods=['POST'])
def temporary_user_delete():
    data = request.get_json()
    access_token = data.get('access_token')
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    deleted_count = 0
    for collection_name in db.list_collection_names():
        collection = db[collection_name]
        result = collection.delete_many({'user_id': user_id})
        deleted_count += result.deleted_count

    # Delete the user
    users_collection.delete_one({'username': user_id})

    return jsonify({'message': True}), 200


def generate_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=20))


@application.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    user = users_collection.find_one({'email': email})
    if user:
        token = generate_token()
        users_collection.update_one({'email': email}, {'$set': {'reset_token': token}})

        msg = Message('Відновлення паролю', recipients=[email])
        msg.body = f"Перейдіть за цим посиланням для відновлення паролю: http://127.0.0.1:5000/reset_password?token={token}"
        mail.send(msg)

        return jsonify({'message': True}), 200
    else:
        return jsonify({'message': False}), 404


@application.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('reset_token')
    new_password = data.get('new_password')

    user = users_collection.find_one({'reset_token': token})
    if user:
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        users_collection.update_one({'reset_token': token}, {'$set': {'password': hashed_password, 'reset_token': None}})

        return jsonify({'message': True}), 200
    else:
        return jsonify({'message': False}), 400


@application.route('/change_password', methods=['POST'])
def change_password():
    data = request.get_json()

    access_token = data.get('access_token')
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    current_password = data.get('current_password')
    new_password = data.get('new_password')
    new_password2 = data.get('new_password2')

    if new_password != new_password2:
        return jsonify({'message': False}), 409

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Find the user in the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        return jsonify({'message': False}), 404

    hashed_password_in_db = user.get('password', '')

    # Check if the current password is correct
    if not bcrypt.check_password_hash(hashed_password_in_db, current_password):
        return jsonify({'message': False}), 401

    # Hash the new password
    hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    # Update the user's password in the database
    users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'password': hashed_new_password, 'password2': hashed_new_password}}
    )

    return jsonify({'message': True}), 200


@application.route('/check_reset_token', methods=['POST'])
def check_reset_token():
    data = request.get_json()
    token = data.get('reset_token')

    user = users_collection.find_one({'reset_token': token})
    if user:
        return jsonify({'message': True}), 200
    else:
        return jsonify({'message': False}), 400


def send_welcome_email(email):
    msg = Message('Презентація СРМ для вашого бізнесу', recipients=[email])

    # Customize the email content
    msg.body = ''

    pdf_file_url = 'https://raw.githubusercontent.com/bagriul/sizecrm/main/%D0%9F%D1%80%D0%B5%D0%B7%D0%B5%D0%BD%D1%82%D0%B0%D1%86%D1%96%D1%8F%20Size%20CRM.pdf'

    # Download the PDF file from the URL
    response = requests.get(pdf_file_url)

    # Attach the PDF file to the email
    msg.attach('%D0%9F%D1%80%D0%B5%D0%B7%D0%B5%D0%BD%D1%82%D0%B0%D1%86%D1%96%D1%8F%20Size%20CRM.pdf', 'application/pdf', response.content)

    mail.send(msg)


# Endpoint to add new client
@application.route('/add_client', methods=['POST'])
def add_client():
    # Get form data including image
    data = request.form.to_dict()
    userpic = request.files.get('userpic')

    # Check access token
    access_token = data.get('access_token')
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Extract data from form
    name = data.get('name')
    phone = data.get('phone')
    additional_phone = data.get('additional_phone')
    email = data.get('email')
    gender = data.get('gender')
    birthday = data.get('birthday')
    instagram = data.get('instagram')
    telegram = data.get('telegram')
    comment = data.get('comment')
    status = data.get('status')
    discount = data.get('discount', 0)

    # Fetch status document from collection
    status_doc = statuses_collection.find_one({'status': status}, {'_id': 0}) if status else None

    # Process image file
    userpic = base64.b64encode(userpic.read()).decode('utf-8') if userpic else None

    # Construct document
    document = {
        'name': name,
        'phone': phone,
        'additional_phone': additional_phone,
        'email': email,
        'gender': gender,
        'birthday': datetime.strptime(birthday, "%a %b %d %Y"),
        'instagram': instagram,
        'telegram': telegram,
        'comment': comment,
        'status': status_doc,
        'userpic': userpic,
        'user_id': user_id,
        'discount': discount
    }

    # Check if client already exists
    is_present = clients_collection.find_one({'email': email, 'user_id': user_id})
    if is_present:
        return jsonify({'message': 'Client already exists'}), 409

    # Insert new client document
    clients_collection.insert_one(document)

    # Return response
    return jsonify({'message': 'Client created successfully'}), 200


# Endpoint to get clients list
@application.route('/clients', methods=['POST'])
def clients():
    # Get data from request
    data = request.get_json()

    # Get access token from data
    access_token = data.get('access_token')

    # Check access token
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    # Decode user_id from access token
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Get keyword, page, and per_page from data
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    # Define filter criteria based on user_id and keyword
    filter_criteria = {'user_id': user_id}
    if keyword:
        regex_pattern = f'.*{re.escape(keyword)}.*'
        filter_criteria['name'] = {'$regex': regex_pattern, '$options': 'i'}

    # Count the total number of clients that match the filter criteria
    total_clients = clients_collection.count_documents(filter_criteria)

    # Calculate total pages
    total_pages = math.ceil(total_clients / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    clients = list(clients_collection.find(filter_criteria).skip(skip).limit(per_page))

    # Prepare response clients with additional information
    response_clients = []
    for client in clients:
        client_orders = list(orders_collection.find({'email': client['email']}))
        client['orders'] = client_orders
        total_price_sum = sum(order.get('total_sum', 0) for order in client_orders)
        latest_order_date = max((order.get('date', datetime.min) for order in client_orders), default=None)
        client['_id'] = str(client['_id'])
        client['orders_amount'] = len(client_orders)
        client['total_price_sum'] = total_price_sum
        client['latest_order_date'] = latest_order_date
        response_clients.append(client)

    # Sort response clients based on sort_by and reverse_sort parameters
    sort_by = data.get('sort_by')
    if sort_by:
        reverse_sort = data.get('reverse_sort', False)
        if sort_by in ('latest_order_date', 'status'):
            response_clients = sorted(response_clients, key=lambda x: x.get(
                sort_by) or datetime.min if sort_by == 'latest_order_date' else x.get('status', {}).get('status', ''),
                                      reverse=reverse_sort)
        else:
            response_clients = sorted(response_clients, key=lambda x: x.get(sort_by, 0), reverse=reverse_sort)

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_clients)

    # Serialize the response clients using json_util from pymongo and specify encoding
    response = Response(
        json_util.dumps({
            'clients': response_clients,
            'total_clients': total_clients,
            'start_range': start_range,
            'end_range': end_range,
            'total_pages': total_pages
        }, ensure_ascii=False).encode('utf-8'),
        content_type='application/json;charset=utf-8'
    )

    return response, 200


# Endpoint to delete client
@application.route('/delete_client', methods=['POST'])
def delete_client():
    # Get data from request
    data = request.get_json()

    # Extract client_id and access_token from data
    client_id = data.get('client_id')
    access_token = data.get('access_token')

    # Check access token
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    try:
        # Convert client_id to ObjectId type
        client_object_id = ObjectId(client_id)
    except:
        # Return error response if client_id is invalid
        return jsonify({'message': 'Invalid client ID'}), 400

    # Find and delete the document by its ObjectId
    result = clients_collection.delete_one({'_id': client_object_id})

    # Check if document is deleted successfully
    if result.deleted_count == 1:
        return jsonify({'message': 'Client deleted successfully'}), 200
    else:
        return jsonify({'message': 'Client not found'}), 404


# Endpoint to edit client
@application.route('/update_client/<client_id>', methods=['POST'])
def update_client(client_id):
    # Get form data and access token from request
    data = request.form.to_dict()
    access_token = data.get('access_token')

    # Check access token
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    try:
        # Convert client_id to ObjectId type
        client_object_id = ObjectId(client_id)
    except:
        # Return error response if client_id is invalid
        return jsonify({'message': 'Invalid client ID'}), 400

    # Retrieve the existing client document from MongoDB
    existing_client = clients_collection.find_one({'_id': client_object_id})

    if existing_client:
        # Update client fields if new data is provided in the request
        for field in ['name', 'phone', 'additional_phone', 'email', 'gender', 'birthday', 'instagram', 'telegram', 'comment', 'discount']:
            if field in data:
                existing_client[field] = data[field]

        # Update client status if provided in the request
        if 'status' in data:
            status_doc = statuses_collection.find_one({'status': data['status']})
            if status_doc:
                del status_doc['_id']
            existing_client['status'] = status_doc

        # Update userpic if a new userpic is provided in the request
        userpic = request.files.get('userpic')
        if userpic:
            existing_client['userpic'] = process_and_store_userpic(userpic)

        # Update the client document in MongoDB
        clients_collection.replace_one({'_id': client_object_id}, existing_client)

        return jsonify({'message': 'Client updated successfully'}), 200

    else:
        return jsonify({'message': 'Client not found'}), 404

def process_and_store_userpic(userpic):
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


# Endpoint to create new client status
@application.route('/new_status', methods=['POST'])
def new_status():
    # Get data from request
    data = request.get_json()

    # Extract access_token and status details from data
    access_token = data.get('access_token')
    status = data.get('status')
    colour = data.get('colour')
    type = data.get('type')

    # Check access token
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    # Decode user_id from access token
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Check if status already exists
    is_present = statuses_collection.find_one({'status': status, 'type': type, 'user_id': user_id})
    if is_present:
        return jsonify({'message': 'Status already exists'}), 409

    # Insert new status document
    statuses_collection.insert_one({'status': status, 'colour': colour, 'type': type, 'user_id': user_id})

    return jsonify({'message': 'Created successfully'}), 200


@application.route('/get_statuses', methods=['POST'])
def get_statuses():
    # Get data from request
    data = request.get_json()

    # Extract access_token and type from data
    access_token = data.get('access_token')
    type = data.get('type')

    # Check access token
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    # Decode user_id from access token
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Prepare filter criteria based on user_id and type
    filter_criteria = {
        '$or': [
            {'user_id': user_id},
            {'user_id': "0"}
        ]
    }
    if type:
        filter_criteria['type'] = type

    # Retrieve documents from the collection based on filter criteria
    documents = list(statuses_collection.find(filter_criteria))

    # Convert ObjectId to string for each document
    for document in documents:
        document['_id'] = str(document['_id'])

    # Serialize the response documents using json_util from pymongo and specify encoding
    response = Response(
        json_util.dumps({'statuses': documents}, ensure_ascii=False).encode('utf-8'),
        content_type='application/json;charset=utf-8'
    )

    return response, 200


@application.route('/client_info', methods=['POST'])
def client_info():
    # Get data from request
    data = request.get_json()

    # Extract access_token and client_id from data
    access_token = data.get('access_token')
    client_id = data.get('client_id')

    # Check access token
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    # Convert client_id to ObjectId
    try:
        object_id = ObjectId(client_id)
    except:
        return jsonify({'message': 'Invalid client ID'}), 400

    # Find client document by ObjectId
    client_document = clients_collection.find_one({'_id': object_id})

    if client_document:
        # Convert ObjectId to string for client document
        client_document['_id'] = str(client_document['_id'])

        # Find orders where email matches client email
        client_email = client_document.get('email')
        orders_query = {'email': client_email}

        # Get total number of orders
        total_orders = orders_collection.count_documents(orders_query)

        # Pagination parameters
        page = int(data.get('page', 1))
        page_size = int(data.get('per_page', 10))
        skip = (page - 1) * page_size

        # Retrieve a subset of orders based on pagination
        orders = list(orders_collection.find(orders_query).skip(skip).limit(page_size))

        # Convert ObjectId to string for each order document
        for order in orders:
            order['_id'] = str(order['_id'])

        # Get sorting parameters from the request
        sort_by = data.get('sort_by')
        if sort_by:
            reverse_sort = data.get('reverse_sort', False)
            orders = sorted(orders, key=lambda x: x.get(sort_by, 0), reverse=reverse_sort)

        # Add sorted orders to the client document
        client_document['orders'] = orders

        # Calculate pagination details
        start_range = skip + 1
        end_range = min(skip + page_size, total_orders)
        total_pages = (total_orders + page_size - 1) // page_size

        # Include pagination details in the response
        response_data = {
            'client_info': client_document,
            'total_orders': total_orders,
            'start_range': start_range,
            'end_range': end_range,
            'total_pages': total_pages
        }

        # Serialize response data using json.dumps() with ObjectId serialization
        return json.dumps(response_data, default=str), 200, {'Content-Type': 'application/json'}
    else:
        return jsonify({'message': 'Client not found'}), 404


# Endpoint to get orders list
@application.route('/orders', methods=['POST'])
def orders():
    # Get data from request
    data = request.get_json()

    # Extract access_token and user_id from data
    access_token = data.get('access_token')
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Check access token
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    # Extract filtering parameters from data
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    # Prepare filter criteria
    filter_criteria = {'user_id': user_id}
    if keyword:
        regex_pattern = f'.*{re.escape(keyword)}.*'
        filter_criteria['name'] = {'$regex': regex_pattern, '$options': 'i'}

    # Count the total number of orders that match the filter criteria
    total_orders = orders_collection.count_documents(filter_criteria)
    total_pages = math.ceil(total_orders / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(orders_collection.find(filter_criteria).skip(skip).limit(per_page))

    # Convert ObjectId to string and format date for each document
    for document in documents:
        document['_id'] = str(document['_id'])
        document['date'] = document['date'].strftime("%a %b %d %Y")

    # Sort documents based on sort_by parameter
    sort_by = data.get('sort_by')
    if sort_by:
        reverse_sort = data.get('reverse_sort', False)
        if sort_by == 'date':
            documents = sorted(documents, key=lambda x: x.get('date', ''), reverse=reverse_sort)
        elif sort_by in ('client', 'status', 'source', 'payment'):
            documents = sorted(documents, key=lambda x: x.get(sort_by, ''), reverse=reverse_sort)

    # Calculate the range of orders being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_orders)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(
        json_util.dumps({
            'orders': documents,
            'total_orders': total_orders,
            'start_range': start_range,
            'end_range': end_range,
            'total_pages': total_pages
        }, ensure_ascii=False).encode('utf-8'),
        content_type='application/json;charset=utf-8'
    )
    return response, 200


@application.route('/add_order', methods=['POST'])
def add_order():
    data = request.get_json()

    # Check access token
    access_token = data.get('access_token')
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Extract order details from request data
    client_name = data.get('client')
    client_email = data.get('email')
    shipping = data.get('shipping')
    status = data.get('status')
    source = data.get('source')
    payment = data.get('payment')
    comment = data.get('comment')
    cashier = data.get('cashier')
    variations_data = data.get('variations', [])

    # Get client details
    client = clients_collection.find_one({'name': client_name, 'email': client_email})

    # Prepare variations list
    variations = []
    total_sum = 0
    in_stock_errors = []

    for var_data in variations_data:
        variation_id = var_data.get('id')
        amount = var_data.get('amount', 1)  # Default amount is 1 if not specified

        # Fetch product and its variation
        product = products_collection.find_one({'variations._id': variation_id})

        if product:
            for variation in product.get('variations', []):
                if variation.get('_id') == variation_id:
                    variation_data = {
                        '_id': variation.get('_id'),
                        'name': product.get('name'),
                        'category': product.get('category'),
                        'size': variation.get('size'),
                        'colour': variation.get('colour'),
                        'price': variation.get('price'),
                        'in_stock': variation.get('in_stock'),
                        'photos': variation.get('photos'),
                        'cost_price': variation.get('cost_price'),
                        'amount': amount
                    }

                    if variation_data['in_stock'] < amount:
                        in_stock_errors.append({
                            'variation_id': variation_data['_id'],
                            'error': f'Not enough stock. Available: {variation_data["in_stock"]}'
                        })
                    else:
                        variations.append(variation_data)

                        try:
                            # Calculate price considering loyalty and client discounts
                            loyalty = loyalty_collection.find_one({'user_id': user_id, 'category': product.get('category'),
                                                                   'date': datetime.utcnow().replace(hour=0, minute=0,
                                                                                                     second=0,
                                                                                                     microsecond=0)})
                            if loyalty is not None:
                                variation_data['price'] = (variation_data['price'] * (100 - loyalty['discount']) / 100)
                            elif client['discount'] != 0:
                                variation_data['price'] = (variation_data['price'] * (100 - client['discount']) / 100)
                        except KeyError:
                            pass

                        # Calculate total sum for this variation
                        total_sum += variation_data['price'] * amount

                        # Update in_stock for this variation
                        variation_in_stock = variation.get('in_stock', 0) - amount
                        products_collection.update_one(
                            {'variations._id': variation_id},
                            {'$set': {'variations.$.in_stock': max(0, variation_in_stock)}}
                        )

    if in_stock_errors:
        return jsonify({'errors': in_stock_errors}), 400

    # Apply global discounts
    discount_sum = data.get('discount_sum', 0)
    discount_per = data.get('discount_per', 0)
    total_sum -= discount_sum
    total_sum -= (total_sum * discount_per / 100)

    # Prepare order document
    order_doc = {
        'date': datetime.today(),
        'client': client,
        'email': client_email,
        'gender': client.get('gender'),
        'shipping': shipping,
        'status': statuses_collection.find_one({'status': status}, {'_id': 0}),
        'source': source,
        'payment': payment,
        'comment': comment,
        'variations': variations,
        'discount_sum': discount_sum,
        'discount_per': discount_per,
        'total_sum': total_sum,
        'cashier': cashier,
        'user_id': user_id
    }

    # Check if order already exists
    existing_order = orders_collection.find_one(order_doc)
    if existing_order is None:
        new_order = orders_collection.insert_one(order_doc)

        notification = {'text': 'Нове замовлення', 'user_id': user_id, 'date': datetime.now(), 'type': 'order'}
        notifications_collection.insert_one(notification)

        # Process payment if status is 'Оплачено'
        if status == 'Оплачено':
            cashier = cashiers_collection.find_one({'name': cashier, 'user_id': user_id})
            balance = cashier.get('balance', 0)
            incomes = cashier.get('incomes', 0)
            cashiers_collection.update_one({'_id': cashier['_id']}, {'$set': {'balance': balance + total_sum}})
            cashiers_collection.update_one({'_id': cashier['_id']}, {'$set': {'incomes': incomes + total_sum}})
            transaction = {
                'type': "На рахунок",
                'cashier': cashier['name'],
                'sum': total_sum,
                'counterpartie': '',
                'date': datetime.now(),
                'category': '',
                'comment': '',
                'user_id': user_id,
                'order_id': str(new_order.inserted_id)
            }
            transactions_collection.insert_one(transaction)

            notification = {'text': 'Нове оплачене замовлення', 'user_id': user_id, 'date': datetime.now(), 'type': 'order'}
            notifications_collection.insert_one(notification)

    return jsonify({'message': True}), 200


@application.route('/delete_order', methods=['POST'])
def delete_order():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    order_id = data.get('order_id')
    orders_collection.find_one_and_delete({'_id': ObjectId(order_id)})
    return jsonify({'message': True}), 200


@application.route('/update_order', methods=['POST'])
def update_order():
    data = request.get_json()

    # Check access token
    access_token = data.get('access_token')
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    order_id = data.get('order_id')
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    total_sum = order.get('total_sum')
    if order is None:
        return jsonify({'message': False}), 404

    client_email = order.get('email')
    client = clients_collection.find_one({'email': client_email})
    try:
        client_discount = client['discount']
    except KeyError:
        client_discount = 0
    except TypeError:
        client_discount = 0

    # Update other order fields if provided
    order['client'] = data.get('client', order.get('client'))
    order['email'] = data.get('email', order.get('email'))
    order['shipping'] = data.get('shipping', order.get('shipping'))
    order['status'] = statuses_collection.find_one({'status': data.get('status')}, {'_id': 0}) if 'status' in data else order.get('status')
    order['source'] = data.get('source', order.get('source'))
    order['payment'] = data.get('payment', order.get('payment'))
    order['comment'] = data.get('comment', order.get('comment'))
    order['cashier'] = data.get('cashier', order.get('cashier'))

    # Prepare variations list
    variations_data = data.get('variations', [])
    if variations_data:
        variations = []
        total_sum = 0

        for var_data in variations_data:
            variation_id = var_data.get('id')
            amount = var_data.get('amount', 1)  # Default amount is 1 if not specified

            # Fetch product and its variation
            product = products_collection.find_one({'variations._id': variation_id})

            if product:
                for variation in product.get('variations', []):
                    if variation.get('_id') == variation_id:
                        variation_data = {
                            '_id': variation.get('_id'),
                            'name': product.get('name'),
                            'category': product.get('category'),
                            'size': variation.get('size'),
                            'colour': variation.get('colour'),
                            'price': variation.get('price'),
                            'in_stock': variation.get('in_stock'),
                            'photos': variation.get('photos'),
                            'cost_price': variation.get('cost_price'),
                            'amount': amount
                        }
                        variations.append(variation_data)

                        try:
                            # Calculate price considering loyalty and client discounts
                            loyalty = loyalty_collection.find_one(
                                {'user_id': user_id, 'category': product.get('category'),
                                 'date': datetime.utcnow().replace(hour=0, minute=0,
                                                                   second=0,
                                                                   microsecond=0)})
                            if loyalty is not None:
                                variation_data['price'] = (variation_data['price'] * (100 - loyalty['discount']) / 100)
                            elif client_discount != 0:
                                variation_data['price'] = (variation_data['price'] * (100 - client_discount) / 100)
                        except KeyError:
                            pass

                        # Calculate total sum for this variation
                        total_sum += variation_data['price'] * amount

                        # Update in_stock for this variation
                        variation_in_stock = variation.get('in_stock', 0) - amount
                        products_collection.update_one(
                            {'variations._id': variation_id},
                            {'$set': {'variations.$.in_stock': max(0, variation_in_stock)}}
                        )

    # Apply global discounts
    discount_sum = data.get('discount_sum', 0)
    discount_per = data.get('discount_per', 0)
    print(total_sum)
    try:
        if discount_sum != 0:
            total_sum -= discount_sum
    except TypeError:
        pass
    try:
        if discount_per != 0:
            total_sum -= (total_sum * discount_per / 100)
    except TypeError:
        pass

    # Update order document
    if variations_data:
        order['variations'] = variations
    order['discount_sum'] = discount_sum
    order['discount_per'] = discount_per
    order['total_sum'] = total_sum

    orders_collection.update_one({'_id': ObjectId(order_id)}, {'$set': order})

    # Process payment if status is 'Оплачено' or 'Повернено'
    if data.get("status") in ['Оплачено', 'Повернено']:
        cashier = cashiers_collection.find_one({'name': order.get('cashier'), 'user_id': user_id})
        if cashier:
            balance = cashier.get('balance', 0)
            incomes = cashier.get('incomes', 0)
            # Update balance and incomes based on status
            if data.get("status") == 'Оплачено':
                new_balance = balance + total_sum
                new_incomes = incomes + total_sum
                cashiers_collection.update_one({'_id': cashier['_id']},
                                               {'$set': {'balance': new_balance, 'incomes': new_incomes}})
            elif data.get("status") == 'Повернено':
                new_balance = balance - total_sum
                new_incomes = incomes - total_sum
                cashiers_collection.update_one({'_id': cashier['_id']},
                                               {'$set': {'balance': new_balance, 'incomes': new_incomes}})

            # Record the transaction
            transaction = {
                'type': "На рахунок" if data.get("status") == 'Оплачено' else "З рахунку",
                'cashier': cashier['name'],
                'sum': total_sum,
                'counterpartie': '',
                'date': datetime.now(),
                'category': '',
                'comment': '',
                'user_id': user_id,
                'order_id': str(order_id)
            }
            transactions_collection.insert_one(transaction)

            # Create a notification
            notification_text = 'Нове оплачене замовлення' if data.get(
                "status") == 'Оплачено' else 'Повернене замовлення'
            notification = {'text': notification_text, 'user_id': user_id, 'date': datetime.now(), 'type': 'order'}
            notifications_collection.insert_one(notification)

    return jsonify({'message': True}), 200


@application.route('/add_product_order', methods=['POST'])
def add_product_order():
    data = request.get_json()

    # Check access token
    access_token = data.get('access_token')
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    order_id = data.get('order_id')
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    if order is None:
        return jsonify({'message': False}), 404

    variation_id = data.get('variation_id')
    products_id_list = [str(product['_id']) for product in order.get('products', [])]

    if variation_id in products_id_list:
        for product in order['products']:
            if str(product['_id']) == variation_id:
                product['amount'] += 1
                break
    else:
        variation = variations_collection.find_one({'_id': ObjectId(variation_id)})
        if variation:
            document = {
                '_id': variation['_id'],
                'size': variation['size'],
                'colour': variation['colour'],
                'price': variation['price'],
                'in_stock': variation['in_stock'],
                'amount': 1,
                'photos': variation['photos'],
                'name': variation['name']
            }
            orders_collection.update_one({'_id': ObjectId(order_id)}, {'$push': {'products': document}})

    # Recalculate total_sum and update it in the order document
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    total_sum = sum(product['price'] * product['amount'] for product in order.get('products', []))
    orders_collection.update_one({'_id': ObjectId(order_id)}, {'$set': {'total_sum': total_sum}})

    return jsonify({'message': True}), 200


@application.route('/delete_product_order', methods=['POST'])
def delete_product_order():
    data = request.get_json()

    # Check access token
    access_token = data.get('access_token')
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    order_id = data.get('order_id')
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    if order is None:
        return jsonify({'message': False}), 404

    variation_id = data.get('variation_id')

    # Try to remove the product from the order
    try:
        orders_collection.update_one(order, {'$pull': {'products': {'_id': ObjectId(variation_id)}}})
    except:
        # If removing by ObjectId fails, try removing by string ID
        orders_collection.update_one(order, {'$pull': {'products': {'_id': variation_id}}})

    # Recalculate total_sum and update it in the order document
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    total_sum = sum(product['price'] * product['amount'] for product in order.get('products', []))
    orders_collection.find_one_and_update(order, {'$set': {'total_sum': total_sum}})

    return jsonify({'message': True}), 200


def convert_object_id(obj):
    if isinstance(obj, list):
        return [convert_object_id(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: convert_object_id(value) for key, value in obj.items()}
    elif isinstance(obj, ObjectId):
        return str(obj)
    else:
        return obj

@application.route('/order_info', methods=['POST'])
def order_info():
    data = request.get_json()

    # Check access token
    access_token = data.get('access_token')
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    order_id = data.get('order_id')
    object_id = ObjectId(order_id)

    # Find the order document by its ObjectId
    order_document = orders_collection.find_one({'_id': object_id})

    if order_document:
        # Convert ObjectId to string and format date before returning the response
        order_document = convert_object_id(order_document)
        order_document['date'] = order_document['date'].strftime("%a %b %d %Y")

        # Return the order document as JSON with proper content type
        return jsonify(order_document), 200, {'Content-Type': 'application/json'}
    else:
        # Return a 404 response if the order is not found
        return jsonify({'message': 'Order not found'}), 404



@application.route('/add_task', methods=['POST'])
def add_task():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    creator = data.get('creator')
    headline = data.get('headline')
    description = data.get('description', None)
    participants = data.get('participants', None)
    responsible = data.get('responsible', None)
    deadline = data.get('deadline', None)
    if deadline:
        deadline = datetime.strptime(deadline, "%a %b %d %Y")
    status = data.get('status', None)
    if status:
        status_doc = statuses_collection.find_one({'status': status})
        if status_doc:
            del status_doc['_id']
    comment = data.get('comment', None)

    # Get today's date
    today = datetime.today()

    document = {'date': today,
                'creator': creator,
                'headline': headline,
                'description': description,
                'participants': participants,
                'responsible': responsible,
                'deadline': deadline,
                'status': status_doc,
                'comment': comment,
                'user_id': user_id}
    tasks_collection.insert_one(document)

    notification = {'text': f'Нове завдання: {headline}',
                    'user_id': user_id,
                    'date': datetime.now(),
                    'type': 'task'}
    notifications_collection.insert_one(notification)

    return jsonify({'message': True}), 200


@application.route('/update_task', methods=['POST'])
def update_task():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    task_id = data.get('task_id')
    task = tasks_collection.find_one({'_id': ObjectId(task_id)})
    if task is None:
        return jsonify({'message': False}), 404

    # Update task fields based on the provided data
    task['headline'] = data.get('headline', task['headline'])
    task['creator'] = data.get('creator', task['creator'])
    task['description'] = data.get('description', task['description'])
    task['participants'] = data.get('participants', task['participants'])
    task['responsible'] = data.get('responsible', task['responsible'])
    deadline = datetime.strptime(data.get('deadline'), "%a %b %d %Y")
    if deadline:
        task['deadline'] = deadline
    status = data.get('status')
    if status:
        status_doc = statuses_collection.find_one({'status': status})
        if status_doc:
            del status_doc['_id']
        task['status'] = status_doc
    task['comment'] = data.get('comment', task['comment'])

    # Update the task in the database
    tasks_collection.update_one({'_id': ObjectId(task_id)}, {'$set': task})
    return jsonify({'message': True}), 200


@application.route('/delete_task', methods=['POST'])
def delete_task():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    task_id = data.get('task_id')
    tasks_collection.find_one_and_delete({'_id': ObjectId(task_id)})
    return jsonify({'message': True}), 200


@application.route('/task_info', methods=['POST'])
def task_info():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    task_id = data.get('task_id')
    object_id = ObjectId(task_id)
    task_document = tasks_collection.find_one({'_id': object_id})

    if task_document:
        # Convert ObjectId to string before returning the response
        task_document['_id'] = str(task_document['_id'])
        task_document['deadline'] = task_document['deadline'].strftime("%a %b %d %Y")
        task_document['date'] = task_document['date'].strftime("%a %b %d %Y")


        # Use dumps() to handle ObjectId serialization
        return json.dumps(task_document, default=str), 200, {'Content-Type': 'application/json'}
    else:
        response = jsonify({'message': 'Task not found'}), 404
        return response


@application.route('/tasks', methods=['POST'])
def tasks():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {'user_id': user_id}
    if keyword:
        regex_pattern = f'.*{re.escape(keyword)}.*'
        filter_criteria['headline'] = {'$regex': regex_pattern, '$options': 'i'}

    # Count the total number of clients that match the filter criteria
    total_tasks = tasks_collection.count_documents(filter_criteria)

    total_pages = math.ceil(total_tasks / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(tasks_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])
        document['date'] = document['date'].strftime("%a %b %d %Y")
        document['deadline'] = document['deadline'].strftime("%a %b %d %Y")

    sort_by = data.get('sort_by')
    if sort_by:
        reverse_sort = data.get('reverse_sort', False)
        if sort_by == 'status':
            documents = sorted(documents, key=lambda x: x.get("status", {}).get("status", ""), reverse=reverse_sort)
        else:
            documents = sorted(documents, key=lambda x: x.get(sort_by, 0), reverse=reverse_sort)

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_tasks)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'tasks': documents, 'total_tasks': total_tasks, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/add_task_participant', methods=['POST'])
def add_task_participant():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    task_id = data.get('task_id')
    task = tasks_collection.find_one({'_id': ObjectId(task_id)})
    if task is None:
        return jsonify({'message': False}), 404
    participant = data.get('participant')
    tasks_collection.update_one(task, {'$push': {'participants': participant}})
    return jsonify({'message': True}), 200


@application.route('/delete_task_participant', methods=['POST'])
def delete_task_participant():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    task_id = data.get('task_id')
    task = tasks_collection.find_one({'_id': ObjectId(task_id)})
    if task is None:
        return jsonify({'message': False}), 404
    participant = data.get('participant')
    tasks_collection.update_one(task, {'$pull': {'participants': participant}})
    return jsonify({'message': True}), 200


@application.route('/users', methods=['POST'])
def users():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {'user_id': user_id}
    if keyword:
        users_collection.create_index([("$**", "text")])
        filter_criteria['$text'] = {'$search': keyword}

    # Count the total number of clients that match the filter criteria
    total_users = users_collection.count_documents(filter_criteria)

    total_pages = math.ceil(total_users / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(users_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_users)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'users': documents, 'total_users': total_users, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/add_product', methods=['POST'])
def add_product():
    data = request.get_json()
    access_token = data.get('access_token')

    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    name = data.get('name')
    description = data.get('description')
    status = data.get('status')
    type = data.get('status_type')

    if status:
        status_doc = statuses_collection.find_one({'status': status, 'type': type})
        if status_doc:
            del status_doc['_id']

    category = data.get('category')
    units = data.get('units')
    warehouse = data.get('warehouse')
    comment = data.get('comment')
    variations = data.get('variations')
    subwarehouse = data.get('subwarehouse')
    cost_price = data.get('cost_price')
    photo = data.get('photo')

    # Generate a unique ID for each variation
    for variation in variations:
        variation['_id'] = str(uuid4())

    # Check if the generated IDs already exist in the database
    existing_ids = set(product['_id'] for product in products_collection.find({}, {'_id': 1}))
    for variation in variations:
        while variation['_id'] in existing_ids:
            # Regenerate the ID until it's unique
            variation['_id'] = str(uuid4())

    pieces = sum(variation.get('in_stock', 0) for variation in variations)

    document = {
        'date': datetime.now(),
        'name': name,
        'description': description,
        'status': status_doc,
        'category': category,
        'units': units,
        'warehouse': warehouse,
        'subwarehouse': subwarehouse,
        'comment': comment,
        'variations': variations,
        'pieces': pieces,
        'variations_num': len(variations),
        'cost_price': cost_price,
        'photo': photo,
        'user_id': user_id
    }

    products_collection.insert_one(document)
    return jsonify({'message': True}), 200


@application.route('/products', methods=['POST'])
def products():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    keyword = data.get('keyword')
    warehouse = data.get('warehouse')
    subwarehouse = data.get('subwarehouse')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {'user_id': user_id}
    if keyword:
        regex_pattern = f'.*{re.escape(keyword)}.*'
        filter_criteria['name'] = {'$regex': regex_pattern, '$options': 'i'}
    if warehouse:
        regex_pattern = f'.*{re.escape(warehouse)}.*'
        filter_criteria['warehouse'] = {'$regex': regex_pattern, '$options': 'i'}
    if subwarehouse:
        regex_pattern = f'.*{re.escape(subwarehouse)}.*'
        filter_criteria['subwarehouse'] = {'$regex': regex_pattern, '$options': 'i'}

    total_products = products_collection.count_documents(filter_criteria)

    total_pages = math.ceil(total_products / per_page)

    skip = (page - 1) * per_page
    documents = list(products_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])
    for document in documents:
        for variation in document['variations']:
            variation['name'] = document['name']

    sort_by = data.get('sort_by')
    if sort_by:
        reverse_sort = data.get('reverse_sort', False)
        if sort_by == 'category':
            documents = sorted(documents, key=lambda x: x.get('category', ''), reverse=reverse_sort)
        elif sort_by == 'date':
            documents = sorted(documents, key=lambda x: x.get('date', ''),
                               reverse=reverse_sort)
        elif sort_by == 'warehouse':
            documents = sorted(documents, key=lambda x: x.get('warehouse', ''), reverse=reverse_sort)
        elif sort_by == 'pieces':
            documents = sorted(documents, key=lambda x: x.get('pieces', 0), reverse=reverse_sort)
        elif sort_by == 'status':
            documents = sorted(documents, key=lambda x: x.get('status', {}).get('status', ''), reverse=reverse_sort)

    start_range = skip + 1
    end_range = min(skip + per_page, total_products)

    response = Response(json_util.dumps(
        {'products': documents, 'total_products': total_products, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/product_info', methods=['POST'])
def product_info():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    product_id = data.get('product_id')
    object_id = ObjectId(product_id)
    product_document = products_collection.find_one({'_id': object_id})

    if product_document:
        # Convert ObjectId to string before returning the response
        product_document['_id'] = str(product_document['_id'])

        # Include pagination details in the response
        response_data = {
            'product_info': product_document
        }

        # Use dumps() to handle ObjectId serialization
        return json.dumps(response_data, default=str), 200, {'Content-Type': 'application/json'}
    else:
        response = jsonify({'message': 'Product not found'}), 404
        return response


@application.route('/update_product', methods=['POST'])
def update_product():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    product_id = data.get('product_id')
    product = products_collection.find_one({'_id': ObjectId(product_id)})
    if product is None:
        return jsonify({'message': False}), 404

    # Update task fields based on the provided data
    product['name'] = data.get('name', product['name'])
    product['description'] = data.get('description', product['description'])
    status = data.get('status')
    type = data.get('status_type')
    if status:
        status_doc = statuses_collection.find_one({'status': status, 'type': type})
        if status_doc:
            del status_doc['_id']
        product['status'] = status_doc
    product['category'] = data.get('category', product['category'])
    product['units'] = data.get('units', product['units'])
    product['warehouse'] = data.get('warehouse', product['warehouse'])
    product['subwarehouse'] = data.get('subwarehouse', product['subwarehouse'])
    product['comment'] = data.get('comment', product['comment'])
    product['cost_price'] = data.get('cost_price', product['cost_price'])
    product['photo'] = data.get('photo', product['photo'])

    variations = data.get('variations')
    if variations:
        product['variations'] = variations
    else:
        product['variations'] = []
    products_collection.update_one({'_id': ObjectId(product_id)}, {'$set': product})

    product = products_collection.find_one({'_id': ObjectId(product_id)})
    pieces = 0
    for variation in product['variations']:
        pieces += variation['in_stock']
    products_collection.find_one_and_update(product, {'$set': {'pieces': pieces}})
    products_collection.find_one_and_update(product, {'$set': {'variations_num': len(variations)}})

    return jsonify({'message': True}), 200


@application.route('/delete_product', methods=['POST'])
def delete_product():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    product_id = data.get('product_id')
    products_collection.find_one_and_delete({'_id': ObjectId(product_id)})
    return jsonify({'message': True}), 200


'''@application.route('/add_variation', methods=['POST'])
def add_variation():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    product_id = data.get('product_id')
    product = products_collection.find_one({'_id': ObjectId(product_id)})
    if product is None:
        return jsonify({'message': False}), 404
    variation = data.get('variation')
    products_collection.update_one(product, {'$push': {'variations': variation}})
    product = products_collection.find_one({'_id': ObjectId(product_id)})
    products_collection.update_one(product, {'$set': {'pieces': sum(variation.get('in_stock', 0) for variation in product['variations'])}})
    product = products_collection.find_one({'_id': ObjectId(product_id)})
    products_collection.update_one(product, {'$set': {'variations_num': len(product['variations'])}})
    return jsonify({'message': True}), 200


@application.route('/delete_variation', methods=['POST'])
def delete_variation():
    data = request.get_json()
    product_id = data.get('product_id')
    index = data.get('index')

    product = products_collection.find_one({'_id': ObjectId(product_id)})
    # Update the document by pulling the element with the specified sequence number
    products_collection.update_one(
        {"_id": ObjectId(product_id)},
        {"$pull": {"variations": {"$eq": product['variations'][index]}}}
    )

    # Update pieces and variations_num after removing the variation
    product = products_collection.find_one({'_id': ObjectId(product_id)})
    pieces_sum = sum(variation.get('in_stock', 0) for variation in product['variations'])
    variations_num = len(product['variations'])

    products_collection.update_one(
        {"_id": ObjectId(product_id)},
        {"$set": {"pieces": pieces_sum, "variations_num": variations_num}}
    )

    return jsonify({'message': True}), 200


@application.route('/variations', methods=['POST'])
def variations():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    name = data.get('name')

    filter_criteria = {}
    if name:
        regex_pattern = f'.*{re.escape(name)}.*'
        filter_criteria['name'] = {'$regex': regex_pattern, '$options': 'i'}

    documents = list(variations_collection.find(filter_criteria))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps({'variations': documents}, ensure_ascii=False).encode('utf-8'),
            content_type='application/json;charset=utf-8')
    return response, 200'''


@application.route('/add_subwarehouse', methods=['POST'])
def add_subwarehouse():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    warehouse = data.get('warehouse')
    subwarehouse = data.get('subwarehouse')

    document = {'warehouse': warehouse,
                'subwarehouse': subwarehouse,
                'user_id': user_id}

    warehouses_collection.insert_one(document)
    return jsonify({'message': True}), 200


@application.route('/delete_subwarehouse', methods=['POST'])
def delete_subwarehouse():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    warehouse = data.get('warehouse')
    subwarehouse = data.get('subwarehouse')

    document = {'warehouse': warehouse,
                'subwarehouse': subwarehouse}

    warehouses_collection.delete_one(document)
    return jsonify({'message': True}), 200


@application.route('/subwarehouses', methods=['POST'])
def subwarehouses():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    filter_criteria = {'user_id': user_id}

    documents = list(warehouses_collection.find(filter_criteria))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps({'subwarehouses': documents}, ensure_ascii=False).encode('utf-8'),
            content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/add_transaction', methods=['POST'])
def add_transaction():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    if data.get('recuring') == False:
        type = data.get('type')
        cashier = data.get('cashier')
        amount = data.get('sum')
        counterpartie = data.get('counterpartie')
        date = datetime.strptime(data.get('date'), "%a %b %d %Y")
        category = data.get('category')
        comment = data.get('comment')

        document = {
            'type': type,
            'cashier': cashier,
            'sum': amount,
            'counterpartie': counterpartie,
            'date': date,
            'category': category,
            'comment': comment,
            'user_id': user_id
        }

        transactions_collection.insert_one(document)

        cashier_doc = cashiers_collection.find_one({'name': cashier})

        if document['type'] == 'На рахунок':
            cashier_doc['incomes'] += amount
            cashiers_collection.find_one_and_update(
                {'name': cashier},
                {'$set': {'incomes': cashier_doc['incomes']}}
            )
        elif document['type'] == 'З рахунку':
            cashier_doc['expenses'] += amount
            cashiers_collection.find_one_and_update(
                {'name': cashier},
                {'$set': {'expenses': cashier_doc['expenses']}}
            )

        # Assuming you have an '_id' field in your document
        transactions_collection.find_one_and_update(
            {'_id': document['_id']},
            {'$set': {'total_left': cashier_doc['incomes'] - cashier_doc['expenses']}}
        )

        return jsonify({'message': True})
    elif data.get('recuring') == True:
        type = data.get('type')
        cashier = data.get('cashier')
        amount = data.get('sum')
        counterpartie = data.get('counterpartie')
        date = datetime.strptime(data.get('date'), "%a %b %d %Y")
        category = data.get('category')
        comment = data.get('comment')
        periodicity = data.get('periodicity')

        document = {
            'type': type,
            'cashier': cashier,
            'sum': amount,
            'counterpartie': counterpartie,
            'date': date,
            'category': category,
            'comment': comment,
            'periodicity': periodicity,
            'user_id': user_id
        }

        transactions_collection.insert_one(document)
        auto_transactions_collection.insert_one(document)

        cashier_doc = cashiers_collection.find_one({'name': cashier})

        if document['type'] == 'На рахунок':
            cashier_doc['incomes'] += amount
            cashiers_collection.find_one_and_update(
                {'name': cashier},
                {'$set': {'incomes': cashier_doc['incomes']}}
            )
        elif document['type'] == 'З рахунку':
            cashier_doc['expenses'] += amount
            cashiers_collection.find_one_and_update(
                {'name': cashier},
                {'$set': {'expenses': cashier_doc['expenses']}}
            )

        # Assuming you have an '_id' field in your document
        transactions_collection.find_one_and_update(
            {'_id': document['_id']},
            {'$set': {'total_left': cashier_doc['incomes'] - cashier_doc['expenses']}}
        )

        return jsonify({'message': True})


@application.route('/update_transaction', methods=['POST'])
def update_transaction():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    transaction_id = data.get('transaction_id')
    transaction = transactions_collection.find_one({'_id': ObjectId(transaction_id)})
    if transaction is None:
        return jsonify({'message': False}), 404

    # Update task fields based on the provided data
    transaction['type'] = data.get('type', transaction['type'])
    transaction['cashier'] = data.get('cashier', transaction['cashier'])
    transaction['sum'] = data.get('sum', transaction['sum'])
    transaction['counterpartie'] = data.get('counterpartie', transaction['counterpartie'])
    transaction['category'] = data.get('category', transaction['category'])
    transaction['comment'] = data.get('comment', transaction['comment'])
    transaction['date'] = datetime.strptime(data.get('date', transaction['date']), "%a %b %d %Y")

    # Update the task in the database
    transactions_collection.update_one({'_id': ObjectId(transaction_id)}, {'$set': transaction})

    cashier = cashiers_collection.find_one({'name': transaction['cashier']})
    transactions = transactions_collection.find({'cashier': transaction['cashier']})
    incomes = 0
    expenses = 0
    for transaction in transactions:
        if transaction['type'] == 'На рахунок':
            incomes += transaction['sum']
        if transaction['type'] == 'З рахунку':
            expenses += transaction['sum']
    cashiers_collection.find_one_and_update(cashier, {'$set': {'incomes': incomes}})
    cashiers_collection.find_one_and_update(cashier, {'$set': {'expenses': expenses}})

    return jsonify({'message': True}), 200


@application.route('/delete_transaction', methods=['POST'])
def delete_transaction():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    transaction_id = data.get('transaction_id')
    transaction = transactions_collection.find_one({'_id': ObjectId(transaction_id)})
    transactions_collection.find_one_and_delete({'_id': ObjectId(transaction_id)})

    cashier = cashiers_collection.find_one({'name': transaction['cashier']})
    transactions = transactions_collection.find({'cashier': transaction['cashier']})
    incomes = 0
    expenses = 0
    for transaction in transactions:
        if transaction['type'] == 'На рахунок':
            incomes += transaction['sum']
        if transaction['type'] == 'З рахунку':
            expenses += transaction['sum']
    cashiers_collection.find_one_and_update(cashier, {'$set': {'incomes': incomes}})
    cashiers_collection.find_one_and_update(cashier, {'$set': {'expenses': expenses}})

    return jsonify({'message': True}), 200


@application.route('/transactions', methods=['POST'])
def transactions():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided
    archived = data.get('archived', False)  # Default to False if not provided

    filter_criteria = {'user_id': user_id}
    if keyword:
        regex_pattern = f'.*{re.escape(keyword)}.*'
        filter_criteria['comment'] = {'$regex': regex_pattern, '$options': 'i'}

    if not archived:
        filter_criteria['archived'] = {'$ne': True}

    # Count the total number of transactions that match the filter criteria
    total_transactions = transactions_collection.count_documents(filter_criteria)

    total_pages = math.ceil(total_transactions / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(transactions_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])
        document['date'] = document['date'].strftime("%a %b %d %Y")

    # Sorting logic
    sort_by = data.get('sort_by')
    if sort_by:
        reverse_sort = data.get('reverse_sort', False)
        if sort_by == 'date':
            documents = sorted(documents, key=lambda x: datetime.strptime(x['date'], "%a %b %d %Y"), reverse=reverse_sort)
        else:
            documents = sorted(documents, key=lambda x: x.get(sort_by, 0), reverse=reverse_sort)

    # Calculate the range of transactions being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_transactions)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'transactions': documents, 'total_transactions': total_transactions, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/transaction_info', methods=['POST'])
def transaction_info():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    transaction_id = data.get('transaction_id')
    object_id = ObjectId(transaction_id)
    transaction_document = transactions_collection.find_one({'_id': object_id})

    if transaction_document:
        # Convert ObjectId to string before returning the response
        transaction_document['_id'] = str(transaction_document['_id'])

        # Use dumps() to handle ObjectId serialization
        return json.dumps(transaction_document, default=str), 200, {'Content-Type': 'application/json'}
    else:
        response = jsonify({'message': 'Transaction not found'}), 404
        return response


@application.route('/add_cashier', methods=['POST'])
def add_cashier():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    name = data.get('name')
    type = data.get('type')
    document = {'name': name,
                'type': type,
                'incomes': 0,
                'expenses': 0,
                'user_id': user_id}
    is_present = cashiers_collection.find_one(document)
    if is_present is None:
        cashiers_collection.insert_one(document)
        return jsonify({'message': True}), 200
    else:
        return jsonify({'message': False}), 409


@application.route('/delete_cashier', methods=['POST'])
def delete_cashier():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    cashier_id = data.get('cashier_id')
    cashiers_collection.find_one_and_delete({'_id': ObjectId(cashier_id)})
    return jsonify({'message': True}), 200


@application.route('/cashiers', methods=['POST'])
def cashiers():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided
    archived = data.get('archived', False)  # Default to False if not provided

    filter_criteria = {'user_id': user_id}
    if keyword:
        cashiers_collection.create_index([("$**", "text")])
        filter_criteria['$text'] = {'$search': keyword}

    if not archived:
        filter_criteria['archived'] = {'$ne': True}

    # Count the total number of clients that match the filter criteria
    total_cashiers = cashiers_collection.count_documents(filter_criteria)
    total_pages = math.ceil(total_cashiers / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page

    transactions = list(transactions_collection.find({'user_id': user_id}))
    cashiers = list(cashiers_collection.find({'user_id': user_id}))

    # Initialize dictionaries to store incomes, expenses, and balances for each cashier
    cashier_incomes = {}
    cashier_expenses = {}
    cashier_balances = {}

    for cashier in cashiers:
        cashier_name = cashier['name']
        cashier_incomes[cashier_name] = 0
        cashier_expenses[cashier_name] = 0
        cashier_balances[cashier_name] = 0

    for transaction in transactions:
        cashier_name = transaction['cashier']

        if transaction['type'] == 'На рахунок':
            cashier_incomes[cashier_name] += transaction['sum']
        elif transaction['type'] == 'З рахунку':
            cashier_expenses[cashier_name] += transaction['sum']

    # Update cashiers_collection for each cashier
    for cashier_name in cashier_incomes.keys():
        balance = cashier_incomes[cashier_name] - cashier_expenses[cashier_name]
        cashiers_collection.find_one_and_update({'name': cashier_name, 'user_id': user_id}, {
            '$set': {
                'incomes': cashier_incomes[cashier_name],
                'expenses': cashier_expenses[cashier_name],
                'balance': balance
            }
        })

    documents = list(cashiers_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_cashiers)

    cashiers = cashiers_collection.find({'user_id': user_id})
    total_incomes = 0
    total_expenses = 0
    for cashier in cashiers:
        total_incomes += cashier.get('incomes', 0)
        total_expenses += cashier.get('expenses', 0)
    total_balance = total_incomes - total_expenses

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'cashiers': documents, 'total_cashiers': total_cashiers, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages, 'total_balance': total_balance, 'total_incomes': total_incomes,
         'total_expenses': total_expenses},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/add_counterpartie', methods=['POST'])
def add_counterpartie():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    name = data.get('name')
    is_present = counterparties_collection.find_one({'name': name,
                                                     'user_id': user_id})
    if is_present is None:
        counterparties_collection.insert_one({'name': name, 'user_id': user_id})
        return jsonify({'message': True}), 200
    else:
        return jsonify({'message': False}), 409


@application.route('/delete_counterpartie', methods=['POST'])
def delete_counterpartie():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    counterpartie_id = data.get('counterpartie_id')
    counterparties_collection.find_one_and_delete({'_id': ObjectId(counterpartie_id)})
    return jsonify({'message': True}), 200


@application.route('/counterparties', methods=['POST'])
def counterparties():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    keyword = data.get('keyword')

    filter_criteria = {'user_id': user_id}
    if keyword:
        regex_pattern = f'.*{re.escape(keyword)}.*'
        filter_criteria['name'] = {'$regex': regex_pattern, '$options': 'i'}

    # Retrieve all documents that match the filter criteria
    documents = list(counterparties_collection.find(filter_criteria))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps({'counterparties': documents}, ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/change_product_warehouse', methods=['POST'])
def change_product_warehouse():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    product_id = data.get('product_id')
    warehouse = data.get('warehouse')
    subwarehouse = data.get('subwarehouse')

    products_collection.find_one_and_update({'_id': ObjectId(product_id)}, {'$set': {'warehouse': warehouse}})
    products_collection.find_one_and_update({'_id': ObjectId(product_id)}, {'$set': {'subwarehouse': subwarehouse}})

    return jsonify({'message': True})


@application.route("/send_mailing", methods=['POST'])
def send_mailing():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    type = data.get('type')
    subject = data.get('subject')
    recipients = data.get('recipients')
    text = data.get('text')

    today = datetime.today()
    if type == 'mail':
        recipients_names = []
        for recipient in recipients:
            msg = Message(subject=subject, sender='bagriul@gmail.com', recipients=[recipient])
            msg.body = text
            #mail.send(msg)
            client = clients_collection.find_one({'email': recipient})
            recipients_names.append({'client_name': client['name'], 'client_id': str(client['_id'])})
        document = {'date': today,
                    'subject': subject,
                    'text': text,
                    'amount': len(recipients),
                    'recipients': recipients_names,
                    'type': 'mail',
                    'user_id': user_id,}
        mailing_history_collection.insert_one(document)
        return jsonify({'message': True}), 200
    elif type == 'telegram':
        recipients_names = []
        for recipient in recipients:
            try:
                #bot.send_message(recipient, text)
                client = clients_collection.find_one({'tgID': recipient})
                recipients_names.append({'client_name': client['name'], 'client_id': str(client['_id'])})
            except Exception as e:
                print(e)
        document = {'date': today,
                    'text': text,
                    'amount': len(recipients),
                    'recipients': recipients_names,
                    'type': 'telegram',
                    'user_id': user_id}
        mailing_history_collection.insert_one(document)
        return jsonify({'message': True}), 200


@application.route('/new_mailing_list', methods=['POST'])
def new_mailing_list():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    min_price = data.get('min_price')
    max_price = data.get('max_price')
    min_total_price = data.get('min_total_price')
    max_total_price = data.get('max_total_price')
    category = data.get('category')

    filter_criteria = {'user_id': user_id}
    if category:
        filter_criteria['variations'] = {'$elemMatch': {'category': category}}

    if min_price is not None and max_price is not None:
        filter_criteria['variations'] = {
            '$elemMatch': {
                'price': {'$gte': min_price, '$lte': max_price}
            }
        }
    elif min_price is not None:
        filter_criteria['variations'] = {
            '$elemMatch': {
                'price': {'$gte': min_price}
            }
        }
    elif max_price is not None:
        filter_criteria['variations'] = {
            '$elemMatch': {
                'price': {'$lte': max_price}
            }
        }

    if min_total_price is not None and max_total_price is not None:
        filter_criteria['total_sum'] = {'$gte': min_price, '$lte': max_price}
    elif min_total_price is not None:
        filter_criteria['total_sum'] = {'$gte': min_price}
    elif max_total_price is not None:
        filter_criteria['total_sum'] = {'$lte': max_price}

    documents = list(orders_collection.find(filter_criteria))
    email_list = []
    for document in documents:
        client = clients_collection.find_one({'email': document['email']})
        email = client['email']
        if email not in email_list:
            email_list.append(email)

    return jsonify({'emails': email_list}), 200


@application.route('/get_category', methods=['POST'])
def get_category():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    filter_criteria = {'user_id': user_id}
    # Query to get all documents
    documents = orders_collection.find(filter_criteria)

    # Extract unique categories from the documents
    categories_set = set()
    for document in documents:
        variations = document.get('variations', [])
        for variation in variations:
            category = variation.get('category')
            if category:
                categories_set.add(category)

    # Convert the set of categories to a list
    categories_list = list(categories_set)
    response = Response(json_util.dumps(
        {'categories': categories_list},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/new_telegram_list', methods=['POST'])
def new_telegram_list():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    min_price = data.get('min_price')
    max_price = data.get('max_price')
    min_total_price = data.get('min_total_price')
    max_total_price = data.get('max_total_price')
    category = data.get('category')

    filter_criteria = {'user_id': user_id}
    if category:
        filter_criteria['variations'] = {'$elemMatch': {'category': category}}

    if min_price is not None and max_price is not None:
        filter_criteria['variations'] = {
            '$elemMatch': {
                'price': {'$gte': min_price, '$lte': max_price}
            }
        }
    elif min_price is not None:
        filter_criteria['variations'] = {
            '$elemMatch': {
                'price': {'$gte': min_price}
            }
        }
    elif max_price is not None:
        filter_criteria['variations'] = {
            '$elemMatch': {
                'price': {'$lte': max_price}
            }
        }

    if min_total_price is not None and max_total_price is not None:
        filter_criteria['total_sum'] = {'$gte': min_price, '$lte': max_price}
    elif min_total_price is not None:
        filter_criteria['total_sum'] = {'$gte': min_price}
    elif max_total_price is not None:
        filter_criteria['total_sum'] = {'$lte': max_price}

    documents = list(orders_collection.find(filter_criteria))
    tgID_list = []
    for document in documents:
        client = clients_collection.find_one({'email': document['email']})
        try:
            tgID = client['tgID']
        except TypeError:
            continue
        except KeyError:
            continue
        if tgID not in tgID_list:
            tgID_list.append(tgID)

    return jsonify({'tgIDs': tgID_list}), 200


@application.route('/analytics', methods=['POST'])
def analytics():
    data = request.get_json() or {}
    access_token = data.get('access_token')

    if not check_token(access_token):
        return jsonify({'error': 'Invalid token'}), 401

    try:
        user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

        start_date = data.get('start_date', '')
        end_date = data.get('end_date', '')
        start_date = datetime.strptime(start_date, "%a %b %d %Y")
        end_date = datetime.strptime(end_date, "%a %b %d %Y") + timedelta(days=1)
    except (TypeError, ValueError) as e:
        response_data = {
            'sales_info': None,
            'returns_info': None,
            'top_products': None,
            'purchase_segmentation': None,
            'daily_analytics': None
        }
        return jsonify(response_data), 200

    sales_info = calculate_sales_info(user_id, start_date, end_date)
    returns_info = calculate_returns_info(user_id, start_date, end_date)
    top_products = calculate_top_products(user_id, start_date, end_date, data.get('product_category'))
    purchase_segmentation = calculate_purchase_segmentation(data, user_id)
    #mailing_history, total_documents = get_mailing_history(data, user_id)
    daily_analytics = calculate_daily_tasks_transactions_orders_sales(start_date, end_date, user_id)

    response_data = {
        **sales_info,
        **returns_info,
        'top_products': top_products,
        **purchase_segmentation,
        'daily_analytics': daily_analytics
    }

    return jsonify(response_data), 200


@application.route('/mailing_history', methods=['POST'])
def mailing_history():
    data = request.get_json() or {}
    access_token = data.get('access_token')

    if not check_token(access_token):
        return jsonify({'error': 'Invalid token'}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    mailing_history, total_documents = get_mailing_history(data, user_id)

    response_data = {
        'mailing_history': mailing_history,
        'total_documents': total_documents
    }

    return jsonify(response_data), 200


def calculate_daily_tasks_transactions_orders_sales(start_date, end_date, user_id):
    # Initialize a dictionary to hold day-by-day data
    daily_data = {}
    current_date = start_date
    while current_date < end_date:
        date_key = current_date.strftime('%Y-%m-%d')
        daily_data[date_key] = {'orders': 0, 'sales': 0, 'active_tasks': 0, 'transactions': 0, 'products': 0}
        current_date += timedelta(days=1)

    # Query for orders and sales
    orders_and_sales = orders_collection.aggregate([
        {
            '$match': {
                'user_id': user_id,
                'date': {'$gte': start_date, '$lt': end_date}
            }
        },
        {
            '$group': {
                '_id': {
                    'date': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$date'}},
                    'status': '$status.status'
                },
                'count': {'$sum': 1}
            }
        }
    ])
    for item in orders_and_sales:
        date_key = item['_id']['date']
        if item['_id']['status'] == 'Оплачено':
            daily_data[date_key]['sales'] += item['count']
        daily_data[date_key]['orders'] += item['count']

    # Query specifically for transactions
    transactions = transactions_collection.aggregate([
        {
            '$match': {
                'user_id': user_id,
                'date': {'$gte': start_date, '$lt': end_date}
            }
        },
        {
            '$group': {
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$date'}},
                'count': {'$sum': 1}
            }
        }
    ])
    for item in transactions:
        date_key = item['_id']
        daily_data[date_key]['transactions'] += item['count']

    # Query specifically for products
    products = products_collection.aggregate([
        {
            '$match': {
                'user_id': user_id,
                'date': {'$gte': start_date, '$lt': end_date}
            }
        },
        {
            '$group': {
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$date'}},
                'count': {'$sum': 1}
            }
        }
    ])
    for item in products:
        date_key = item['_id']
        daily_data[date_key]['products'] += item['count']

    # Query specifically for active tasks
    active_tasks = tasks_collection.aggregate([
        {
            '$match': {
                'user_id': user_id,
                'date': {'$gte': start_date, '$lt': end_date},
                'status': {'$ne': 'Завершено'}
            }
        },
        {
            '$group': {
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$date'}},
                'count': {'$sum': 1}
            }
        }
    ])
    for item in active_tasks:
        date_key = item['_id']
        daily_data[date_key]['active_tasks'] += item['count']

    return daily_data


def calculate_sales_or_returns_info(user_id, start_date, end_date):
    filter_criteria = {
        'user_id': user_id,
        'date': {"$gte": start_date, "$lt": end_date},
        'status.status': {'$in': ['Оплачено', 'Повернено', 'Скасовано']}
    }
    documents = list(orders_collection.find(filter_criteria))

    sales_total_sum = returns_total_sum = canceled_total_sum = 0
    sales_count = returns_count = canceled_count = 0
    sales_daily_info = {}
    returns_daily_info = {}
    canceled_daily_info = {}

    for doc in documents:
        date_key = doc['date'].strftime('%Y-%m-%d')
        status = doc['status']['status']
        if status == 'Оплачено':
            sales_total_sum += doc['total_sum']
            sales_count += 1
            if date_key not in sales_daily_info:
                sales_daily_info[date_key] = {'total_sum': 0, 'count': 0}
            sales_daily_info[date_key]['total_sum'] += doc['total_sum']
            sales_daily_info[date_key]['count'] += 1
        elif status == 'Повернено':
            returns_total_sum += doc['total_sum']
            returns_count += 1
            if date_key not in returns_daily_info:
                returns_daily_info[date_key] = {'total_sum': 0, 'count': 0}
            returns_daily_info[date_key]['total_sum'] += doc['total_sum']
            returns_daily_info[date_key]['count'] += 1
        elif status == 'Скасовано':
            canceled_total_sum += doc['total_sum']
            canceled_count += 1
            if date_key not in canceled_daily_info:
                canceled_daily_info[date_key] = {'total_sum': 0, 'count': 0}
            canceled_daily_info[date_key]['total_sum'] += doc['total_sum']
            canceled_daily_info[date_key]['count'] += 1

    sales_average_check = sales_total_sum / sales_count if sales_count else 0
    returns_average_check = returns_total_sum / returns_count if returns_count else 0
    canceled_average_check = canceled_total_sum / canceled_count if canceled_count else 0

    return {
        'sales_total_sum': sales_total_sum,
        'sales_average_check': sales_average_check,
        'sales_amount': sales_count,
        'daily_sales_info': sales_daily_info,
        'returns_total_sum': returns_total_sum,
        'returns_average_check': returns_average_check,
        'returns_amount': returns_count,
        'daily_returns_info': returns_daily_info,
        'canceled_total_sum': canceled_total_sum,
        'canceled_average_check': canceled_average_check,
        'canceled_amount': canceled_count,
        'daily_canceled_info': canceled_daily_info
    }


def calculate_sales_info(user_id, start_date, end_date):
    return calculate_sales_or_returns_info(user_id, start_date, end_date)


def calculate_returns_info(user_id, start_date, end_date):
    return calculate_sales_or_returns_info(user_id, start_date, end_date)


def calculate_top_products(user_id, start_date, end_date, category=None):
    # Match stage to filter orders by user_id, date, and optionally by category within variations
    match_stage = {
        '$match': {
            'user_id': user_id,
            'date': {'$gte': start_date, '$lt': end_date},
            'status.status': 'Оплачено',  # Assuming you want to filter by paid orders
        }
    }

    # Unwind the variations array to treat each product as a separate document
    unwind_stage = {
        '$unwind': '$variations'
    }

    # Optional category match stage if a category is provided
    if category:
        category_match_stage = {
            '$match': {
                'variations.category': category
            }
        }
    else:
        category_match_stage = {}

    # Group stage to aggregate products, count their occurrences, and sum the amounts
    group_stage = {
        '$group': {
            '_id': {
                'product_name': '$variations.name',
                'product_category': '$variations.category',
            },
            'count': {'$sum': 1},
            'total_amount': {'$sum': '$variations.amount'}  # Sum the total amount sold for each product
        }
    }

    # Sort stage to order the results by count and total_amount (if you want to prioritize higher sales volume)
    sort_stage = {
        '$sort': {'count': -1, 'total_amount': -1}
    }

    # Limit stage to get the top 5 products
    limit_stage = {
        '$limit': 5
    }

    # Building the pipeline conditionally based on whether a category filter is applied
    pipeline = [match_stage, unwind_stage]
    if category:
        pipeline.append(category_match_stage)
    pipeline.extend([group_stage, sort_stage, limit_stage])

    # Execute the aggregation pipeline
    top_products = list(orders_collection.aggregate(pipeline))

    # Format results for readability
    formatted_results = [{
        'product_name': product['_id']['product_name'],
        'product_category': product['_id']['product_category'],
        'sold_count': product['count'],
        'total_amount': product['total_amount']
    } for product in top_products]

    return formatted_results


def calculate_purchase_segmentation(data, user_id):
    filter_criteria = {'user_id': user_id}
    for field in ['gender', 'variations.category']:
        key = f'purchase_segmentation_{field.split(".")[-1]}' # Adjust key to match input data
        value = data.get(key)
        if value:
            if 'gender' in field:
                filter_criteria['gender'] = {'$regex': f'.*{re.escape(value)}.*', '$options': 'i'}
            else:  # Handle category within variations
                filter_criteria['variations'] = {'$elemMatch': {'category': value}}

    documents = list(orders_collection.find(filter_criteria))
    purchase_segmentation_sum = sum(doc['total_sum'] for doc in documents)

    return {
        'purchase_segmentation_amount': len(documents),
        'purchase_segmentation_sum': purchase_segmentation_sum
    }


def get_mailing_history(data, user_id):
    mailing_type = data.get('mailing_type')
    page = data.get('page', 1)
    per_page = data.get('per_page', 10)

    filter_criteria = {'user_id': user_id}
    if mailing_type:
        filter_criteria['type'] = {'$regex': f'.*{re.escape(mailing_type)}.*', '$options': 'i'}

    total_documents = mailing_history_collection.count_documents(filter_criteria)
    documents = list(
        mailing_history_collection.find(filter_criteria)
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    # Convert ObjectIds to strings for JSON serialization
    for doc in documents:
        doc['_id'] = str(doc['_id'])

    return documents, total_documents


@application.route('/all_variations', methods=['POST'])
def all_variations():
    # Get data from request
    data = request.get_json()

    # Extract access token from data
    access_token = data.get('access_token')

    # Check if the access token is valid
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    # Decode user_id from access token
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Retrieve all products from the database
    products = products_collection.find({'user_id': user_id})

    # Initialize an empty list to store all variations
    all_variations = []

    # Iterate through each product
    for product in products:
        # Get product name and id
        product_name = product['name']
        product_id = str(product['_id'])

        # Iterate through each variation of the product
        for variation in product['variations']:
            # Add product name and id to the variation
            variation['product_name'] = product_name
            variation['product_id'] = product_id

            # Add the variation to the list of all variations
            all_variations.append(variation)

    # Return the list of all variations as JSON response
    return jsonify({'variations': all_variations}), 200


@application.route('/update_variation', methods=['POST'])
def update_variation():
    # Get data from request
    data = request.get_json()

    # Extract access token from data
    access_token = data.get('access_token')

    # Check if the access token is valid
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    # Decode user_id from access token
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Extract product ID, variation ID, and the parameters to update
    product_id = data.get('product_id')
    variation_id = data.get('variation_id')
    updates = data.get('updates')  # This should be a dictionary of the parameters to update

    # Validate required fields
    if not product_id or not variation_id or not updates:
        return jsonify({'message': False}), 400

    # Retrieve the specific product
    product = products_collection.find_one({'_id': ObjectId(product_id), 'user_id': user_id})

    if not product:
        return jsonify({'message': False}), 404

    # Find the variation to update
    variation_found = False
    for variation in product['variations']:
        if str(variation['_id']) == variation_id:
            # Update the necessary fields in the variation
            for key, value in updates.items():
                if key in ['cost_price', 'price', 'in_stock', 'recommended_balance_amount']:
                    variation[key] = value
            variation_found = True
            break

    if not variation_found:
        return jsonify({'message': False}), 404

    # Update the product in the database
    products_collection.update_one(
        {'_id': ObjectId(product_id), 'user_id': user_id},
        {'$set': {'variations': product['variations']}}
    )

    return jsonify({'message': True}), 200


@application.route('/settings', methods=['POST'])
def handle_settings():
    data = request.get_json()
    setting_type = data.get('setting_type')
    if setting_type == 'add':
        return add_setting(request)
    elif setting_type == 'view':
        return view_settings(request)
    elif setting_type == 'delete':
        return delete_setting(request)
    else:
        return jsonify({'message': False}), 405


def add_setting(request):
    data = request.get_json()
    access_token = data.get('access_token')

    # Check token validity
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Extract setting type from the request data
    data_type = data.get('data_type')

    # Extract setting data
    setting_data = data.get('data')
    setting_data['user_id'] = user_id

    # Handle different setting types
    collections_map = {
        'status': statuses_collection,
        'counterparty': counterparties_collection,
        'task_participant': task_participants_collection,
        'product_category': products_categories_collection,
        'subwarehouse': warehouses_collection,
        'shipping_method': shipping_methods_collection,
        'order_source': order_sources_collection,
        'payment_method': payment_methods_collection
    }

    # Insert setting data into the appropriate collection
    if data_type in collections_map:
        collection = collections_map[data_type]

        # Check if counterparty already exists
        if data_type == 'counterparty':
            counterparty_name = setting_data.get('name')
            existing_counterparty = collection.find_one({'name': counterparty_name, 'user_id': user_id})
            if existing_counterparty:
                return jsonify({'message': 'Counterparty already exists'}), 400

        collection.insert_one(setting_data)
        return jsonify({'message': True}), 200
    else:
        return jsonify({'message': False}), 400


def view_settings(request):
    data = request.get_json()
    access_token = data.get('access_token')

    # Check token validity
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Extract setting type from the request data
    data_type = data.get('data_type')

    # Handle different setting types
    collections_map = {
        'status': statuses_collection,
        'counterparty': counterparties_collection,
        'task_participant': task_participants_collection,
        'product_category': products_categories_collection,
        'subwarehouse': warehouses_collection,
        'shipping_method': shipping_methods_collection,
        'order_source': order_sources_collection,
        'payment_method': payment_methods_collection
    }

    # Retrieve settings data from the appropriate collection
    if data_type in collections_map:
        collection = collections_map[data_type]
        settings = list(collection.find({"$or": [{"user_id": user_id}, {"user_id": "0"}]}))
        for setting in settings:
            setting['_id'] = str(setting['_id'])
        return jsonify({'settings': settings}), 200
    else:
        return jsonify({'message': False}), 400


def delete_setting(request):
    data = request.get_json()
    access_token = data.get('access_token')

    # Check token validity
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    # Extract setting type and setting ID from the request data
    data_type = data.get('data_type')
    setting_id = data.get('setting_id')

    # Handle different setting types
    collections_map = {
        'status': statuses_collection,
        'counterparty': counterparties_collection,
        'task_participant': task_participants_collection,
        'product_category': products_categories_collection,
        'subwarehouse': warehouses_collection,
        'shipping_method': shipping_methods_collection,
        'order_source': order_sources_collection,
        'payment_method': payment_methods_collection
    }

    # Retrieve the appropriate collection based on the setting type
    if data_type in collections_map:
        collection = collections_map[data_type]

        # Delete the setting from the collection
        result = collection.delete_one({'_id': ObjectId(setting_id), 'user_id': user_id})

        # Check if the setting was successfully deleted
        if result.deleted_count == 1:
            return jsonify({'message': True}), 200
        else:
            return jsonify({'message': False}), 404
    else:
        return jsonify({'message': False}), 400


@application.route('/quick_action', methods=['POST'])
def quick_action():
    data = request.get_json()
    access_token = data.get('access_token')

    # Check token validity
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    document_type = data.get('document_type')
    action = data.get('action')
    document_ids = data.get('document_ids', [])

    # Convert document IDs to ObjectId
    document_ids = [ObjectId(doc_id) for doc_id in document_ids]

    # Map document types to their respective collections
    collections = {
        'clients': clients_collection,
        'tasks': tasks_collection,
        'finance': transactions_collection,
        'warehouses': products_collection,
        'orders': orders_collection
    }

    # Ensure valid document type
    if document_type not in collections:
        return jsonify({'message': False}), 400

    collection = collections[document_type]

    # Handle actions
    if action in ['delete']:
        delete_documents(collection, document_ids)
    elif action in ['change_status', 'change_comment', 'change_responsible', 'change_deadline', 'change_participants',
                    'change_cashier', 'change_counterpartie', 'change_sum', 'change_name', 'change_warehouse',
                    'change_subwarehouse', 'change_category', 'change_client', 'change_source', 'change_shipping',
                    'change_payment']:
        if action == 'change_status':
            status = data.get('status')
            type = data.get('type')
            status_doc = find_status_document(status, type)

            # Check for orders with status "Оплачено"
            if document_type == 'orders':
                paid_orders = list(collection.find({'_id': {'$in': document_ids}, 'status.status': 'Оплачено'}))
                if paid_orders:
                    paid_order_ids = [str(order['_id']) for order in paid_orders]
                    return jsonify({'error': 'Cannot change status of paid orders', 'ids': paid_order_ids}), 400

            update_documents(collection, document_ids, {'status': status_doc})
        elif action in ['change_comment', 'change_responsible', 'change_deadline', 'change_participants',
                        'change_cashier', 'change_counterpartie', 'change_name', 'change_warehouse',
                        'change_subwarehouse', 'change_category', 'change_source', 'change_shipping',
                        'change_payment']:
            update_field = action.split('_')[1]
            update_value = data.get(update_field)
            if action == 'change_deadline':
                update_value = datetime.strptime(update_value, "%a %b %d %Y")
            update_documents(collection, document_ids, {update_field: update_value})
        elif action == 'change_client':
            client = data.get('client')
            client_document = clients_collection.find_one({'name': client})
            update_documents(collection, document_ids,
                             {'client': client, 'email': client_document['email'], 'gender': client_document['gender']})
        elif action == 'change_sum':
            # Custom handling for changing sum with additional logic
            handle_change_sum(collection, document_ids, data.get('sum'))
    else:
        return jsonify({'message': False}), 400

    return jsonify({'message': True}), 200


def update_documents(collection, document_ids, update):
    """Update documents in a specified collection."""
    collection.update_many({'_id': {'$in': document_ids}}, {'$set': update})


def delete_documents(collection, document_ids):
    """Delete documents from a specified collection."""
    collection.delete_many({'_id': {'$in': document_ids}})


def find_status_document(status, type):
    """Find a status document and remove its ID."""
    status_doc = statuses_collection.find_one({'status': status, 'type': type})
    if status_doc:
        del status_doc['_id']
    return status_doc


def handle_change_sum(collection, document_ids, new_sum):
    """
    Update the sum for transactions and adjust the total_left accordingly.

    Args:
        collection: The MongoDB collection to operate on.
        document_ids: List of document IDs to update.
        new_sum: The new sum to apply to the transactions.
    """
    # Retrieve the current transactions to calculate the difference
    transactions_old = list(collection.find({'_id': {'$in': document_ids}}, {'sum': 1, 'total_left': 1}))

    # Update the transactions with the new sum
    update_result = collection.update_many({'_id': {'$in': document_ids}}, {'$set': {'sum': new_sum}})

    # Check if the transactions were successfully updated to proceed with adjustments
    if update_result.modified_count > 0:
        for transaction_old in transactions_old:
            # Calculate the difference between the old and new sums
            diff = transaction_old['sum'] - new_sum
            # Adjust the total_left by adding the difference
            # Assuming total_left is a field in the same document
            collection.update_one({'_id': transaction_old['_id']}, {'$inc': {'total_left': diff}})


@application.route('/add_loyalty', methods=['POST'])
def add_loyalty():
    data = request.get_json()
    access_token = data.get('access_token')

    # Check token validity
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    date = datetime.strptime(data.get('date'), "%a %b %d %Y")
    discount = data.get('discount')
    category = data.get('category')

    document = {'date': date,
                'discount': discount,
                'category': category,
                'user_id': user_id}

    loyalty_collection.insert_one(document)

    notification = {'text': f'Знижка {discount}% на {category} почне діяти {date}',
                    'user_id': user_id,
                    'date': datetime.now(),
                    'type': 'loyalty'}
    notifications_collection.insert_one(notification)

    return jsonify({'message': True}), 200


@application.route('/loyalty', methods=['POST'])
def loyalty():
    data = request.get_json()
    access_token = data.get('access_token')

    # Check token validity
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    loyalty = list(loyalty_collection.find({'user_id': user_id}))
    for document in loyalty:
        document['_id'] = str(document['_id'])

    return jsonify({'loyalty': loyalty}), 200


@application.route('/delete_loyalty', methods=['POST'])
def delete_loyalty():
    data = request.get_json()
    access_token = data.get('access_token')

    # Check token validity
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

    loyalty_id = data.get('loyalty_id')

    loyalty = loyalty_collection.find_one({'_id': ObjectId(loyalty_id)})

    loyalty_collection.delete_one({'_id': ObjectId(loyalty_id)})

    notification = {'text': f'Знижку {loyalty["discount"]}% на {loyalty["category"]} {loyalty["date"]} видалено',
                    'user_id': user_id,
                    'date': datetime.now(),
                    'type': 'loyalty'}
    notifications_collection.insert_one(notification)

    return jsonify({'message': True}), 200


@application.route('/archive_cashier', methods=['POST'])
def archive_cashier():
    data = request.get_json()
    access_token = data.get('access_token')

    if not check_token(access_token):
        return jsonify ({'token': False}), 401

    cashier_id = data.get('cashier_id')
    archive = data.get('archive', True)

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    cashier = cashiers_collection.find_one({'_id': ObjectId(cashier_id)})
    cashiers_collection.find_one_and_update(cashier,
                                            {'$set': {'archived': archive}})
    transactions = transactions_collection.find({'user_id': user_id, 'cashier': cashier['name']})
    for transaction in transactions:
        transactions_collection.find_one_and_update(transaction, {'$set': {'archived': archive}})

    return jsonify({'message': True}), 200


@application.route('/profile', methods=['POST'])
def profile():
    data = request.get_json()
    access_token = data.get('access_token')

    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    user['_id'] = str(user['_id'])
    try:
        user['subscription_end'] = datetime.strftime(user['subscription_end'], "%a %b %d %Y")
    except KeyError:
        pass

    return jsonify({'user': user}), 200


@application.route('/update_user', methods=['POST'])
def update_user():
    data = request.get_json()
    access_token = data.get('access_token')
    if not check_token(access_token):
        return jsonify({'token': False}), 401

    user_id = data.get('user_id')
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if user is None:
        return jsonify({'message': False}), 404

    # Update user fields based on the provided data
    user['name'] = data.get('name', user['name'])
    user['phone'] = data.get('phone', user['phone'])
    user['email'] = data.get('email', user['email'])
    user['userpic'] = data.get('userpic', user['userpic'])

    # Update the user in the database
    users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': user})
    return jsonify({'message': True}), 200


@application.route('/notifications', methods=['POST'])
def notifications():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {'user_id': user_id}

    # Count the total number of clients that match the filter criteria
    total_notifications = notifications_collection.count_documents(filter_criteria)

    total_pages = math.ceil(total_notifications / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(notifications_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_notifications)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'notifications': documents, 'total_notifications': total_notifications, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/hourly_analytics', methods=['POST'])
def hourly_analytics():
    data = request.get_json() or {}
    access_token = data.get('access_token')

    if not check_token(access_token):
        return jsonify({'error': 'Invalid token'}), 401

    try:
        user_id = decode_access_token(access_token, SECRET_KEY).get('user_id')

        date_str = data.get('date', '')
        selected_date = datetime.strptime(date_str, "%a %b %d %Y")
        start_date = selected_date
        end_date = selected_date + timedelta(days=1)
    except (TypeError, ValueError) as e:
        response_data = {
            'sales_info': None,
            'returns_info': None,
            'top_products': None,
            'purchase_segmentation': None,
            'hourly_analytics': None
        }
        return jsonify(response_data), 200

    sales_info = calculate_sales_info_hourly(user_id, start_date, end_date)
    returns_info = calculate_returns_info_hourly(user_id, start_date, end_date)
    top_products = calculate_top_products_hourly(user_id, start_date, end_date, data.get('product_category'))
    purchase_segmentation = calculate_purchase_segmentation_hourly(data, user_id)
    hourly_analytics = calculate_hourly_tasks_transactions_orders_sales(start_date, end_date, user_id)

    response_data = {
        **sales_info,
        **returns_info,
        'top_products': top_products,
        **purchase_segmentation,
        'hourly_analytics': hourly_analytics
    }

    return jsonify(response_data), 200

def calculate_sales_or_returns_info_hourly(user_id, start_date, end_date):
    filter_criteria = {
        'user_id': user_id,
        'date': {"$gte": start_date, "$lt": end_date},
        'status.status': {'$in': ['Оплачено', 'Повернено', 'Скасовано']}
    }
    documents = list(orders_collection.find(filter_criteria))

    sales_total_sum = returns_total_sum = canceled_total_sum = 0
    sales_count = returns_count = canceled_count = 0
    sales_hourly_info = {}
    returns_hourly_info = {}
    canceled_hourly_info = {}

    for doc in documents:
        hour_key = doc['date'].strftime('%H:00')
        status = doc['status']['status']
        if status == 'Оплачено':
            sales_total_sum += doc['total_sum']
            sales_count += 1
            if hour_key not in sales_hourly_info:
                sales_hourly_info[hour_key] = {'total_sum': 0, 'count': 0}
            sales_hourly_info[hour_key]['total_sum'] += doc['total_sum']
            sales_hourly_info[hour_key]['count'] += 1
        elif status == 'Повернено':
            returns_total_sum += doc['total_sum']
            returns_count += 1
            if hour_key not in returns_hourly_info:
                returns_hourly_info[hour_key] = {'total_sum': 0, 'count': 0}
            returns_hourly_info[hour_key]['total_sum'] += doc['total_sum']
            returns_hourly_info[hour_key]['count'] += 1
        elif status == 'Скасовано':
            canceled_total_sum += doc['total_sum']
            canceled_count += 1
            if hour_key not in canceled_hourly_info:
                canceled_hourly_info[hour_key] = {'total_sum': 0, 'count': 0}
            canceled_hourly_info[hour_key]['total_sum'] += doc['total_sum']
            canceled_hourly_info[hour_key]['count'] += 1

    sales_average_check = sales_total_sum / sales_count if sales_count else 0
    returns_average_check = returns_total_sum / returns_count if returns_count else 0
    canceled_average_check = canceled_total_sum / canceled_count if canceled_count else 0

    return {
        'sales_total_sum': sales_total_sum,
        'sales_average_check': sales_average_check,
        'sales_amount': sales_count,
        'hourly_sales_info': sales_hourly_info,
        'returns_total_sum': returns_total_sum,
        'returns_average_check': returns_average_check,
        'returns_amount': returns_count,
        'hourly_returns_info': returns_hourly_info,
        'canceled_total_sum': canceled_total_sum,
        'canceled_average_check': canceled_average_check,
        'canceled_amount': canceled_count,
        'hourly_canceled_info': canceled_hourly_info
    }

def calculate_sales_info_hourly(user_id, start_date, end_date):
    return calculate_sales_or_returns_info_hourly(user_id, start_date, end_date)

def calculate_returns_info_hourly(user_id, start_date, end_date):
    return calculate_sales_or_returns_info_hourly(user_id, start_date, end_date)

def calculate_top_products_hourly(user_id, start_date, end_date, category=None):
    match_stage = {
        '$match': {
            'user_id': user_id,
            'date': {'$gte': start_date, '$lt': end_date},
            'status.status': 'Оплачено',
        }
    }

    unwind_stage = {
        '$unwind': '$variations'
    }

    if category:
        category_match_stage = {
            '$match': {
                'variations.category': category
            }
        }
    else:
        category_match_stage = {}

    group_stage = {
        '$group': {
            '_id': {
                'product_name': '$variations.name',
                'product_category': '$variations.category',
                'hour': {'$hour': '$date'}
            },
            'count': {'$sum': 1},
            'total_amount': {'$sum': '$variations.amount'}
        }
    }

    sort_stage = {
        '$sort': {'_id.hour': 1, 'count': -1, 'total_amount': -1}
    }

    pipeline = [match_stage, unwind_stage]
    if category:
        pipeline.append(category_match_stage)
    pipeline.extend([group_stage, sort_stage])

    top_products = list(orders_collection.aggregate(pipeline))

    formatted_results = [{
        'hour': f'{product["_id"]["hour"]:02}:00',
        'product_name': product['_id']['product_name'],
        'product_category': product['_id']['product_category'],
        'sold_count': product['count'],
        'total_amount': product['total_amount']
    } for product in top_products]

    return formatted_results

def calculate_purchase_segmentation_hourly(data, user_id):
    filter_criteria = {'user_id': user_id}
    for field in ['gender', 'variations.category']:
        key = f'purchase_segmentation_{field.split(".")[-1]}'
        value = data.get(key)
        if value:
            if 'gender' in field:
                filter_criteria['gender'] = {'$regex': f'.*{re.escape(value)}.*', '$options': 'I'}
            else:
                filter_criteria['variations'] = {'$elemMatch': {'category': value}}

    documents = list(orders_collection.find(filter_criteria))
    purchase_segmentation_sum = sum(doc['total_sum'] for doc in documents)

    hourly_data = {}
    for hour in range(24):
        hourly_data[f'{hour:02}:00'] = {'purchase_segmentation_sum': 0, 'purchase_segmentation_amount': 0}

    for doc in documents:
        hour_key = doc['date'].strftime('%H:00')
        hourly_data[hour_key]['purchase_segmentation_sum'] += doc['total_sum']
        hourly_data[hour_key]['purchase_segmentation_amount'] += 1

    return hourly_data

def calculate_hourly_tasks_transactions_orders_sales(start_date, end_date, user_id):
    hourly_data = {}
    for hour in range(24):
        hourly_data[f'{hour:02}:00'] = {'orders': 0, 'sales': 0, 'active_tasks': 0, 'transactions': 0, 'products': 0}

    orders_and_sales = orders_collection.aggregate([
        {
            '$match': {
                'user_id': user_id,
                'date': {'$gte': start_date, '$lt': end_date}
            }
        },
        {
            '$group': {
                '_id': {
                    'hour': {'$hour': '$date'},
                    'status': '$status.status'
                },
                'count': {'$sum': 1}
            }
        }
    ])
    for item in orders_and_sales:
        hour_key = f'{item["_id"]["hour"]:02}:00'
        if item['_id']['status'] == 'Оплачено':
            hourly_data[hour_key]['sales'] += item['count']
        hourly_data[hour_key]['orders'] += item['count']

    transactions = transactions_collection.aggregate([
        {
            '$match': {
                'user_id': user_id,
                'date': {'$gte': start_date, '$lt': end_date}
            }
        },
        {
            '$group': {
                '_id': {'hour': {'$hour': '$date'}},
                'count': {'$sum': 1}
            }
        }
    ])
    for item in transactions:
        hour_key = f'{item["_id"]["hour"]:02}:00'
        hourly_data[hour_key]['transactions'] += item['count']

    active_tasks = tasks_collection.aggregate([
        {
            '$match': {
                'user_id': user_id,
                'date': {'$gte': start_date, '$lt': end_date},
            }
        },
        {
            '$group': {
                '_id': {'hour': {'$hour': '$date'}},
                'count': {'$sum': 1}
            }
        }
    ])
    for item in active_tasks:
        hour_key = f'{item["_id"]["hour"]:02}:00'
        hourly_data[hour_key]['active_tasks'] += item['count']

    products = products_collection.aggregate([
        {
            '$match': {
                'user_id': user_id,
                'date': {'$gte': start_date, '$lt': end_date}
            }
        },
        {
            '$group': {
                '_id': {'hour': {'$hour': '$date'}},
                'count': {'$sum': 1}
            }
        }
    ])
    for item in products:
        hour_key = f'{item["_id"]["hour"]:02}:00'
        hourly_data[hour_key]['products'] += item['count']

    return hourly_data


if __name__ == '__main__':
    application.run(port=8000)
