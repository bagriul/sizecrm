import config
from flask import Flask, request, Response, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import jwt
from bson import json_util, ObjectId
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import json
import math
from gridfs import GridFS
import re
import boto3
from botocore.client import Config
import io
from botocore.exceptions import ClientError
import uuid


application = Flask(__name__)
CORS(application)
application.config['SECRET_KEY'] = config.SECRET_KEY
SECRET_KEY = config.SECRET_KEY
client = MongoClient(config.MONGO_STRING)
db = client['olimpia_crm']
users_collection = db['users']
statuses_collection = db['statuses']
tasks_collection = db['tasks']
contracts_collection = db['contracts']
merchants_reports_collection = db['merchants_reports']
clients_collection = db['clients']
orders_collection = db['orders']

bcrypt = Bcrypt(application)


@application.route('/', methods=['GET'])
def test():
    return 'OlimpiaCRM API v1.0'


def decode_access_token(access_token, secret_key):
    try:
        payload = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        print(payload)
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
                return jsonify({'name': name}), 200
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
                return jsonify({'name': name}), 200
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

    # Check if the user exists in the database
    user = users_collection.find_one({'email': email})

    if user:
        hashed_password_in_db = user.get('password', '')  # Assuming the field name is 'password'

        if bcrypt.check_password_hash(hashed_password_in_db, password):
            user_id = str(user['_id'])  # Assuming user ID is stored as ObjectId in MongoDB

            # Generate tokens based on user ID
            access_token = jwt.encode(
                {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                application.config['SECRET_KEY'], algorithm='HS256')
            refresh_token = jwt.encode(
                {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(days=1)},
                application.config['SECRET_KEY'], algorithm='HS256')

            response = jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
            return response

    response = jsonify({'message': 'Invalid credentials'}), 401
    return response


# Endpoint for user registration
@application.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # Hash the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    document = {
        'name': name,
        'email': email,
        'password': hashed_password
    }

    is_present = users_collection.find_one({'email': email})

    if (is_present is None) and (bcrypt.check_password_hash(hashed_password, password)):
        users_collection.insert_one(document)
        response = jsonify({'message': True}), 200
        return response
    else:
        response = jsonify({'message': False}), 401
        return response


@application.route('/add_task', methods=['POST'])
def add_task():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    headline = data.get('headline')
    responsible = data.get('responsible')
    deadline = data.get('deadline')
    description = data.get('description')
    status = data.get('status', None)
    if status:
        status_doc = statuses_collection.find_one({'status': status})
        if status_doc:
            del status_doc['_id']

    # Get today's date
    today = datetime.today()
    # Format the date
    formatted_date = today.strftime("%a %b %d %Y")

    document = {'date': formatted_date,
                'headline': headline,
                'responsible': responsible,
                'deadline': deadline,
                'description': description,
                'status': status_doc}
    tasks_collection.insert_one(document)
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
    task['responsible'] = data.get('responsible', task['responsible'])
    task['deadline'] = data.get('deadline', task['deadline'])
    task['description'] = data.get('description', task['description'])
    status = data.get('status')
    if status:
        status_doc = statuses_collection.find_one({'status': status})
        if status_doc:
            del status_doc['_id']
        task['status'] = status_doc

    # Update the task in the database
    tasks_collection.update_one({'_id': ObjectId(task_id)}, {'$set': task})
    return jsonify({'message': True}), 200


@application.route('/delete_task', methods=['POST'])
def delete_task():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    task_ids = data.get('task_ids')
    for task_id in task_ids:
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
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {}
    if keyword:
        tasks_collection.create_index([("$**", "text")])
        filter_criteria['$text'] = {'$search': keyword}

    # Count the total number of clients that match the filter criteria
    total_tasks = tasks_collection.count_documents(filter_criteria)

    total_pages = math.ceil(total_tasks / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(tasks_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_tasks)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'tasks': documents, 'total_tasks': total_tasks, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response


# Endpoint to create new client status
@application.route('/new_status', methods=['POST'])
def new_status():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    status = data.get('status')
    colour = data.get('colour')
    type = data.get('type')
    is_present = statuses_collection.find_one({'status': status, 'type': type})
    if is_present is None:
        statuses_collection.insert_one({'status': status, 'colour': colour, 'type': type})
        return jsonify({'message': 'Created successfully'}), 200
    else:
        return jsonify({'message': 'Status already exists'}), 409


@application.route('/get_statuses', methods=['POST'])
def get_statuses():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    type = data.get('type')
    filter_criteria = {}
    if type:
        statuses_collection.create_index([("$**", "text")])
        filter_criteria['$text'] = {'$search': type}

    # Retrieve specific fields from all documents in the collection
    documents = list(statuses_collection.find(filter_criteria))
    for document in documents:
        document['_id'] = str(document['_id'])

    response = Response(json_util.dumps(
        {'statuses': documents},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response, 200


@application.route('/users', methods=['POST'])
def users():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {}
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


@application.route('/add_contract', methods=['POST'])
def add_contract():
    data = request.form
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    number = data.get('number')
    counterpartie = data.get('counterpartie')
    category = data.get('category')
    date = data.get('date')
    deadline = data.get('deadline')
    subject = data.get('subject')
    status = data.get('status', None)
    if status:
        status_doc = statuses_collection.find_one({'status': status})
        if status_doc:
            del status_doc['_id']
    scans = request.files.getlist('scans')

    document = {'date': date,
                'number': number,
                'counterpartie': counterpartie,
                'category': category,
                'deadline': deadline,
                'subject': subject,
                'status': status_doc}
    scans_links_list = []
    for scan in scans:
        # Create an in-memory file-like object
        file_stream = io.BytesIO()
        scan.save(file_stream)
        file_stream.seek(0)

        def generate_unique_filename(original_filename):
            # Get current timestamp
            current_timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')[:-3]

            # Generate a unique identifier (UUID)
            unique_identifier = str(uuid.uuid4())

            # Extract the file extension from the original filename
            file_extension = original_filename.rsplit('.', 1)[-1].lower()

            # Combine timestamp, unique identifier, and file extension to create a unique filename
            unique_filename = f"{current_timestamp}_{unique_identifier}.{file_extension}"

            return unique_filename

        unique_filename = generate_unique_filename(scan.filename)

        # Upload the file directly to S3
        config.s3_client.upload_fileobj(file_stream, 'olimpiabucket', f'contracts/{unique_filename}', ExtraArgs={'ACL': 'public-read'})
        scans_links_list.append(f'https://olimpiabucket.fra1.digitaloceanspaces.com/contracts/{unique_filename}')

    document['scans_links'] = scans_links_list
    contracts_collection.insert_one(document)
    return jsonify({'message': True}), 200


@application.route('/update_contract', methods=['POST'])
def update_contract():
    data = request.form
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    contract_id = data.get('contract_id')
    contract = contracts_collection.find_one({'_id': ObjectId(contract_id)})
    if contract is None:
        return jsonify({'message': False}), 404

    # Update task fields based on the provided data
    contract['date'] = data.get('date', contract['date'])
    contract['number'] = data.get('number', contract['number'])
    contract['counterpartie'] = data.get('counterpartie', contract['counterpartie'])
    contract['category'] = data.get('category', contract['category'])
    contract['deadline'] = data.get('deadline', contract['deadline'])
    contract['subject'] = data.get('subject', contract['subject'])
    status = data.get('status')
    if status:
        status_doc = statuses_collection.find_one({'status': status})
        if status_doc:
            del status_doc['_id']
        contract['status'] = status_doc
    contracts_collection.update_one({'_id': ObjectId(contract_id)}, {'$set': contract})

    delete_scans = data.get('delete_scans')
    scans = request.files.getlist('scans')

    if delete_scans:
        # Delete files not in new scans_links but present in old contract['scans_links']
        for scan_link in contract['scans_links']:
            if scan_link in delete_scans:
                # Extract file key from the old_scan_link
                file_key = scan_link.split('/')[-1]
                config.s3_client.delete_object(Bucket='olimpiabucket', Key=f'contracts/{file_key}')
                contracts_collection.find_one_and_update({'_id': ObjectId(contract_id)},
                                                         {"$pull": {"scans_links": f"https://olimpiabucket.fra1.digitaloceanspaces.com/contracts/{file_key}"}})

    if scans:
        for scan in scans:
            # Create an in-memory file-like object
            file_stream = io.BytesIO()
            scan.save(file_stream)
            file_stream.seek(0)

            def generate_unique_filename(original_filename):
                # Get current timestamp
                current_timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')[:-3]

                # Generate a unique identifier (UUID)
                unique_identifier = str(uuid.uuid4())

                # Extract the file extension from the original filename
                file_extension = original_filename.rsplit('.', 1)[-1].lower()

                # Combine timestamp, unique identifier, and file extension to create a unique filename
                unique_filename = f"{current_timestamp}_{unique_identifier}.{file_extension}"

                return unique_filename

            unique_filename = generate_unique_filename(scan.filename)

            # Upload the file directly to S3
            config.s3_client.upload_fileobj(file_stream, 'olimpiabucket', f'contracts/{unique_filename}', ExtraArgs={'ACL': 'public-read'})
            contracts_collection.find_one_and_update({'_id': ObjectId(contract_id)},
                                                     {"$push": {"scans_links": f"https://olimpiabucket.fra1.digitaloceanspaces.com/contracts/{unique_filename}"}})

    return jsonify({'message': True}), 200


@application.route('/delete_contract', methods=['POST'])
def delete_contract():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    contract_ids = data.get('contract_ids')
    for contract_id in contract_ids:
        contracts_collection.find_one_and_delete({'_id': ObjectId(contract_id)})
    return jsonify({'message': True}), 200


@application.route('/contract_info', methods=['POST'])
def contract_info():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    contract_id = data.get('contract_id')
    object_id = ObjectId(contract_id)
    contract_document = contracts_collection.find_one({'_id': object_id})

    if contract_document:
        # Convert ObjectId to string before returning the response
        contract_document['_id'] = str(contract_document['_id'])

        # Use dumps() to handle ObjectId serialization
        return json.dumps(contract_document, default=str), 200, {'Content-Type': 'application/json'}
    else:
        response = jsonify({'message': 'Contract not found'}), 404
        return response


@application.route('/contracts', methods=['POST'])
def contracts():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {}
    if keyword:
        contracts_collection.create_index([("$**", "text")])
        filter_criteria['$text'] = {'$search': keyword}

    # Count the total number of clients that match the filter criteria
    total_contracts = contracts_collection.count_documents(filter_criteria)

    total_pages = math.ceil(total_contracts / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(contracts_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_contracts)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'contracts': documents, 'total_contracts': total_contracts, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response


@application.route('/merchants_reports', methods=['POST'])
def merchants_reports():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {}
    if keyword:
        merchants_reports_collection.create_index([("$**", "text")])
        filter_criteria['$text'] = {'$search': keyword}

    # Count the total number of clients that match the filter criteria
    total_reports = merchants_reports_collection.count_documents(filter_criteria)

    total_pages = math.ceil(total_reports / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(merchants_reports_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_reports)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'reports': documents, 'total_reports': total_reports, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response


@application.route('/merchants_reports_update', methods=['POST'])
def merchants_reports_update():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    report_id = data.get('report_id')
    report = merchants_reports_collection.find_one({'_id': ObjectId(report_id)})
    if report is None:
        return jsonify({'message': False}), 404

    # Update task fields based on the provided data
    report['shop_name'] = data.get('shop_name', report['shop_name'])
    report['product_name'] = data.get('product_name', report['product_name'])
    report['product_amount'] = data.get('product_amount', report['product_amount'])
    report['sale_amount'] = data.get('sale_amount', report['sale_amount'])
    report['photo'] = data.get('photo', report['photo'])

    # Update the task in the database
    merchants_reports_collection.update_one({'_id': ObjectId(report_id)}, {'$set': report})
    return jsonify({'message': True}), 200


@application.route('/merchants_reports_delete', methods=['POST'])
def merchants_reports_delete():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    reports_ids = data.get('reports_ids')
    for report_id in reports_ids:
        merchants_reports_collection.find_one_and_delete({'_id': ObjectId(report_id)})
    return jsonify({'message': True}), 200


@application.route('/merchant_report_info', methods=['POST'])
def merchant_report_info():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    report_id = data.get('report_id')
    object_id = ObjectId(report_id)
    report_document = merchants_reports_collection.find_one({'_id': object_id})

    if report_document:
        # Convert ObjectId to string before returning the response
        report_document['_id'] = str(report_document['_id'])

        # Use dumps() to handle ObjectId serialization
        return json.dumps(report_document, default=str), 200, {'Content-Type': 'application/json'}
    else:
        response = jsonify({'message': 'Report not found'}), 404
        return response


@application.route('/add_client', methods=['POST'])
def add_client():
    data = request.form
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    name = data.get('name')
    edrpou = data.get('edrpou')
    ipn = data.get('ipn')
    bank = data.get('bank')
    account_number = data.get('account_number')
    address_jur = data.get('address_jur')
    address_phiz = data.get('address_phiz')
    address_sklad = data.get('address_sklad')
    pib_kerivnyka = data.get('pib_kerivnyka')
    pib_kontaktna = data.get('pib_kontaktna')
    number = data.get('number')
    email = data.get('email')
    supervisors = data.get('supervisors')
    if supervisors:
        supervisors = json.loads(supervisors)
    contracts = request.files.getlist('contracts')
    payment_terms_and_conditions = data.get('payment_terms_and_conditions')

    document = {'name': name,
                'edrpou': edrpou,
                'ipn': ipn,
                'bank': bank,
                'account_number': account_number,
                'address_jur': address_jur,
                'address_phiz': address_phiz,
                'address_sklad': address_sklad,
                'pib_kerivnyka': pib_kerivnyka,
                'pib_kontaktna': pib_kontaktna,
                'number': number,
                'email': email,
                'supervisors': supervisors,
                'payment_terms_and_conditions': payment_terms_and_conditions}

    contracts_links_list = []
    for contract in contracts:
        # Create an in-memory file-like object
        file_stream = io.BytesIO()
        contract.save(file_stream)
        file_stream.seek(0)

        def generate_unique_filename(original_filename):
            # Get current timestamp
            current_timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')[:-3]

            # Generate a unique identifier (UUID)
            unique_identifier = str(uuid.uuid4())

            # Extract the file extension from the original filename
            file_extension = original_filename.rsplit('.', 1)[-1].lower()

            # Combine timestamp, unique identifier, and file extension to create a unique filename
            unique_filename = f"{current_timestamp}_{unique_identifier}.{file_extension}"

            return unique_filename

        unique_filename = generate_unique_filename(contract.filename)

        # Upload the file directly to S3
        config.s3_client.upload_fileobj(file_stream, 'olimpiabucket', f'contracts_clients/{unique_filename}',
                                        ExtraArgs={'ACL': 'public-read'})
        contracts_links_list.append(f'https://olimpiabucket.fra1.digitaloceanspaces.com/contracts_clients/{unique_filename}')

    document['contracts_links'] = contracts_links_list

    clients_collection.insert_one(document)
    return jsonify({'message': True}), 200


@application.route('/update_client', methods=['POST'])
def update_client():
    data = request.form
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    client_id = data.get('client_id')
    client = clients_collection.find_one({'_id': ObjectId(client_id)})
    if client is None:
        return jsonify({'message': False}), 404

    # Update task fields based on the provided data
    client['name'] = data.get('name', client['name'])
    client['edrpou'] = data.get('edrpou', client['edrpou'])
    client['ipn'] = data.get('ipn', client['ipn'])
    client['bank'] = data.get('bank', client['bank'])
    client['account_number'] = data.get('account_number', client['account_number'])
    client['address_jur'] = data.get('address_jur', client['address_jur'])
    client['address_phiz'] = data.get('address_phiz', client['address_phiz'])
    client['address_sklad'] = data.get('address_sklad', client['address_sklad'])
    client['pib_kerivnyka'] = data.get('pib_kerivnyka', client['pib_kerivnyka'])
    client['pib_kontaktna'] = data.get('pib_kontaktna', client['pib_kontaktna'])
    client['number'] = data.get('number', client['number'])
    client['email'] = data.get('email', client['email'])
    client['supervisors'] = json.loads(data.get('supervisors', client['supervisors']))
    client['payment_terms_and_conditions'] = data.get('payment_terms_and_conditions', client['payment_terms_and_conditions'])
    clients_collection.update_one({'_id': ObjectId(client_id)}, {'$set': client})

    delete_contracts = data.get('delete_contracts')
    contracts = request.files.getlist('contracts')

    if delete_contracts:
        # Delete files not in new scans_links but present in old contract['scans_links']
        for contract_link in client['contracts_links']:
            if contract_link in delete_contracts:
                # Extract file key from the old_scan_link
                file_key = contract_link.split('/')[-1]
                config.s3_client.delete_object(Bucket='olimpiabucket', Key=f'contracts_clients/{file_key}')
                clients_collection.find_one_and_update({'_id': ObjectId(client_id)},
                                                         {"$pull": {"contracts_links": f"https://olimpiabucket.fra1.digitaloceanspaces.com/contracts/{file_key}"}})

    if contracts:
        for contract in contracts:
            # Create an in-memory file-like object
            file_stream = io.BytesIO()
            contract.save(file_stream)
            file_stream.seek(0)

            def generate_unique_filename(original_filename):
                # Get current timestamp
                current_timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')[:-3]

                # Generate a unique identifier (UUID)
                unique_identifier = str(uuid.uuid4())

                # Extract the file extension from the original filename
                file_extension = original_filename.rsplit('.', 1)[-1].lower()

                # Combine timestamp, unique identifier, and file extension to create a unique filename
                unique_filename = f"{current_timestamp}_{unique_identifier}.{file_extension}"

                return unique_filename

            unique_filename = generate_unique_filename(contract.filename)

            # Upload the file directly to S3
            config.s3_client.upload_fileobj(file_stream, 'olimpiabucket', f'contracts_clients/{unique_filename}', ExtraArgs={'ACL': 'public-read'})
            clients_collection.find_one_and_update({'_id': ObjectId(client_id)},
                                                     {"$push": {"contracts_links": f"https://olimpiabucket.fra1.digitaloceanspaces.com/contracts/{unique_filename}"}})

    return jsonify({'message': True}), 200


@application.route('/delete_client', methods=['POST'])
def delete_client():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    clients_ids = data.get('clients_ids')
    for client_id in clients_ids:
        clients_collection.find_one_and_delete({'_id': ObjectId(client_id)})
    return jsonify({'message': True}), 200


@application.route('/client_info', methods=['POST'])
def client_info():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    client_id = data.get('client_id')
    object_id = ObjectId(client_id)
    client_document = clients_collection.find_one({'_id': object_id})

    if client_document:
        # Convert ObjectId to string before returning the response
        client_document['_id'] = str(client_document['_id'])

        # Use dumps() to handle ObjectId serialization
        return json.dumps(client_document, default=str), 200, {'Content-Type': 'application/json'}
    else:
        response = jsonify({'message': 'Client not found'}), 404
        return response


@application.route('/clients', methods=['POST'])
def clients():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {}
    if keyword:
        clients_collection.create_index([("$**", "text")])
        filter_criteria['$text'] = {'$search': keyword}

    # Count the total number of clients that match the filter criteria
    total_clients = clients_collection.count_documents(filter_criteria)

    total_pages = math.ceil(total_clients / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(clients_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_clients)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'clients': documents, 'total_clients': total_clients, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response


@application.route('/update_order', methods=['POST'])
def update_order():
    data = request.form
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    order_id = data.get('order_id')
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    if order is None:
        return jsonify({'message': False}), 404

    # Update task fields based on the provided data
    order['sales_agent'] = data.get('sales_agent', order['sales_agent'])
    order['distributor'] = data.get('distributor', order['distributor'])
    order['shop'] = data.get('shop', order['shop'])
    order['products'] = data.get('products', order['products'])
    order['status'] = data.get('status', order['status'])
    order['photos'] = data.get('photos', order['photos'])
    orders_collection.update_one({'_id': ObjectId(order_id)}, {'$set': order})

    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    total_amount = 0
    total_amount_discount = 0
    for product in order['products']:
        if product['discount'] == '0':
            total_amount += int(product['amount'])
        elif product['discount'] != '0':
            total_amount_discount += int(product['amount'])
    order['total_amount'] = total_amount
    order['total_amount_discount'] = total_amount_discount
    orders_collection.update_one({'_id': ObjectId(order_id)}, {'$set': order})
    return jsonify({'message': True}), 200


@application.route('/delete_order', methods=['POST'])
def delete_order():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    orders_ids = data.get('orders_ids')
    for order_id in orders_ids:
        orders_collection.find_one_and_delete({'_id': ObjectId(order_id)})
    return jsonify({'message': True}), 200


@application.route('/order_info', methods=['POST'])
def order_info():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401

    order_id = data.get('order_id')
    object_id = ObjectId(order_id)
    order_document = orders_collection.find_one({'_id': object_id})

    if order_document:
        # Convert ObjectId to string before returning the response
        order_document['_id'] = str(order_document['_id'])

        # Use dumps() to handle ObjectId serialization
        return json.dumps(order_document, default=str), 200, {'Content-Type': 'application/json'}
    else:
        response = jsonify({'message': 'Order not found'}), 404
        return response


@application.route('/orders', methods=['POST'])
def orders():
    data = request.get_json()
    access_token = data.get('access_token')
    if check_token(access_token) is False:
        return jsonify({'token': False}), 401
    keyword = data.get('keyword')
    page = data.get('page', 1)  # Default to page 1 if not provided
    per_page = data.get('per_page', 10)  # Default to 10 items per page if not provided

    filter_criteria = {}
    if keyword:
        orders_collection.create_index([("$**", "text")])
        filter_criteria['$text'] = {'$search': keyword}

    # Count the total number of clients that match the filter criteria
    total_orders = orders_collection.count_documents(filter_criteria)

    total_pages = math.ceil(total_orders / per_page)

    # Paginate the query results using skip and limit, and apply filters
    skip = (page - 1) * per_page
    documents = list(orders_collection.find(filter_criteria).skip(skip).limit(per_page))
    for document in documents:
        document['_id'] = str(document['_id'])

    # Calculate the range of clients being displayed
    start_range = skip + 1
    end_range = min(skip + per_page, total_orders)

    # Serialize the documents using json_util from pymongo and specify encoding
    response = Response(json_util.dumps(
        {'orders': documents, 'total_orders': total_orders, 'start_range': start_range, 'end_range': end_range,
         'total_pages': total_pages},
        ensure_ascii=False).encode('utf-8'),
                        content_type='application/json;charset=utf-8')
    return response


if __name__ == '__main__':
    application.run()
