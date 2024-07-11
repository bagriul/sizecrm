from apscheduler.schedulers.background import BackgroundScheduler
from flask_mail import Mail, Message
from flask import Flask
from datetime import datetime, timedelta
from pymongo import MongoClient
import config

# Initialize Flask app
application = Flask(__name__)

# Configure Flask-Mail
application.config['MAIL_SERVER'] = 'smtp.gmail.com'
application.config['MAIL_PORT'] = 465  # Use your mail server's port
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USE_SSL'] = True
application.config['MAIL_USERNAME'] = 'size.crm@gmail.com'
application.config['MAIL_PASSWORD'] = 'wchg bcif xkkr oqga'
application.config['MAIL_DEFAULT_SENDER'] = 'size.crm@gmail.com'

mail = Mail(application)

# Configure MongoDB connection
client = MongoClient(config.MONGO_STRING)
db = client['size_crm']
tasks_collection = db['tasks']

def send_email_reminder(task):
    msg = Message(f'Reminder: Task "{task["headline"]}" is due tomorrow',
                  recipients=[task['responsible']['email']])
    msg.body = f'Hello {task["responsible"]["name"]},\n\nThis is a reminder that the task "{task["headline"]}" is due tomorrow.\n\nBest regards,\nYour Team'
    with application.app_context():
        mail.send(msg)

def check_deadlines():
    tomorrow = datetime.now() + timedelta(days=1)
    tasks = tasks_collection.find({'deadline': {'$lte': tomorrow}})
    for task in tasks:
        send_email_reminder(task)

scheduler = BackgroundScheduler()
scheduler.add_job(check_deadlines, 'interval', hours=24)

def start_scheduler():
    scheduler.start()

if __name__ == '__main__':
    start_scheduler()