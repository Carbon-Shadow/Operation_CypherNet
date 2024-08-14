from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)
app.config.from_object('app.config')

db = SQLAlchemy(app)  # Initialize SQLAlchemy with the Flask app
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from app import routes # Import routes at the end to avoid circular imports