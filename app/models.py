from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from app import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    total_challenges_completed = db.Column(db.Integer, default=0)
    challenge1_completed = db.Column(db.Boolean, default=False)
    challenge2_completed = db.Column(db.Boolean, default=False)
    challenge3_completed = db.Column(db.Boolean, default=False)
    challenge4_completed = db.Column(db.Boolean, default=False)
    challenge5_completed = db.Column(db.Boolean, default=False)
    challenge6_completed = db.Column(db.Boolean, default=False)
    challenge7_completed = db.Column(db.Boolean, default=False)
    challenge8_completed = db.Column(db.Boolean, default=False)
    challenge9_completed = db.Column(db.Boolean, default=False)
    challenge10_completed = db.Column(db.Boolean, default=False)
    challenge11_completed = db.Column(db.Boolean, default=False)
    challenge12_completed = db.Column(db.Boolean, default=False)
    killswitch_activated = db.Column(db.Boolean, default=False)
    time_taken = db.Column(db.String(150))