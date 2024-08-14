from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from app.models import User


class LoginForm(FlaskForm):
    username = StringField('Username:', validators=[DataRequired()])
    password = PasswordField('Password:', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    username = StringField('Username:', validators=[DataRequired()])
    password = PasswordField('Password:', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password:', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_confirm_password(self, confirm_password):
        if confirm_password.data != self.password.data:
            raise ValidationError('Passwords must match.')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

### CHALLENGES ###

class ChallengeForm(FlaskForm):
    text = StringField('Enter your decoded message:', validators=[DataRequired()])
    submit = SubmitField('Submit')


class KillSwitchForm(FlaskForm):
    text = StringField('Enter the Killswitch Code:', validators=[DataRequired()])
    submit = SubmitField('Submit')

class DatabaseReset(FlaskForm):
    text = StringField('Database reset password:', validators=[DataRequired()])
    submit = SubmitField('Submit')