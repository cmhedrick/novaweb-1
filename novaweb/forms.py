from novaweb.model import *
from flask_wtf import Form
from wtforms import FormField, FieldList, BooleanField, TextField, PasswordField, SelectField, validators
from wtforms.ext.sqlalchemy.fields import QuerySelectField

class LoginForm(Form):
  username = TextField('username', [validators.Required()])
  password = PasswordField('password')
