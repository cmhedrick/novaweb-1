from novaweb.model import *
from flask_wtf import Form
from wtforms import fields, FormField, FieldList, BooleanField, TextField, TextAreaField, PasswordField, SelectField, validators
from wtforms.ext.sqlalchemy.fields import QuerySelectField

class LoginForm(Form):
  username = TextField('username', [validators.Required()])
  password = PasswordField('password')

class AddUser(Form):
  name = TextField('Name')
  email = TextField('E-mail')
  username = TextField('Username', [validators.Required()])
  password = PasswordField('Password')
  password2 = PasswordField('Confirm password')

class AddGroup(Form):
  name = TextField('Group Name')

class AddCustomer(Form):
  name = TextField("Customer Name")
  email = TextField("Customer E-Mail")
  contract = TextAreaField("Contract")
