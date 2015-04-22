from novaweb.model import *
from flask_wtf import Form
from wtforms import fields, FormField, FieldList, BooleanField, TextField, TextAreaField, PasswordField, SelectField, validators
from wtforms.ext.sqlalchemy.fields import QuerySelectField
from wtforms.ext.dateutil.fields import DateField

class LoginForm(Form):
  username = TextField('Username:', [validators.Required()])
  password = PasswordField('Password:')

class AddUser(Form):
  name = TextField('Name')
  email = TextField('E-mail')
  username = TextField('Username', [validators.Required()])
  password = PasswordField('Password')
  password2 = PasswordField('Confirm password')
  active = BooleanField('Active')

class AddGroup(Form):
  name = TextField('Group Name')

class AddCustomer(Form):
  name = TextField("Customer Name")
  email = TextField("Customer E-Mail")
  address = TextAreaField("Address")
  contract = TextAreaField("Contract")

class AddPayPeriod(Form):
  start_date = DateField("Start Date")
  end_date = DateField("End Date")

class TaskOrder(Form):
  note = TextAreaField('Notes')
