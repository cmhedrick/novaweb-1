###########
#
# Documentation: lol python is self documenting
#
##########
from flask.ext.sqlalchemy import SQLAlchemy
#from flask.ext.login import UserMixin
from flask.ext.security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from uuid import uuid1 as uuid
from novaweb import app

db = SQLAlchemy(app)

# classes for authentication

# This is M2M with "secondary" pattern
roles_groups = db.Table('roles_groups',
        db.Column('group_id', db.Integer(), db.ForeignKey('group.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

# This is M2M with "secondary" pattern
groups_users = db.Table('groups_users',
        db.Column('group_id', db.Integer(), db.ForeignKey('group.id')),
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')))


# Users Have Many Groups
# Users have Many Many Roles
# Groups have Many Roles
# Groups have Many Users
# Roles have Many Groups
# Roles have Many Users

# General Permission Model:
# Each specific functionality has it's own role
## example: timesheet_create, timesheet_view(self vs other), timesheet_edit (self vs other), timesheet_delete, timesheet_approve(review)
# A group can have a set of roles
# A user has a group (or more)
# A user has direct roles
# A user can have roles denied explicitly (although a group can't).
# That is, a group can add roles, but only can't remove roles.


# Resolution is complex and is handled by the User has_role class.
# Group Roles get Merged. group roles are only additive.
# User Roles get Merged, favoring - Permissions over + and null
# resolved in User.has_role() method.

# @require_role("timesheet_view")

# This is an M2M with "Association" pattern
class UsersRoles(db.Model):
  user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key = True)
  role_id = db.Column(db.Integer, db.ForeignKey("role.id"), primary_key = True)
  # 1 = True, 2 = False, 0 = Ignore (default to permissions from group)
  permission_bit = db.Column(db.Integer)
  role = db.relationship("Role", backref="user_assocs")

class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(255), unique=True)
  email = db.Column(db.String(255), unique=True)
  name = db.Column(db.String(255)) # users full name
  password = db.Column(db.String(255))
  active = db.Column(db.Boolean())
  roles = db.relationship("UsersRoles",backref="user")
  customers = db.relationship("UsersCustomers", backref="user")
  groups = db.relationship("Group", secondary=groups_users, backref=db.backref('users', lazy='dynamic'))

  def __init__(self, username, password, email, name=None, active=True):
    self.username = username
    self.set_password(password)
    self.email = email
    self.active = True
    self.name = name

  def __repr__(self):
    return "Username: %s" % self.username

  def set_password(self, password):
    self.password = generate_password_hash(password)

  def check_password(self, password):
    return check_password_hash(self.password, password)

  def has_role(self, rolename):
    permission_matrix = []
    for group in self.groups:
      for role in group.roles:
        if role.name not in permission_matrix: permission_matrix.append(role.name)
    user_role_matrix = self.resolve_roles()
    for role in user_role_matrix:
      if user_role_matrix[role] == 1:
        if role not in permission_matrix: permission_matrix.append(role)
      elif user_role_matrix[role] == 2:
        if role in permission_matrix: permission_matrix.remove(role)
      else: pass
    return rolename in permission_matrix

  def resolve_roles(self):
    user_role_matrix = {}
    for role in self.roles:
      user_role_matrix[role.role.name] = role.permission_bit
    return user_role_matrix

  def hours_worked(self, pay_period):
    try:
      logged_hours = self.timesheets.filter_by(payperiod=pay_period).first().logged_hours.all()
      hours = [x.hours for x in logged_hours]
    except:
      hours = [0]
    return sum(hours)

class Role(db.Model, RoleMixin):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(255), unique=True)
  desc = db.Column(db.String(255))

  def __init__(self, name, desc):
    self.name = name
    self.desc = desc

  def __repr__(self):
    return "Role: %s" % self.name

class Group(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(255), unique=True)
  roles = db.relationship("Role", secondary=roles_groups, backref=db.backref('groups', lazy='dynamic'))

  def __init__(self, name):
    self.name = name

class Customer(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(255), unique=True)
  email = db.Column(db.String(255), unique=True)
  contract = db.Column(db.Text())

  def __init__(self, name, email, contract=None):
    self.name = name
    self.email = email
    self.contract = contract

  def __repr__(self):
    return "Customer: %s" % self.name

  def invoice_hours(self, pay_period):
    logged_hours = []
    for timesheet in pay_period.timesheets.all():
      timesheet_hours = self.logged_hours.filter_by(timesheet=timesheet).all()
      logged_hours += timesheet_hours
    hours = [x.hours for x in logged_hours]
    return sum(hours)
       

# This is an M2M with "Association" pattern
class UsersCustomers(db.Model):
  user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key = True)
  customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), primary_key = True)
  pay_rate = db.Column(db.Integer)
  bill_rate = db.Column(db.Integer)
  customer = db.relationship("Customer", backref="customer_assocs")

class PayPeriod(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  start_date = db.Column(db.DateTime)
  end_date = db.Column(db.DateTime)

  def __init__(self, start_date, end_date):
    self.start_date = start_date.date()
    self.end_date = end_date.date()

  def __repr__(self):
    return "Start: %s End: %s" % (self.start_date, self.end_date)

  def get_headers(self):
    date_headers = []
    current_date = self.start_date
    while current_date <= self.end_date:
      date_headers.append((current_date.strftime("%a"), current_date.strftime("%d")))
      current_date += datetime.timedelta(days=1)
    return date_headers

  def get_next(self):
    return PayPeriod.query.filter(PayPeriod.start_date > self.end_date).order_by(PayPeriod.start_date).first()

  def get_previous(self):
    return PayPeriod.query.filter(PayPeriod.end_date < self.start_date).order_by(PayPeriod.start_date.desc()).first()


class Timesheet(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
  user = db.relationship('User',  backref=db.backref('timesheets', lazy='dynamic'))
  payperiod_id = db.Column(db.Integer, db.ForeignKey('pay_period.id'))
  payperiod = db.relationship('PayPeriod', backref=db.backref('timesheets', lazy='dynamic'))
  submitted = db.Column(db.Boolean)
  approved = db.Column(db.Boolean)

  def __init__(self, user, payperiod):
    self.user = user
    self.payperiod = payperiod
    self.submitted = False
    self.approved = False

  def __repr__(self):
    if self.submitted:
      if self.approved:
        status = "Submitted and Approved"
      else:
        status = "Submitted Pending Approval"
    else:
      status = "Unsubmitted"
    return "Timesheet (%s) for %s. Status: %s" % (self.payperiod, self.user, status)

class LoggedHours(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  timesheet_id = db.Column(db.Integer, db.ForeignKey('timesheet.id'))
  timesheet = db.relationship('Timesheet', backref=db.backref('logged_hours', lazy='dynamic'))
  customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))
  customer = db.relationship('Customer', backref=db.backref('logged_hours', lazy='dynamic'))
  day = db.Column(db.DateTime)
  hours = db.Column(db.Integer)
  note = db.Column(db.Text())

  def __init__(self, timesheet, customer, day=None, hours=0, note=None):
    self.timesheet = timesheet
    self.customer = customer
    if day is None:
      day = datetime.date.today()
    self.day = day
    self.hours = hours
    self.note = note

class Invoice(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))
  customer = db.relationship('Customer', backref=db.backref('invoices', lazy='dynamic'))
  payperiod_id = db.Column(db.Integer, db.ForeignKey('pay_period.id'))
  payperiod = db.relationship('PayPeriod', backref=db.backref('invoices', lazy='dynamic'))
  total_hours = db.Column(db.Integer)
  sent = db.Column(db.Boolean)
  invoice_pdf = db.Column(db.String(255))

  def __init__(self, customer, pay_period):
    self.customer = customer
    self.payperiod = pay_period
    self.sent = False
    self.update_invoice()

  def update_invoice(self):
    self.total_hours = self.customer.invoice_hours(self.payperiod)
    self.generate_invoice()

  def send_invoice(self):
    email = self.customer.email
    output = self.invoice_pdf
    print "Sending invoice to: %s with: %s" % (email, output)
    self.sent = True

  def generate_invoice(self):
    filename = "%s.pdf" % uuid().hex
    #filepath = app.config.blah
    # generate pdf with some codes
    # save it to filepath/filename
    self.invoice_pdf = filename
    return "Customer: %s Hours: %s" % (self.customer.name, self.total_hours)


