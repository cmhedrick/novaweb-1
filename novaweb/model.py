###########
#
# Documentation: lol python is self documenting
#
##########
import datetime
import os
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask.ext.login import current_user
from werkzeug.security import generate_password_hash, check_password_hash
from uuid import uuid1 as uuid
from novaweb import app
from flask import render_template
from pdfs import create_pdf

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

  # returns number of hours worked per customer, along with the pay rate and total pay.
  def hours_worked(self, pay_period):
    total_pay = 0
    total_hours = 0
    hours = {}
    if len(self.customers) > 0:
      for customer in self.customers:
        pay_rate = customer.pay_rate
        num_hours = 0
        timesheet = self.timesheets.filter_by(payperiod=pay_period).first()
        if timesheet:
          logged_hours = timesheet.logged_hours.filter_by(customer_id=customer.customer_id)
          if logged_hours:
            num_hours = sum([x.hours for x in logged_hours])
        hours[customer.customer_id] = { 'customer': customer, 'pay_rate': pay_rate, 'hours': num_hours }
      for val in hours.values():
        total_pay += ( val['pay_rate'] * val['hours'] )
        total_hours += val['hours']
    return { 'total_pay': total_pay, 'total_hours': total_hours, 'hours': hours }

  def get_name(self):
    if self.name:
      return self.name
    else:
      return self.username

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
  email = db.Column(db.String(255))
  address = db.Column(db.Text())
  contract = db.Column(db.Text())

  def __init__(self, name, email, address=None, contract=None):
    self.name = name
    self.email = email
    self.address = address
    self.contract = contract

  def __repr__(self):
    return "Customer: %s" % self.name

  def hours_worked(self, pay_period):
    total_billable = 0
    total_hours = 0
    logged_hours = {}
    for timesheet in pay_period.timesheets.all():
      if timesheet.user.active:
        timesheet_hours = self.logged_hours.filter_by(timesheet=timesheet).all()
        uc = UsersCustomers.query.filter_by(user=timesheet.user, customer=self).first()
        if uc:
          bill_rate = uc.bill_rate
        else:
          bill_rate = 0
        logged_hours[timesheet.user.id] = { "user":timesheet.user, "bill_rate": bill_rate, "hours": timesheet_hours }
        tmp_hours = sum([x.hours for x in timesheet_hours])
        total_billable += (tmp_hours * bill_rate)
        total_hours += tmp_hours
    hours = { "total_hours": total_hours, "total_billable": total_billable, "logged_hours": logged_hours }
    return hours

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
  payroll_processed = db.Column(db.Boolean)
  invoices_processed = db.Column(db.Boolean)

  def __init__(self, start_date, end_date):
    self.start_date = start_date.date()
    self.end_date = end_date.date()
    self.payroll_processed = False
    self.invoices_processed = False

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

  def __repr__(self):
    return "User: %s Customer: %s Hours: %s" % (self.timesheet.user.username, self.customer.name, self.hours)

class Invoice(db.Model):
  id = db.Column(db.Integer, db.Sequence('seq_invoice_id', start=1100, increment=1), primary_key=True)
  customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))
  customer = db.relationship('Customer', backref=db.backref('invoices', lazy='dynamic'))
  payperiod_id = db.Column(db.Integer, db.ForeignKey('pay_period.id'))
  payperiod = db.relationship('PayPeriod', backref=db.backref('invoices', lazy='dynamic'))
  total_hours = db.Column(db.Integer)
  total_billable = db.Column(db.Integer)
  sent = db.Column(db.Boolean)
  invoice_pdf = db.Column(db.String(255))

  def __init__(self, customer, pay_period):
    self.customer = customer
    self.payperiod = pay_period
    self.sent = False

  def update_invoice(self):
    self.total_hours = self.customer.hours_worked(self.payperiod)['total_hours']
    self.total_billable = self.customer.hours_worked(self.payperiod)['total_billable']

  def send_invoice(self):
    email = self.customer.email
    output = self.invoice_pdf
    self.sent = True
    db.session.commit()
    if os.path.isfile(self.invoice_pdf):
      return "Sent invoice to %s (%s)" % (self.customer.name, self.customer.email)
    else:
      return "File not found!"

  def generate_invoice(self):
    filepath = app.config['PDF_DIR']
    filename = "/invoice_%s_%s.pdf" % (self.payperiod.start_date.strftime("%m%d%y"), self.customer.name)
    invoice_date = datetime.date.today()
    pdf = create_pdf(render_template("invoice_template.html", payperiod=self.payperiod, invoice=self, invoice_date=invoice_date))
    with open(app.config['PDF_DIR']+filename, 'w') as pdfout:
        pdfout.write(pdf.getvalue())
    self.invoice_pdf = "%s%s" % (filepath, filename)

class AuditLogType(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  audit_type = db.Column(db.String(255))

  def __init__(self, audit_type):
    self.audit_type = audit_type

class AuditLog(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  audit_type_id = db.Column(db.Integer, db.ForeignKey('audit_log_type.id'))
  audit_type = db.relationship('AuditLogType', backref=db.backref('auditlogs', lazy='dynamic'))
  date = db.Column(db.DateTime)
  message = db.Column(db.String(255))
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
  user = db.relationship('User', backref=db.backref('auditlogs', lazy='dynamic'))

  def __init__(self, audit_type, audit_message):
    self.audit_type = audit_type
    self.date = datetime.date.today()
    self.message = audit_message
    if current_user.is_authenticated():
      self.user = current_user
    else:
      self.user = None
