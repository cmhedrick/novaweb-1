###########
#
# Documentation: lol python is self documenting
#
##########
from flask.ext.sqlalchemy import SQLAlchemy
#from flask.ext.login import UserMixin
from flask.ext.security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from werkzeug.security import generate_password_hash, check_password_hash
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

  def __init__(self, username, password, email, name=None):
    self.username = username
    self.set_password(password)
    self.email = email
    self.active = True
    self.name = name

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

class Role(db.Model, RoleMixin):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(255), unique=True)
  desc = db.Column(db.String(255))

  def __init__(self, name, desc):
    self.name = name
    self.desc = desc

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
  # reference to invoices

  def __init__(self, name, email, contract=None):
    self.name = name
    self.email = email
    self.contract = contract

# This is an M2M with "Association" pattern
class UsersCustomers(db.Model):
  user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key = True)
  customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), primary_key = True)
  pay_rate = db.Column(db.Integer)
  bill_rate = db.Column(db.Integer)
  customer = db.relationship("Customer", backref="customer_assocs")
  

#class Invoice(db.Model):
#  id = db.Column(db.Integer, primary_key=True)

#class Timesheet(db.Model):
#  id = db.Column(db.Integer, primary_key=True)
#  approved = db.column(db.Boolean())
# some user reference

# A user has many timesheets
# That is, a timesheet belongs to a user
# A timesheet has many customers
# Customers appear on many timesheets
# An Invoice is an aggregation of time across timesheets for a period
