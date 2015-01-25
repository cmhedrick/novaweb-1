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

roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(255), unique=True)
  email = db.Column(db.String(255), unique=True)
  password = db.Column(db.String(255))
  active = db.Column(db.Boolean())
  roles = db.relationship("Role", secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

  def __init__(self, username, password, email):
    self.username = username
    self.set_password(password)
    self.email = email
    self.active = True

  def set_password(self, password):
    self.password = generate_password_hash(password)

  def check_password(self, password):
    return check_password_hash(self.password, password)

  def has_role(self, role):
    return role in self.roles

class Role(db.Model, RoleMixin):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(255), unique=True)
  desc = db.Column(db.String(255))

  def __init__(self, name, desc):
    self.name = name
    self.desc = desc
