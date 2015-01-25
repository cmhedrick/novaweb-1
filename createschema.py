#!/usr/bin/python

import novaweb
from novaweb.model import *

db.create_all()

# create default admin user
admin = User("admin", "admin", "null@null.edu")
internuser = User("intern", "intern", "null@null.com")

# create admin and intern roles
admin_role = Role("Admin", "Administrator Role")
intern_role = Role("Intern", "Intern Role")

# give admin user admin role
admin.roles.append(admin_role)
internuser.roles.append(intern_role)

db.session.add(admin_role)
db.session.add(intern_role)
db.session.add(admin)
db.session.commit()
