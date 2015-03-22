#!/usr/bin/python

import os

os.system("mysql < dropall.sql 1> /dev/null 2>&1")
print "Database dropped."

import novaweb
from novaweb.model import *

db.create_all()

print "Database created."

admin = User("admin", "admin", "nwheele3@gmu.edu")
db.session.add(admin)
db.session.commit()
