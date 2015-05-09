#!/usr/bin/python

import os

os.system("mysql < dropall.sql 1> /dev/null 2>&1")
print "Database dropped."

import novaweb
from novaweb.model import *

db.create_all()

print "Database created."

admin = User("admin", "admin", "nwheele3@gmu.edu")
admin_group = Group("admin")
admin.groups.append(admin_group)
db.session.add(admin_group)
db.session.add(admin)

audit_reason_1 = AuditLogType("login")
audit_reason_2 = AuditLogType("timesheet")
audit_reason_3 = AuditLogType("approve")
audit_reason_4 = AuditLogType("invoice")
audit_reason_5 = AuditLogType("payroll")
audit_reason_6 = AuditLogType("user")
audit_reason_7 = AuditLogType("customer")

db.session.add(audit_reason_1)
db.session.add(audit_reason_2)
db.session.add(audit_reason_3)
db.session.add(audit_reason_4)
db.session.add(audit_reason_5)
db.session.add(audit_reason_6)


db.session.commit()
