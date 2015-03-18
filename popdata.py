#!/usr/bin/python

import novaweb
from novaweb.model import *


admin = User.query.filter_by(username='admin').first()
admin_group = Group.query.filter_by(name='admin').first()

user = User("user", "user", "user@user.edu")
user_group = Group("interns")
user.groups.append(user_group)
admin.groups.append(admin_group)

#some_other_role = Role("some_other_role", "Some Other Role")
#some_third_role = Role("some_third_role", "Some Third Role")

#admin_group.roles.append(some_third_role)
#user.groups.append(admin_group)

#entry = UsersRoles(permission_bit=1)
#entry.role = some_other_role
#user.roles.append(entry)


# 1. create UsersCustomers with extra data (pay/bill rate) (done)
# 2. set UsersCustomers.customer = some customer (done)
# 3. user.customer.append(UsersCustomers)
 
#some_customer = Customer(name, email, desc)
#entry = UsersCustomers(bill_rate=20, pay_rate=15)
#UsersCustomers.customer = some_customer
#user.customer.append(entry)



#anotherentry = UsersRoles(permission_bit=2)
#anotherentry.role = some_third_role
#user.roles.append(anotherentry)


#db.session.add(admin)
#db.session.add(user)
#db.session.add(some_other_role)
#db.session.add(some_third_role)
#db.session.add(entry)
#db.session.add(anotherentry)
db.session.commit()

# Tests:
# "user" should not have "some_third_role"
# "user" should have group "AdminGroup", and therefore: some_role
# "user" should have "some_other_role" as it's explicitly added
