#!/usr/bin/python

import novaweb
from novaweb.model import *


admin = User.query.filter_by(username='admin').first()
#user = User("user", "user", "user@user.edu")
admin_group = Group.query.filter_by(name='admin').first()

#some_other_role = Role("some_other_role", "Some Other Role")
#some_third_role = Role("some_third_role", "Some Third Role")

#admin_group.roles.append(some_third_role)
admin.groups.append(admin_group)
#user.groups.append(admin_group)

#entry = UsersRoles(permission_bit=1)
#entry.role = some_other_role
#user.roles.append(entry)

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
