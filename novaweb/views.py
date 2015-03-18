from novaweb import app, login_manager
from flask.ext.login import login_required, login_user, logout_user, current_user
from novaweb.model import *
from flask import current_app, render_template, request, url_for, flash, redirect, jsonify 
from forms import *
from functools import wraps

# User Loader Method. Don't touch.
@login_manager.user_loader
def load_user(userid):
  return User.query.get(int(userid))

# User Logout Method. Don't touch.
@app.route("/logout")
@login_required
def logout():
  logout_user()
  return redirect(url_for("index"))

# User Login Method. Probably shouldn't touch.
@app.route("/login", methods=['GET', 'POST'])
def login():
  form = LoginForm(request.form)
  if form.validate_on_submit():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user:
      if user.check_password(password):
        login_user(user)
        return redirect(request.args.get("next") or url_for("index"))
    flash("Unsuccessful login attempt.")
  return render_template("login.html", form=form)

# Decorator helper function. Use this to decorate functions to require a role.
# It also will create an admin group if it doesn't exist.
# It also adds newly seen roles to this admin group.
def require_role(rolename, roledesc=""):
  try:
    role = Role.query.filter_by(name=rolename).first()
    if role is None:
      role = Role(rolename, roledesc)
      admin_group = Group.query.filter_by(name="admin").first()
      if admin_group is None:
        admin_group = Group("admin")
        db.session.add(admin_group)
      admin_group.roles.append(role)
      db.session.add(role)
      db.session.commit()
  except:
    pass
  def wrap(f):
    @wraps(f)
    def wrapped_f():
      if current_user.has_role(rolename):
        return f()
      else:
        flash("You do not have the necessary permissions (%s) to perform this action." % rolename)
        return redirect(url_for("index"))
    return wrapped_f
  return wrap


#################################################################
#                                                               #
#   The Views.                                                  #
#                                                               #
#################################################################


@app.route("/admin/")
@require_role("admin_generic")
def admin():
  return render_template("admin.html")

# User Management Views

@app.route("/adduser", methods=['GET', 'POST'])
@login_required
@require_role("gp_edit")
def adduser():
  form = AddUser(request.form)
  if form.validate_on_submit():
    username = request.form['username']
    password = request.form['password']
    password2 = request.form['password2']
    email = request.form['email']
    name = request.form['name']
    user = User.query.filter_by(username=username).first()
    if user:
      flash("User already exists.")
    else:
      if password == password2: # add complexity rules here if desired
        newuser = User(username=username, password=password, email=email, name=name)
        db.session.add(newuser)
        db.session.commit()
        flash("New user added.")
      else:
        flash("Password does not match.")
    return redirect(url_for("groups_and_permissions"))
  return render_template("adduser.html", form=form)

@app.route("/addgroup", methods=['GET', 'POST'])
@login_required
@require_role("gp_edit")
def addgroup():
  form = AddGroup(request.form)
  if form.validate_on_submit():
    groupname = request.form['name']
    group = Group.query.filter_by(name=groupname).first()
    if group:
      flash("Group already exists.")
    else:
      newgroup = Group(name=groupname)
      db.session.add(newgroup)
      db.session.commit()
      flash("New group added.")
    return redirect(url_for("groups_and_permissions"))
  return render_template("addgroup.html", form=form)

@app.route("/addcustomer", methods=['GET', 'POST'])
@login_required
@require_role("c_edit")
def addcustomer():
  form = AddCustomer(request.form)
  if form.validate_on_submit():
    customer_name = request.form['name']
    customer_email = request.form['email']
    customer_contract = request.form['contract']
    customer = Customer.query.filter_by(name=customer_name).first()
    if customer:
      flash("Customer already exists.")
    else:
      newcustomer = Customer(name=customer_name, email=customer_email, contract=customer_contract) 
      db.session.add(newcustomer)
      db.session.commit()
      flash("New customer added")
    return redirect(url_for("contracts"))
  return render_template("addcustomer.html", form=form)

@app.route("/modify_customer_users", methods=['GET', 'POST'])
@login_required
@require_role("c_edit")
def modify_customer_users():
  if "customer_id" not in request.values:
    flash("Invalid Request: Missing Customer ID.")
    return redirect(url_for("contracts"))
  customer = Customer.query.filter_by(id=request.values['customer_id']).first()
  if customer is None:
    flash("Invalid Customer ID")
    return redirect(url_for("contracts"))
  users = User.query.all()
  if request.method == 'GET':
    user_matrix = {}
    for user in users:
      user_customer = UsersCustomers.query.filter_by(user_id=user.id, customer_id=customer.id).first()
      if user.name is not None: username = user.name
      else: username = user.username
      user_matrix[user.id] = {'name': username, 'user_customer': user_customer}
    return render_template("modify_customer_users.html", user_matrix=user_matrix)
  else:
    # Handle POST
    for user in users:
      user_key = "u%s" % user.id
      user_customer = UsersCustomers.query.filter_by(user_id=user.id, customer_id=customer.id).first()
      if user_customer is None:
        user_customer = UsersCustomers(user_id=user.id, customer_id=customer.id)
        user_customer.customer = customer
        user.customers.append(user_customer)
        db.session.add(user_customer)
      if user_key in request.values:
        b_key = "u%s_b" % user.id
        p_key = "u%s_p" % user.id
        if b_key not in request.values: bpay = 0
        else: bpay = request.values[b_key]
        if p_key not in request.values: ppay = 0
        else: ppay = request.values[p_key]
        user_customer.bill_rate = bpay
        user_customer.pay_rate = ppay
      else:
        if user_customer in user.customers:
          user.customers.remove(user_customer)
          db.session.delete(user_customer)
    flash("Contract updated.")
    print "right here."
    db.session.commit()
    print "not here."
    return redirect(url_for("contracts"))

@app.route("/contracts")
@login_required
@require_role("c_view")
def contracts():
  customers = Customer.query.order_by('id').all()
  return render_template("contracts.html", customers=customers)

@app.route("/groups_and_permissions")
@login_required
@require_role("gp_view")
def groups_and_permissions():
  users = User.query.all()
  groups = Group.query.order_by('id').all()
  roles = Role.query.all()
  permissions = {}
  total_permissions = 0
  prefixes = [ role.name.split("_")[0] for role in roles ]
  prefix_map = { 'um': "User Management",
                 'gp': 'Groups & Permissions',
                 'c': 'Contracts',
               }
  group_names = [ group.name for group in groups ]
  user_group_matrix = {}
  for user in users:
    user_group_matrix[user.id] = {'name': user.username, 'groups': {}}
    for group in groups:
      user_group_matrix[user.id]['groups'][group.id] = group in user.groups

  for prefix in prefixes:
    prefix_key = prefix
    if prefix in prefix_map:
      prefix_key = prefix_map[prefix]
    permissions[prefix_key] = [ " ".join(role.name.split("_")[1:]) for role in roles if role.name.startswith(prefix) ]
    total_permissions += len(permissions[prefix_key])
  group_matrix = {}
  for group in groups:
    group_matrix[group.id] = {'name': group.name, 'perms': {}}
    for role in roles:
      group_matrix[group.id]['perms'][role.id] = role in group.roles
  user_matrix = {}
  for user in users:
    user_matrix[user.id] = {'name': user.username, 'perms': {}}
    for role in roles:
      user_role_matrix = user.resolve_roles()
      if role in user_role_matrix:
        user_matrix[user.id]['perms'][role.id] = user_role_matrix[role]
      else:
        user_matrix[user.id]['perms'][role.id] = 0
  permissions_model = { 'permissions': permissions,
                        'group_matrix': group_matrix,
                        'user_matrix': user_matrix,
                        'total': total_permissions }
  group_model = { 'user_group_matrix': user_group_matrix,
                  'group_names': group_names,
                  'total': len(groups) }
  return render_template("groups_and_permissions.html", permissions=permissions_model, group_model=group_model )

@app.route("/groups_and_permissions", methods = ['POST'])
@login_required
@require_role("gp_edit")
def groups_and_permissions_handler():
  users = User.query.all()
  roles = Role.query.all()
  groups = Group.query.all()
  for role in roles:
    for group in groups:
      perm_field = "g%s_r%s" % (group.id, role.id)
      if perm_field in request.form and request.form[perm_field] == "1":
        if role not in group.roles:
          group.roles.append(role)
      else:
        if role in group.roles:
          group.roles.remove(role)
    for user in users:
      perm_field = "u%s_r%s" % (user.id, role.id)
      if perm_field in request.form:
        perm_bit = request.form[perm_field]
      else:
        perm_bit = 0
      role_map = UsersRoles.query.filter_by(user_id=user.id, role_id=role.id).first()
      if role_map is not None:
        if str(role_map.permission_bit) != perm_bit:
          role_map.permission_bit = perm_bit
      else:
        role_map = UsersRoles(permission_bit = perm_bit)
        role_map.role = role
        user.roles.append(role_map)
        db.session.add(role_map)
  for user in users:
    for group in groups:
      group_field = "u%s_g%s" % (user.id, group.id)
      if group_field in request.form and request.form[group_field] == "1":
        if group not in user.groups:
          user.groups.append(group)
      else:
        if group in user.groups:
          user.groups.remove(group)
  db.session.commit()
  flash("Permissions saved.")
  return redirect(url_for("groups_and_permissions"))




@app.route('/zomg')
@login_required
@require_role("some_role")
@require_role("some_other_role")
@require_role("some_fourth_role", "new role entry")
def zomg():
  flash("This worked.")
  return render_template("index.html")


@app.route('/')
@login_required
def index():
  return render_template("index.html")


