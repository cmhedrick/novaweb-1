import datetime
from novaweb import app, login_manager
from flask.ext.login import login_required, login_user, logout_user, current_user
from novaweb.model import *
from flask import current_app, render_template, request, url_for, flash, redirect, jsonify 
from forms import *
from dateutil import parser as dateparser
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
      if user_key in request.values:
        if user_customer is None:
          user_customer = UsersCustomers(user_id=user.id, customer_id=customer.id)
          user_customer.customer = customer
        db.session.add(user_customer)
        user.customers.append(user_customer)
        b_key = "u%s_b" % user.id
        p_key = "u%s_p" % user.id
        if b_key not in request.values: bpay = 0
        else: bpay = request.values[b_key]
        if p_key not in request.values: ppay = 0
        else: ppay = request.values[p_key]
        user_customer.bill_rate = bpay
        user_customer.pay_rate = ppay
      else:
        if user_customer is not None:
          if user_customer in user.customers:
            user.customers.remove(user_customer)
            db.session.delete(user_customer)
    flash("Contract updated.")
    db.session.commit()
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
                 'pp': 'Pay Period',
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

@app.route("/addpayperiod", methods=['GET', 'POST'])
@login_required
@require_role("pp_edit")
def addpayperiod():
  form = AddPayPeriod(request.form)
  latest_date = PayPeriod.query.order_by(PayPeriod.end_date.desc()).first().end_date.date() + datetime.timedelta(days=1)
  if form.validate_on_submit():
    start_date = dateparser.parse(request.values['start_date'])
    end_date = dateparser.parse(request.values['end_date'])
    valid_check = True
    if start_date > end_date:
      valid_check = False
      flash("Error: Start date must be later than end date")
    payperiods = PayPeriod.query.all()
    for period in payperiods:
      if start_date > period.start_date and start_date < period.end_date:
        valid_check = False
        flash("Error: Start date can't overlap another pay period")
      if end_date < period.end_date and end_date > period.start_date:
        valid_check = False
        flash("Error: End date can't overlap another pay period")
    if valid_check:
      ppay = PayPeriod(start_date, end_date)
      db.session.add(ppay)
      db.session.commit()
      flash("New pay period created.")
    return redirect(url_for("payperiod"))
  return render_template("addpayperiod.html", form=form, latest_date=latest_date)  

@app.route("/payperiod", methods=['GET'])
@login_required
@require_role("pp_view")
def payperiod():
  payperiods = PayPeriod.query.all()
  return render_template("payperiod.html", payperiods=payperiods)


@app.route("/timesheet", methods=['GET'])
@login_required
@require_role("ts_view")
def timesheet():
  user = current_user
  if 'user_id' in request.values:
    if current_user.id != request.values['user_id']:
      if not current_user.has_role("ts_view_other"):
        flash("You do not have permission to see other users timesheets.")
        return redirect(url_for("timesheet")) # maybe make manage users?
      else:
        user_id = request.values['user_id']
        user = User.query.filter_by(id=user_id).first()
        if user is None:
          flash("User not found.")
          return redirect(url_for("timesheet")) # maybe make manage users?
  if 'payperiod_id' in request.values:
    get_current_payperiod = False
    payperiod = PayPeriod.query.get(request.values['payperiod_id'])
    if payperiod is None:
      flash("Invalid payperiod specified. Displaying current payperiod.")
      get_current_payperiod = True
  else:
    get_current_payperiod = True
  if get_current_payperiod:
    today = datetime.date.today()
    payperiod = PayPeriod.query.filter(PayPeriod.start_date < today, PayPeriod.end_date > today).first()
  if payperiod is None:
    flash("No payperiod is set up for today. Please set up the payroll cycle!")
    return direct(url_for("payperiod"))
  timesheet = Timesheet.query.filter_by(user=user, payperiod=payperiod).first()
  if timesheet is None:
    timesheet = Timesheet(user, payperiod)
    db.session.add(timesheet)
    db.session.commit()
  start_date = payperiod.start_date
  end_date = payperiod.end_date
  current_date = start_date
  date_range = []
  while current_date <= end_date:
    date_range.append(current_date.strftime("%Y_%m_%d"))
    current_date += datetime.timedelta(days=1)
  # At this point, we have the correct user, payperiod, timesheet, and a range of the relevant dates
  # i will do rest later.
  output = "Timesheet for: %s" % (user.username)
  output += "<br />Pay Period: %s" % (payperiod)
  output += "<br />Timesheet: %s" % (timesheet)
  output += "<br />Date range: %s" % (date_range)
  return output
  
    
@app.route('/')
@login_required
def index():
  return render_template("index.html")


@app.route('/load_permission_groups')
@login_required
@require_role("ts_view_other")
def load_permission_groups():
  return "You have reached here in err."
