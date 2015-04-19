import datetime
import os
from novaweb import app, login_manager
from flask.ext.login import login_required, login_user, logout_user, current_user
from novaweb.model import *
from flask import current_app, render_template, request, url_for, flash, redirect, jsonify, send_file
from forms import *
from dateutil import parser as dateparser
from functools import wraps
from collections import OrderedDict
from pdfs import create_pdf

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
        return redirect(request.args.get("next") or url_for("timesheet"))
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
  user_id = None
  if 'user_id' in request.values:
    user = User.query.get(request.values['user_id'])
    if not user:
      flash("Invalid user specified!")
    else:
      form = AddUser(request.form, user)
      user_id = user.id
  else:
    form = AddUser(request.form, active=True)
  if form.validate_on_submit():
    username = request.form['username']
    password = request.form['password']
    password2 = request.form['password2']
    email = request.form['email']
    name = request.form['name']
    if 'active' in request.form:
      active = True
    else:
      active = False
    if 'user_id' in request.values:
      user.username = username
      if (password != "") and (password == password2):
        user.set_password(password)
      user.email = email
      user.name = name
      user.active = active
      db.session.commit()
      flash("User updated.")
      return redirect(url_for("user_management"))
    else:
      user = User.query.filter_by(username=username).first()
      if user:
        flash("User already exists.")
      else:
        if password == password2: # add complexity rules here if desired
          newuser = User(username=username, password=password, email=email, name=name, active=active)
          db.session.add(newuser)
          db.session.commit()
          flash("New user added.")
        else:
          flash("Password does not match.")
    return redirect(url_for("groups_and_permissions"))
  return render_template("adduser.html", form=form, user_id=user_id)

@app.route("/deletegroup", methods=['GET'])
@login_required
@require_role("gp_edit")
def deletegroup():
  has_errors = False
  if 'group_id' not in request.values:
    flash("Group not specified.")
    has_errors = True
  group = Group.query.get(request.values['group_id'])
  if not group:
    flash("Invalid group specified.")
    has_errors = True
  if group.users.all():
    flash("Cannot remove groups which users belong to. Please remove users first.")
    has_errors = True
  if not has_errors:
    db.session.delete(group)
    db.session.commit()
    flash("Group deleted successfully.")
  return redirect(url_for("groups_and_permissions"))
  

@app.route("/addgroup", methods=['GET', 'POST'])
@login_required
@require_role("gp_edit")
def addgroup():
  group_id = None
  if 'group_id' in request.values:
    group = Group.query.get(request.values['group_id'])
    if not group:
      flash("Group does not exist.")
      return redirect(url_for("groups_and_permissions"))
    group_id = group.id
    form = AddGroup(request.form, group)
  else:
    form = AddGroup(request.form)
  if form.validate_on_submit():
    if 'group_id' in request.values:
      group.name = request.form['name']
      db.session.commit()
      flash("Group modified.")
    else:
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
  return render_template("addgroup.html", form=form, group_id=group_id)

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


# An attempt at fancy ajax for saving information.
@app.route("/taskorder", methods=['GET', 'POST'])
@login_required
@require_role("ts_edit")
def taskorder():
  invalid_request = False
  if 'logged_hour_id' not in request.values:
    invalid_request = True
  else:
    logged_hour = LoggedHours.query.get(request.values['logged_hour_id'])
    if logged_hour is None:
      invalid_request = True
  if invalid_request:
    return "Invalid Request: Missing or invalid logged hour ID."
  user = logged_hour.timesheet.user
  if current_user is not user:
    if not current_user.has_role("ts_edit_other"):
      return "You do no thave permission to edit other timesheets."
  form = TaskOrder(request.form, logged_hour)
  if request.method == "GET":
    return render_template("taskorder.html", form=form, logged_hour=logged_hour)
  if form.validate_on_submit():
    if logged_hour.timesheet.submitted:
      return "You cannot update task orders of submitted timesheets."
    logged_hour.note = request.values['note']
    db.session.commit()
    return "Task order saved."
  else:
    return "An unknown error occurred. Please try again."
  


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
      #if user.name is not None: username = user.name
      #else: username = user.username
      user_matrix[user.id] = {'user': user, 'user_customer': user_customer}
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
  users = User.query.filter_by(active=True).all()
  groups = Group.query.order_by('id').all()
  roles = Role.query.all()
  permissions = {}
  total_permissions = 0
  prefixes = [ role.name.split("_")[0] for role in roles ]
  prefix_map = { 'um': "User Management",
                 'gp': 'Users, Groups & Permissions',
                 'c': 'Contracts',
                 'pp': 'Pay Period',
                 'ts': 'Timesheet',
                 'ap': 'Approvals',
               }
  user_group_matrix = {}
  for user in users:
    user_group_matrix[user.id] = {'name': user, 'groups': {}}
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
    group_matrix[group.id] = {'group': group, 'perms': {}}
    for role in roles:
      group_matrix[group.id]['perms'][role.id] = role in group.roles
  user_matrix = {}
  for user in users:
    user_matrix[user.id] = {'name': user, 'perms': {}}
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
                  'group_names': groups,
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
        role_map.user = user
        # this fails for some reason.
        user.roles.append(role_map)
        print "new role_map: %s (about to add)" % role_map
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

@app.route("/manage_payperiods", methods=['GET'])
@login_required
@require_role("pp_manage")
def manage_payperiods():
  payperiods = PayPeriod.query.all()
  return render_template("manage_payperiods.html", payperiods=payperiods)

# This gets the earliest "unfinished" timesheet.
# should not go past current timesheet
def get_last_payperiod():
  current_payperiod = get_current_payperiod()
  payperiods = PayPeriod.query.filter(PayPeriod.end_date <= current_payperiod.end_date).order_by("start_date").all()
  for payperiod in payperiods:
    if not payperiod.payroll_processed or not payperiod.invoices_processed:
      return payperiod
  return current_payperiod


@app.route("/payperiod", methods=['GET', 'POST'])
@login_required
@require_role("pp_view")
def payperiod():
  processable = {}
  payperiod = get_last_payperiod()
  users = User.query.filter_by(active=True).all()
  processable['payroll'] = True
  for timesheet in payperiod.timesheets.all():
    if (not timesheet.submitted or not timesheet.approved) and timesheet.user.active:
      processable['payroll'] = False
  if payperiod.payroll_processed:
    processable['payroll'] = False
  customer_model = {}
  customers = Customer.query.all()
  for customer in customers:
    invoice = Invoice.query.filter_by(customer=customer, payperiod=payperiod).first()
    customer_model[customer.id] = {'customer': customer, 'invoice': invoice}
  if request.method == 'POST':
    if not payperiod.payroll_processed and not payperiod.invoices_processed:
      timesheet_model = [x.id for x in payperiod.timesheets.all()]
      process_timesheet_approvals(request, timesheet_model)
    if processable['payroll']:
      if 'generate_payroll' in request.values:
        if payperiod.payroll_processed:
          flash("Invalid request. Payroll already processed.")
        else:
          pdf = create_pdf(render_template("payroll_report.html", users=users, payperiod=payperiod))
          filename = "/payroll_%s_%s.pdf" % (payperiod.start_date.strftime("%m%d%y"), payperiod.id)
          with open(app.config['PDF_DIR']+filename, 'w') as pdfout:
            pdfout.write(pdf.getvalue())
          payperiod.payroll_processed = True
          db.session.commit()
  # handle generation of invoice
  if 'generate_invoice' in request.values:
    generate_invoice = True
    if request.values['generate_invoice'] == "all":
      customers = Customer.query.all()
    else:
      customers = [Customer.query.get(request.values['generate_invoice'])]
    if not len(customers) > 0:
      flash("Invalid customer")
      generate_invoice = False
    if generate_invoice:
      print customers
      for customer in customers:
        if customer.hours_worked(payperiod)['total_billable'] > 0:
          invoice = Invoice.query.filter_by(customer=customer, payperiod=payperiod).first()
          if not invoice:
            invoice = Invoice(customer, payperiod)
            db.session.add(invoice)
            db.session.commit()
          invoice.update_invoice()
          invoice.generate_invoice()
          db.session.commit()
          flash("Invoice for customer %s updated." % customer.name)
    return redirect(url_for("payperiod"))
  return render_template("payperiods.html", users=users, payperiod=payperiod, processable=processable, customer_model=customer_model)

@app.route("/view_payroll", methods=['GET', 'POST'])
@login_required
@require_role("pp_payroll_view")
def view_payroll():
  if 'payperiod_id' not in request.values:
    flash("Invalid request.")
  payperiod = PayPeriod.query.get(request.values['payperiod_id'])
  if not payperiod:
    flash("Invalid payperiod.")
  filename = "/payroll_%s_%s.pdf" % (payperiod.start_date.strftime("%m%d%y"), payperiod.id)
  if os.path.isfile(app.config['PDF_DIR']+filename):
    return send_file(app.config['PDF_DIR']+filename)
  else:
    flash("File not found!")
    return redirect(url_for("payperiod"))

@app.route("/send_invoice", methods=['GET'])
@login_required
@require_role("pp_invoice_send")
def send_invoice():
  invoices = []
  fail = False
  if 'payperiod' not in request.values or 'invoice' not in request.values:
    flash("Invalid request.")
    fail = True
  payperiod = PayPeriod.query.get(request.values['payperiod'])
  if not payperiod:
    flash("Invalid payperiod.")
    fail = True
  if not payperiod.payroll_processed:
    flash("You must first process payroll to send invoices.")
    fail = True
  if request.values['invoice'] == "all":
    for invoice in Invoice.query.filter_by(payperiod=payperiod).all():
      if not invoice.sent:
        if invoice.total_billable > 0:
          invoices.append(invoice)
  else:
    invoices.append(Invoice.query.get(request.values['invoice']))
  if not len(invoices) > 0:
    flash("No unsent invoices found.")
    fail = True
  if not fail:
    for invoice in invoices:
      output = invoice.send_invoice()
      flash(output)
  complete = True
  for invoice in Invoice.query.filter_by(payperiod=payperiod).all():
    if invoice.total_billable > 0:
      if not invoice.sent:
        complete = False
  if complete:
    payperiod.invoices_processed = True
    db.session.commit()
  return redirect(url_for("payperiod"))

@app.route("/view_invoice", methods=['GET'])
@login_required
@require_role("pp_invoice_view")
def view_invoice():
  fail = False
  if 'payperiod' not in request.values or 'invoice' not in request.values:
    flash("Invalid request.")
    fail = True
  payperiod = PayPeriod.query.get(request.values['payperiod'])
  if not payperiod:
    flash("Invalid payperiod.")
    fail = True
  invoice = Invoice.query.get(request.values['invoice'])
  if not invoice:
    flash("Invalid invoice.")
    fail = True
  if not fail:
    if os.path.isfile(invoice.invoice_pdf):
      return send_file(invoice.invoice_pdf)
    else:
      flash("File not found!")
  return redirect(url_for("payperiod"))
  

@app.route("/debug", methods=['GET'])
def debug():
  return render_template("payroll_report.html")

@app.route("/timesheet_history", methods=['GET'])
@login_required
def timesheet_history():
# ts_view_other and ts_view
  user = current_user
  if 'user_id' in request.values:
    if current_user.id != request.values['user_id']:
      if not current_user.has_role("ts_view_other"):
        flash("You do not have permission to view other users historical timesheets.")
        user = False
      else:
        user_id = request.values['user_id']
        user = User.query.filter_by(id=user_id).first()
        if user is None:
          flash("User not found.")
          user = False
  timesheets = user.timesheets.all()
  timesheets = sorted(timesheets, key=lambda sheet: sheet.payperiod.start_date)
  return render_template("timesheet_history.html", user=user, timesheets=timesheets)

# timesheet helper methods

def get_current_payperiod():
  today = datetime.date.today()
  payperiod = PayPeriod.query.filter(PayPeriod.start_date <= today, PayPeriod.end_date >= today).first()
  return payperiod


def process_timesheet_request():
  user = current_user
  if 'user_id' in request.values:
    if current_user.id != request.values['user_id']:
      if not current_user.has_role("ts_view_other"):
        flash("You do not have permission to see other users timesheets.")
        user = False
      else:
        user_id = request.values['user_id']
        user = User.query.filter_by(id=user_id).first()
        if user is None:
          flash("User not found.")
          user = False
  if 'payperiod_id' in request.values:
    get_payperiod = False
    payperiod = PayPeriod.query.get(request.values['payperiod_id'])
    if payperiod is None:
      flash("Invalid payperiod specified. Displaying current payperiod.")
      get_payperiod = True
  else:
    get_payperiod = True
  if get_payperiod:
    payperiod = get_current_payperiod()
  if payperiod is None:
    flash("No payperiod is set up for today. Please set up the payroll cycle!")
  return (user, payperiod)

def get_timesheet(user, payperiod):
  timesheet = Timesheet.query.filter_by(user=user, payperiod=payperiod).first()
  if timesheet is None:
    timesheet = Timesheet(user, payperiod)
    db.session.add(timesheet)
    db.session.commit()
  return timesheet


def get_logged_hours(timesheet):
  logged_hours = OrderedDict()
  start_date = timesheet.payperiod.start_date
  end_date = timesheet.payperiod.end_date
  current_date = start_date
  # if timesheet has been submitted (historical view), pull customers from timesheet object.
  if timesheet.submitted:
    customers = [x.customer for x in timesheet.logged_hours.group_by('customer_id').order_by('customer_id').all()]
  else:
    customers = [x.customer for x in timesheet.user.customers]
  for customer in customers:
    logged_hours[customer] = []
    while current_date <= end_date:
      logged_hour = LoggedHours.query.filter_by(timesheet=timesheet, customer=customer, day=current_date).first()
      if not logged_hour:
        logged_hour = LoggedHours(timesheet, customer, current_date, hours=0, note=None)
        db.session.add(logged_hour)
        db.session.commit()
      logged_hours[customer].append(logged_hour)
      current_date += datetime.timedelta(days=1)
    current_date = start_date
  return logged_hours

def get_timesheet_approvals():
  timesheet_model = {}
  customers_model = {}
  payperiod = get_last_payperiod()
  timesheets = Timesheet.query.filter_by(payperiod=payperiod, submitted=True, approved=False)
  for timesheet in timesheets:
    customers = [x.customer for x in timesheet.logged_hours.group_by('customer_id').order_by('customer_id').all()]
    for customer in customers:
      logged_hours = LoggedHours.query.filter_by(timesheet=timesheet, customer=customer).all()
      hours = sum([x.hours for x in logged_hours])
      pay_rate = UsersCustomers.query.filter_by(user_id=timesheet.user.id, customer_id=customer.id).first().pay_rate
      total = hours*pay_rate
      customers_model[customer.id] = {'customer': customer, 'hours': hours, 'rate': pay_rate, 'total': total}
    grand_total = sum( [x['total'] for x in customers_model.values()] )
    timesheet_model[timesheet.id] = { 'timesheet': timesheet, 'customers': customers_model, 'total': grand_total }
  return timesheet_model

def process_timesheet_approvals(request, timesheet_model):
  if not current_user.has_role("ts_approve_other"):
    flash("You do not have permission to approve/reject this timesheet.")
    return False
  else:
    for timesheet_id in timesheet_model:
      token = "approve_ts_%s" % timesheet_id
      if token in request.values:
        timesheet = Timesheet.query.get(timesheet_id)
        timesheet.approved = True
        db.session.commit()
        flash("Timesheet for %s approved." % timesheet.user.get_name())
      token = "reject_ts_%s" % timesheet_id
      if token in request.values:
        timesheet = Timesheet.query.get(timesheet_id)
        timesheet.approved = False
        timesheet.submitted = False
        db.session.commit()
        flash("Timesheet for %s rejected." % timesheet.user.get_name())

@app.route("/approvals", methods=['GET', 'POST'])
@login_required
@require_role("ap_view")
def approvals():
  timesheet_model = get_timesheet_approvals()
  payperiod = get_last_payperiod()
  if request.method == 'POST':
    process_timesheet_approvals(request, timesheet_model)
    return redirect(url_for("approvals"))
  return render_template("approvals.html", timesheet_model=timesheet_model, payperiod=payperiod)
  

# accepts payperiod_id and user_id
@app.route("/timesheet", methods=['GET', 'POST'])
@login_required
@require_role("ts_view")
def timesheet():
  user, payperiod = process_timesheet_request()
  if not user:
    return redirect(url_for("timesheet"))
  if not payperiod:
    return redirect(url_for("payperiod"))
  navigation = {'next': payperiod.get_next(), 'previous': payperiod.get_previous()}
  timesheet = get_timesheet(user, payperiod)
  logged_hours = get_logged_hours(timesheet)
  date_headers = payperiod.get_headers()
  # u#_c#_y#_m#_d#
  if request.method == 'POST':
    has_errors = False
    if current_user is not user:
      if not current_user.has_role("ts_edit_other"):
        flash("You do not have permission to edit other timesheets")
        has_errors = True
    if not current_user.has_role("ts_edit"):
      flash("You do not have permission to edit timesheets!")
      has_errors = True
    if timesheet.submitted:
      flash("You cannot modify a timesheet that has been submitted!")
      has_errors = True
    if has_errors:
      return redirect(url_for("timesheet"))
    conversion_error = False
    for customer in logged_hours:
      for logged_hour in logged_hours[customer]:
        field = "u%s_c%s_%s" % (user.id, customer.id, logged_hour.day.strftime("y%y_m%m_d%d"))
        value = request.values[field]
        if value == "":
          value = 0
        else:
          try:
            value = float(request.values[field])
          except:
            value = 0
            conversion_error = True
        logged_hour.hours = value
        db.session.commit()
    flash("Timesheet has been updated!")
    if conversion_error:
      flash("An error occurred converting one or more timesheet values. Please doublecheck your timesheet")
    else:
      if 'submit' in request.values:
        timesheet.submitted = True
        if current_user.has_role("ts_approve"):
          timesheet.approved = True
          flash("Timesheet successfully submitted and automatically approved.")
        else:
          flash("Timesheet successfully submitted. Now pending approval.")
  db.session.commit()
  return render_template("timesheet.html", logged_hours=logged_hours, payperiod=payperiod, navigation=navigation, user=user, date_headers=date_headers, timesheet=timesheet)

@app.route('/user_management')
@login_required
@require_role("um_view")
def user_management():
  users = User.query.all()
  groups = Group.query.all()
  return render_template("user_management.html", users=users, groups=groups)
  
    
@app.route('/')
@login_required
def index():
  return redirect(url_for("timesheet"))

@app.route('/load_permission_groups')
@login_required
@require_role("ts_view_other")
@require_role("ts_edit_other")
@require_role("ts_edit")
@require_role("ts_approve")
@require_role("ts_approve_other")
def load_permission_groups():
  return "You have reached here in err."
