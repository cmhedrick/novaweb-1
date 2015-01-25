from novaweb import app, login_manager
from flask.ext.login import login_required, login_user, logout_user, current_user
from novaweb.model import *
from flask import current_app, render_template, request, url_for, flash, redirect, jsonify 
from forms import *

@login_manager.user_loader
def load_user(userid):
  return User.query.get(int(userid))

@app.route("/logout")
@login_required
def logout():
  logout_user()
  return redirect(url_for("index"))

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
        #flash("Logged in successfully")
        return redirect(request.args.get("next") or url_for("index"))
    flash("Unsuccessful login attempt.")
  return render_template("login.html", form=form)

@app.route("/admin")
@login_required
def admin():
  if current_user.has_role('Admin'):
    return "Welcome %s to super secret admin page!" % (current_user.username)
  else:
    flash("You don't have permission to view that page.")
    return redirect(url_for("index"))

@app.route('/')
@login_required
def index():
  return render_template("index.html")
