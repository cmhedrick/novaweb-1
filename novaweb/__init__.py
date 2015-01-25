#!/usr/bin/python
#http://flask.pocoo.org/docs/patterns/packages/

import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash
from flask.ext.login import LoginManager

app = Flask(__name__)
app.config.from_pyfile('default_settings.cfg')
app.config.from_envvar('NOVAWEB_SETTINGS', silent=True)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



import novaweb.views
