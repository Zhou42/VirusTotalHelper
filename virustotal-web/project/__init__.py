#################
#### imports ####
#################

import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from werkzeug import secure_filename

################
#### config ####
################
app = Flask(__name__)

app.secret_key = 'myverylongsecretkey'

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "users.login"


from project.models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == int(user_id)).first()


# ####################
# #### blueprints ####
# ####################

from project.users.views import users_blueprint
from project.report.views import report_blueprint

# # register the blueprints
app.register_blueprint(users_blueprint)
app.register_blueprint(report_blueprint)
