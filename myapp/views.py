from flask import Blueprint, render_template, request, url_for, redirect, session
from functools import wraps
from myapp.database import *

views = Blueprint('views', __name__, static_folder='static', template_folder='templates')

def login_required(f):
    @wraps(f)
    def wrapped_view(**kwargs):
        if "user" not in session:
            return redirect(url_for('views.login'))
        return f( **kwargs)

    return wrapped_view


@views.route('/login',methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for('views.home'))

    auth = request.authorization
    if not auth:
        return ('Unauthorized', 401, {
            'WWW-Authenticate': 'Basic realm="Login Required"'
        })

    user = User.query.filter_by(username=request.authorization.username).first()
    if user:
        if user.check_password(request.authorization.password):
            session["user"] = user.username
            return redirect(url_for("views.home"))
        else:
           return ('Unauthorized', 401, {
                'WWW-Authenticate': 'Basic realm="Invalid Password for the user!"'
            })

    new_user = User(username=request.authorization.username, password='meh')
    new_user.set_password(request.authorization.password)
    db.session.add(new_user)
    db.session.commit()

    session["user"] = new_user.username
    return redirect(url_for("views.home"))


@views.get('/')
@login_required
def home():
    return render_template("home.html")

