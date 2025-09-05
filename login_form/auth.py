import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from login_form.forms import LoginForm, RegisterForm
from werkzeug.security import check_password_hash, generate_password_hash

from login_form.db import get_db
from login_form.user import User

bp = Blueprint('auth', __name__, url_prefix='/')

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        error = None
        if not username:
            error = 'Username is required.'
        if error is None:
            User.create(username, password)
            return redirect(url_for('auth.login'))
        flash(error)
    resp = render_template('register.html', form=form)
    from flask import make_response
    response = make_response(resp)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

@bp.route('/login', methods=('GET', 'POST'))
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        error = None
        user = User.find_with_credentials(username, password)
        if user is None:
            error = 'Incorrect username or password.'
        if error is None:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('auth.index'))
        flash(error)
    resp = render_template('login.html', form=form)
    from flask import make_response
    response = make_response(resp)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = User.find_by_id(user_id)

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view