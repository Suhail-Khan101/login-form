import os
from flask import Flask

def create_app(test_config=None):
    from flask_wtf import CSRFProtect
    csrf = CSRFProtect()

    # Remove 'Server' header for all responses, including static files
    from werkzeug.middleware.proxy_fix import ProxyFix
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    csrf.init_app(app)
    app.wsgi_app = ProxyFix(app.wsgi_app)
    @app.after_request
    def secure_headers(response):
        # Remove Server header
        if 'Server' in response.headers:
            del response.headers['Server']
        # Add cache-control
        response.headers['Cache-Control'] = 'no-store'
        # Add Spectre-mitigation headers
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
        return response
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev'),
        DATABASE=os.path.join(app.instance_path, 'login_form.sqlite'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)


    @app.after_request
    def add_security_headers(resp):
        # Content Security Policy (CSP) with fallback
        resp.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "img-src 'self' data:; "
            "style-src 'self'; "
            "font-src 'self'; "
            "form-action 'self'; "
            "upgrade-insecure-requests; "
            "block-all-mixed-content; "
        )
        # Remove Server header to prevent version disclosure
        if 'Server' in resp.headers:
            del resp.headers['Server']
        # Cache control headers
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        # Other security headers
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
        resp.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        resp.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        return resp

    return app