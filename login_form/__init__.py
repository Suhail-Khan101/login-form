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
    # Remove Server header from all responses (including static and errors)
    from werkzeug.middleware.http_proxy import ProxyMiddleware
    class RemoveServerHeaderMiddleware:
        def __init__(self, app):
            self.app = app
        def __call__(self, environ, start_response):
            def custom_start_response(status, headers, exc_info=None):
                headers = [(k, v) for (k, v) in headers if k.lower() != 'server']
                return start_response(status, headers, exc_info)
            return self.app(environ, custom_start_response)
    app.wsgi_app = RemoveServerHeaderMiddleware(app.wsgi_app)
    # Unified after_request for all security and cache-control headers
    @app.after_request
    def add_security_and_cache_headers(resp):
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
        # Set cache headers for static files
        if resp.status_code == 200 and resp.direct_passthrough is False and hasattr(resp, 'headers') and hasattr(resp, 'mimetype') and resp.mimetype and resp.mimetype.startswith(('text/css', 'image/', 'font/', 'application/javascript')):
            resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
            resp.headers.pop('Pragma', None)
            resp.headers.pop('Expires', None)
        elif '/static/' in getattr(resp, 'location', '') or (hasattr(resp, 'request') and getattr(resp.request, 'path', '').startswith('/static/')):
            resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
            resp.headers.pop('Pragma', None)
            resp.headers.pop('Expires', None)
        else:
            resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            resp.headers['Pragma'] = 'no-cache'
            resp.headers['Expires'] = '0'
        # Other security headers
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
        resp.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        resp.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        resp.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
        return resp
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev'),
        DATABASE=os.path.join(app.instance_path, 'login_form.sqlite'),
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=True,
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
        from flask import make_response
        response = make_response('Hello, World!')
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        return response

    @app.route('/')
    def index():
        from flask import render_template, make_response
        return make_response(render_template('index.html'), 200)

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)


    # Remove any duplicate after_request handlers above

    # 404 error handler with cache-control
    @app.errorhandler(404)
    def not_found_error(error):
    from flask import make_response
    response = make_response('Not Found', 404)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

    # 400 error handler with cache-control
    @app.errorhandler(400)
    def bad_request_error(error):
    from flask import make_response
    response = make_response('Bad Request', 400)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
    return app 