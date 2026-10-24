"""
Remediated version of app/app.py from we45/Vulnerable-Flask-App.
CodeAlpha Cyber Security Internship, Task 3: Secure Coding Review (by Hamsa).

Required environment variables before running:
    SECRET_KEY_HMAC   signing key for JWT tokens
    FLASK_SECRET_KEY  Flask session key
    ADMIN_PASSWORD    password for the initial admin account
"""
import datetime
import json
import os
import secrets
import uuid

import jwt
import yaml
from docx import Document
from faker import Faker
from flask import Flask, Response, jsonify, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from jwt.exceptions import InvalidTokenError
from markupsafe import escape
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.wsgi import WSGIContainer
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app_port = int(os.environ.get("APP_PORT", 5050))
app_host = os.environ.get("APP_HOST", "127.0.0.1")
UPLOAD_DIR = os.path.join(os.getcwd(), "Files")

app = Flask(__name__, template_folder="templates")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
# FIX F5: secrets come from the environment, never from source code
app.config["SECRET_KEY_HMAC"] = os.environ["SECRET_KEY_HMAC"]
app.secret_key = os.environ["FLASK_SECRET_KEY"]
# FIX F11: limit upload size to 2 MB
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # stores a salted hash


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    email = db.Column(db.String(80))
    ccn = db.Column(db.String(4), nullable=True)  # FIX F8: last 4 digits only
    username = db.Column(db.String(80))
    password = db.Column(db.String(255))


def setup_users():
    db.create_all()
    if not User.query.first():
        # FIX F6/F7: admin password from environment, stored as a salted hash
        admin_pw = os.environ["ADMIN_PASSWORD"]
        db.session.add(User(username="admin", password=generate_password_hash(admin_pw)))
        db.session.commit()
    if not Customer.query.first():
        fake = Faker()
        for _ in range(5):
            profile = fake.simple_profile(sex=None)
            db.session.add(Customer(
                first_name=fake.first_name(),
                last_name=fake.last_name(),
                email=profile["mail"],
                username=profile["username"],
                password=generate_password_hash(secrets.token_urlsafe(16)),
                ccn=fake.credit_card_number(card_type=None)[-4:],
            ))
        db.session.commit()


def get_exp_date():
    # FIX F14: shorter token lifetime (30 minutes instead of 240)
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)


def verify_jwt(token):
    """Always verifies signature, issuer and expiry."""
    try:
        jwt.decode(
            token, app.config["SECRET_KEY_HMAC"], issuer="we45", leeway=10,
            algorithms=["HS256"], options={"require": ["exp", "iss"]},
        )
        return True
    except InvalidTokenError:
        return False


def authenticated():
    token = request.headers.get("Authorization", "")
    return bool(token) and verify_jwt(token)


def customer_to_dict(c):
    return {
        "id": c.id, "firstname": c.first_name, "lastname": c.last_name,
        "email": c.email, "cc_num": "************" + (c.ccn or ""), "username": c.username,
    }


def save_upload(file_storage, allowed_ext):
    """FIX F11/F13: extension allow-list, random unguessable file name."""
    name = secure_filename(file_storage.filename or "")
    ext = os.path.splitext(name)[1].lower()
    if not name or ext not in allowed_ext:
        return None
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    path = os.path.join(UPLOAD_DIR, uuid.uuid4().hex + ext)
    file_storage.save(path)
    return path


@app.errorhandler(404)
def pnf(e):
    # FIX F4: no render_template_string with user input; output is HTML-escaped
    body = ("<html><head><title>Error</title></head><body>"
            "<h1>Oops that page doesn't exist!!</h1><h3>%s</h3></body></html>") % escape(request.url)
    return body, 404


def has_no_empty_params(rule):
    default = rule.defaults if rule.defaults is not None else ()
    arguments = rule.arguments if rule.arguments is not None else ()
    return len(default) >= len(arguments)


@app.route("/", methods=["GET"])
def sitemap():
    links = []
    for rule in app.url_map.iter_rules():
        if ("GET" in rule.methods or "POST" in rule.methods) and has_no_empty_params(rule):
            if "static" not in rule.endpoint:
                url = url_for(rule.endpoint, **(rule.defaults or {}))
                links.append((url, rule.endpoint, ",".join(rule.methods)))
    return render_template("index.html", urls=links)


@app.route("/register/user", methods=["POST"])
def reg_user():
    content = request.get_json(silent=True) or {}
    username, password = content.get("username"), content.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or len(password) < 8:
        return jsonify({"Error": "Invalid input"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"Error": "Username unavailable"}), 409
    # FIX F6: salted hash instead of unsalted MD5
    db.session.add(User(username=username, password=generate_password_hash(password)))
    db.session.commit()
    return jsonify({"Created": "User has been created"}), 201


@app.route("/register/customer", methods=["POST"])
def reg_customer():
    c = request.get_json(silent=True) or {}
    fields = ("username", "password", "first_name", "last_name", "email", "ccn")
    if not all(isinstance(c.get(f), str) and c.get(f) for f in fields) or len(c["password"]) < 8:
        return jsonify({"Error": "Invalid input"}), 400
    cust = Customer(
        first_name=c["first_name"], last_name=c["last_name"], email=c["email"],
        username=c["username"], password=generate_password_hash(c["password"]),
        ccn=c["ccn"][-4:],  # FIX F8: never store the full card number
    )
    db.session.add(cust)
    db.session.commit()
    return jsonify({"Created": "Customer has been created"}), 201


@app.route("/login", methods=["POST"])
def login():
    content = request.get_json(silent=True) or {}  # FIX F10: credentials are never logged
    username, password = content.get("username"), content.get("password")
    user = User.query.filter_by(username=username).first() if isinstance(username, str) else None
    if user and isinstance(password, str) and check_password_hash(user.password, password):
        now = datetime.datetime.now(datetime.timezone.utc)
        token = jwt.encode(
            {"user": username, "exp": get_exp_date(), "nbf": now, "iss": "we45", "iat": now},
            app.config["SECRET_KEY_HMAC"], algorithm="HS256",
        )
        resp = Response(json.dumps({"Authenticated": True, "User": username}),
                        mimetype="application/json")
        resp.headers["Authorization"] = token
        return resp
    return jsonify({"Error": "Invalid credentials"}), 401  # generic message


@app.route("/fetch/customer", methods=["POST"])
def fetch_customer():
    if not authenticated():
        return jsonify({"Error": "Not Authenticated!"}), 403
    content = request.get_json(silent=True) or {}
    customer = db.session.get(Customer, content.get("id"))
    if not customer:
        return jsonify({"Error": "No Customer Found"}), 404
    return jsonify(customer_to_dict(customer)), 200


@app.route("/get/<int:cust_id>", methods=["GET"])
def get_customer(cust_id):
    # FIX F3: signature is now verified (insecure_verify removed)
    if not authenticated():
        return jsonify({"Error": "Not Authenticated!"}), 403
    customer = db.session.get(Customer, cust_id)
    if not customer:
        return jsonify({"Error": "No Customer Found"}), 404
    return jsonify(customer_to_dict(customer)), 200


@app.route("/search", methods=["POST"])
def search_customer():
    if not authenticated():
        return jsonify({"Error": "Not Authenticated!"}), 403
    content = request.get_json(silent=True) or {}
    term = content.get("search")
    if not isinstance(term, str):
        return jsonify({"Error": "Invalid Request"}), 400
    # FIX F1: ORM query, parameters are bound, never concatenated into SQL
    rows = (Customer.query.filter_by(username=term)
            .with_entities(Customer.first_name, Customer.last_name, Customer.username).all())
    return jsonify([list(r) for r in rows]), 200


@app.route("/xxe")
def index():
    return render_template("test.html")


@app.route("/xxe_uploader", methods=["GET", "POST"])
def hello():
    if request.method == "POST":
        f = request.files.get("file")
        path = save_upload(f, {".docx"}) if f else None
        if not path:
            return jsonify({"Error": "Only .docx files are accepted"}), 400
        document = Document(path)
        text = "\n".join(p.text for p in document.paragraphs)
        return render_template("view.html", name=text)
    return render_template("test.html")


@app.route("/yaml")
def yaml_upload():
    return render_template("yaml_test.html")


@app.route("/yaml_hammer", methods=["POST"])
def yaml_hammer():
    f = request.files.get("file")
    path = save_upload(f, {".yaml", ".yml"}) if f else None
    if not path:
        return jsonify({"Error": "Only .yaml files are accepted"}), 400
    with open(path, "r", encoding="utf-8") as yfile:
        ydata = yaml.safe_load(yfile)  # FIX F2: safe_load, no object construction
    return render_template("view.html", name=json.dumps(ydata))


if __name__ == "__main__":
    with app.app_context():
        setup_users()
    HTTPServer(WSGIContainer(app)).listen(app_port, address=app_host)
    IOLoop.current().start()
