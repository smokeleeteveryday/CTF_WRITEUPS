from flask import Flask, render_template, request, Response, redirect
from flask.ext.mysqldb import MySQL
from functools import wraps
import os, pwd, grp, random, struct, time, pyotp, urllib2, urlparse, imghdr, sys
import utils
sys.path.insert(0, "/home/csaw/development/weeb")

import logging, sys
logging.basicConfig(stream=sys.stderr)

app = Flask(__name__)
app.config.from_object("settings")
mysql = MySQL()
mysql.init_app(app)
utils.mysql = mysql

def render_page(content, page_name, user=None):
    return render_template("base.html", page_name=page_name, page_content=content, user=user)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        cookie = request.cookies.get("session")
        if (cookie and (utils.validate_cookie(app.config["COOKIE_SECRET"], cookie))):
            return f(*args, **kwargs)
        else:
            return redirect("/login")
    return decorated_function

@app.after_request
def after_request(response):
    response.headers.add('Content-Security-Policy', 'script-src "self" https://apis.google.com; report-uri /csp/violate')
    return response

@app.route("/csp/violate", methods=["GET", "POST"])
def csp_violate():
    report_id = utils.insert_csp_report(request.remote_addr, request.data)
    message_body = {"message": "Thoroughly violated, thanks", "view_url":"/csp/view/"+str(report_id)}
    return Response(repr(message_body), mimetype="text/json")

@app.route("/csp/view/<report_id>")
def csp_view(report_id):
    return Response(repr(utils.get_csp_report(report_id)), mimetype="text/json")

@app.route("/")
def index():
    user = utils.get_user_from_cookie(request)
    page_name = 'home page'
    page_content = render_template("home.html")
    return render_page(page_content, page_name, user=user)

@app.route("/register", methods=["GET", "POST"])
def show_registration():
    user = utils.get_user_from_cookie(request)
    page_name = 'register'

    if request.method.lower() == 'get':
        page_content = render_template("register.html")
        return render_page(page_content, "register", user=user)

    if request.method.lower() == 'post':
        username = request.form.get("username") or ""
        password = request.form.get("password") or ""
        if not username or not password :
            page_content = render_template("register.html", message='Missing field')
            return render_page(page_content, page_name)

        if utils.check_username(username):
            page_content = render_template("register.html", message='That username is taken!')
            return render_page(page_content, page_name)

        seed = utils.generate_seed(username, request.remote_addr)
        totp_key = utils.get_totp_key(seed)
        utils.register_user(username, password, request.remote_addr)
        qr_url = 'http://api.qrserver.com/v1/create-qr-code/?data=otpauth://totp/%s?secret=%s&amp;size=220x220&amp;margin=0'%(username, totp_key)
        page_content = render_template(
            "register.html",
            message="Success! <a href='/login'>login here</a><br />TOTP Key: %s<br /><img src='%s' />" % (totp_key, qr_url)
        )

        return render_page(page_content, page_name)

@app.route("/login", methods=["GET", "POST"])
def show_login():
    page_name = 'login'

    if request.method.lower() == 'get':
        page_content = render_template("login.html")
        return render_page(page_content, "login")

    username = request.form.get("username") or ""
    password = request.form.get("password") or ""
    verification_code = request.form.get("verification_code") or ""

    if not (username and password and verification_code):
        page_content = render_template("login.html", message='Missing field')
        return render_page(page_content, page_name)

    if not utils.auth_user(username, password):
        page_content = render_template("login.html", message='Invalid credentials')
        return render_page(page_content, page_name)

    user = utils.check_username(username)
    seed = utils.generate_seed(username, user["user_ip"])
    totp_key = utils.get_totp_key(seed)
    totp = pyotp.TOTP(totp_key)

    if verification_code != totp.now():
        page_content = render_template("login.html", message='Invalid verification code')
        return render_page(page_content, page_name)

    # user/pass/totp all valid by now
    session_cookie = utils.make_cookie(app.config["COOKIE_SECRET"], username, request.remote_addr)
    response = app.make_response(redirect("/"))
    response.set_cookie('session', session_cookie)
    return response

    page_content = render_template("login.html")
    return render_page(page_content, page_name)

@app.route("/profile/edit", methods=["GET", "POST"])
@require_auth
def edit_profile():
    user = utils.get_user_from_cookie(request)
    page_name = 'edit profile'

    if request.method.lower() == 'get':
        page_content = render_template("edit_profile.html", user=user)
        return render_page(page_content, page_name, user=user)

    image_url = request.form.get("image_url") or ""
    profile_text = request.form.get("profile_text") or ""

    if not (image_url and profile_text):
        page_content = render_template("edit_profile.html", user=user, message='Missing fields')
        return render_page(page_content, page_name, user=user)

    parsed_url = urlparse.urlparse(image_url)
    if not (parsed_url.scheme and parsed_url.netloc and parsed_url.path):
        page_content = render_template("edit_profile.html", user=user, message='Malformed url %s'%(repr(parsed_url)))
        return render_page(page_content, page_name, user=user)

    try:
        contents = urllib2.urlopen(image_url).read()
        if imghdr.what(None, contents) not in ["png", "jpeg", "gif"]:
            page_content = render_template("edit_profile.html", user=user, message='Unknown file type: '+contents)
            return render_page(page_content, page_name, user=user)
    except Exception, e:
        page_content = render_template("edit_profile.html", user=user, message='An exception occurred '+str(e))
        return render_page(page_content, page_name, user=user)

    utils.update_user_profile(user["user_id"], image_url, profile_text)
    user = utils.get_user_from_cookie(request)
    page_content = render_template("edit_profile.html", user=user, message='Success')
    return render_page(page_content, page_name, user=user)

@app.route("/messages/")
def messages_redirect():
    return redirect("/messages/view")

@app.route("/messages/compose", methods=["GET", "POST"])
@require_auth
def message_compose():
    user = utils.get_user_from_cookie(request)
    page_name = 'messages'

    if request.method.lower() == "post":
        message_to = request.form.get("message_to") or ""
        message_title = request.form.get("message_title") or ""
        message_contents = request.form.get("message_contents") or ""

        if not (message_to and message_title and message_contents):
            message = 'Missing field'
            page_content = render_template("compose.html", user=user, message=message)
            return render_page(page_content, page_name, user=user)

        to_user = utils.check_username(message_to)
        if not to_user:
            message = 'Invalid user'
            page_content = render_template("compose.html", user=user, message=message)
            return render_page(page_content, page_name, user=user)

        utils.create_message(to_user["user_id"], user["user_id"], message_title, message_contents)
        return redirect("/messages/view")

    page_content = render_template("compose.html", user=user)
    return render_page(page_content, page_name, user=user)

@app.route("/messages/view")
@require_auth
def messages_view_listing():
    user = utils.get_user_from_cookie(request)
    page_name = 'messages'
    messages = utils.get_messages_for_user(user["user_id"])
    if request.method.lower() == 'get':
        page_content = render_template("view_messages.html", user=user, messages=messages)
        return render_page(page_content, page_name, user=user)

@app.route("/messages/<int:message_id>")
@require_auth
def messages_view_individual(message_id):
    user = utils.get_user_from_cookie(request)
    message = utils.get_message_by_id(message_id)
    page_name = 'message'

    if not message or user["user_id"] not in (message["message_from"], message["message_to"]):
        return redirect("/messages/view")

    page_content = render_template("individual_message.html", user=user, message=message)
    return render_page(page_content, page_name, user=user)

@app.route("/search")
@require_auth
def search():
    page_name = 'search'
    user = utils.get_user_from_cookie(request)
    search_query = request.args.get("query")
    if not search_query:
        page_content = render_template("search.html", user=user, message='')
        return render_page(page_content, page_name, user=user)

    users = utils.search(search_query)
    if not users:
        page_content = render_template("search.html", message='NO USERS FOUND :(', user=user)
        return render_page(page_content, page_name, user=user)

    page_content = render_template("search.html", message='', users=users)
    return render_page(page_content, page_name, user=user)

@app.route("/user/<username>")
@require_auth
def browse_profile(username):
    page_name = 'search'
    user = utils.get_user_from_cookie(request)
    if username and utils.check_username(username):
        user_profile = utils.check_username(username)
        page_content = render_template("user_profile.html", message=None, user_profile=user_profile, user=user)
        return render_page(page_content, page_name)

    return redirect("/")

if __name__ == "__main__":
    #app.run(debug=True, host="0.0.0.0", port=5000)
    app.run(host="0.0.0.0", port=5000)

