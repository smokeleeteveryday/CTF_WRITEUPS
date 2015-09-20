# I apologize to any future developers and anyone else who may have to read this code
# :(

import time, struct, random, socket, hashlib, pyotp, hmac

def FetchOneAssoc(cursor) :
    data = cursor.fetchone()
    if data == None :
        return None
    desc = cursor.description

    res = {}

    for (name, value) in zip(desc, data) :
        res[name[0]] = value

    return res

def check_username(username):
    cursor = mysql.connection.cursor()
    cursor.execute(
        'select * from users where user_name = %s limit 1',
        (username,)
    )
    rv = FetchOneAssoc(cursor)
    #rv = cursor.fetchone()
    return rv

def check_user_id(user_id):
    cursor = mysql.connection.cursor()
    cursor.execute("select * from users where user_id=%s limit 1", (user_id,))
    return FetchOneAssoc(cursor)

def generate_seed(username, ip_address):
    return int(struct.unpack('I', socket.inet_aton(ip_address))[0]) + struct.unpack('I', username[:4].ljust(4,'0'))[0]

def get_totp_key(seed):
    random.seed(seed)
    return pyotp.random_base32(16, random)

def register_user(username, password, ip_address):
    password = hashlib.sha256(username+password).hexdigest()
    cursor = mysql.connection.cursor()
    cursor.execute(
        "insert into users (user_name, user_password, user_ip) VALUES (%s, %s, %s)",
        (username, password, ip_address)
    )
    mysql.connection.commit()

def auth_user(username, password):
    cursor = mysql.connection.cursor()
    cursor.execute(
        "select * from users where user_name = %s and user_password = %s limit 1",
        (username, hashlib.sha256(username+password).hexdigest())
    )
    rv = cursor.fetchone()
    if not rv:
        return False

    return True

def make_cookie(secret, username, ip, timestamp=None):
    if not timestamp:
        timestamp = int(time.time())
    base_cookie = '%s_%s' % (username, str(timestamp))
    hmac_builder = hmac.new(secret, digestmod=hashlib.sha1)
    hmac_builder.update(base_cookie)
    return '%s_%s' % (base_cookie, hmac_builder.hexdigest())

def validate_cookie(secret, input_cookie):
    parts = input_cookie.split("_")
    if len(parts) != 3:
        return False

    input_username = parts[0]
    input_time = parts[1]
    input_hmac = parts[2]

    regen_cookie = make_cookie(secret, input_username, '', input_time)
    regen_cookie = regen_cookie.split("_")
    if input_hmac != regen_cookie[2]:
        return False

    #print (int(input_time)-int(time.time()))
    if (int(time.time())-int(input_time)) &gt; 1000*3600:
        return False

    if not check_username(input_username):
        return False
    
    return True

def get_user_from_cookie(request):
    cookie = request.cookies.get("session") or ""
    if not cookie:
        return False

    user = cookie.split("_")[0]
    return check_username(user)

def update_user_profile(user_id, image_url, profile_text):
    cursor = mysql.connection.cursor()
    cursor.execute(
        "update users set user_image=%s, user_profile=%s where user_id=%s",
        (image_url, profile_text, user_id,)
    )
    mysql.connection.commit()

def get_message_by_id(message_id):
    cursor = mysql.connection.cursor()
    cursor.execute(
        "select * from messages where message_id = %s",
        (message_id,)
    )

    message = FetchOneAssoc(cursor)
    print "hell", message
    if not message:
        return {}

    try:
        message["message_from_username"] = check_user_id(message["message_from"])["user_name"]
        message["message_to_username"] = check_user_id(message["message_to"])["user_name"]
    except:
        message["message_from_username"] = 'nobody'
        message["message_to_username"] = 'nobody'

    return message

def get_messages_for_user(user_id):
    cursor = mysql.connection.cursor()
    cursor.execute(
        "select * from messages where %s in (message_to, message_from) order by message_id desc limit 25",
        (user_id,)
    )

    messages = []

    while True:
        message_data = FetchOneAssoc(cursor)
        if not message_data:
            break

        try:
            message_data["message_from_username"] = check_user_id(message_data["message_from"])["user_name"]
            message_data["message_to_username"] = check_user_id(message_data["message_to"])["user_name"]
        except:
            message_data["message_from_username"] = 'nobody'
            message_data["message_to_username"] = 'nobody'

        messages.append(message_data)

    return messages

def create_message(message_to, message_from, message_title, message_contents):
    cursor = mysql.connection.cursor()
    cursor.execute(
        "insert into messages (message_to, message_from, message_title, message_contents) values (%s, %s, %s, %s)",
        (message_to, message_from, message_title, message_contents,)
    )
    mysql.connection.commit()

def insert_csp_report(report_ip, report_content):
    cursor = mysql.connection.cursor()
    cursor.execute(
        "insert into reports (report_ip, report_content) values (%s, %s)",
        (report_ip, report_content,)
    )
    mysql.connection.commit()
    return cursor.lastrowid

def get_csp_report(report_id):
    cursor = mysql.connection.cursor()
    cursor.execute(
        "select * from reports where report_id = %s"%
        (report_id,)
    )

    return FetchOneAssoc(cursor)

def search(search_string):
    search_string = "%"+search_string+"%"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "select * from users where user_name like %s or user_profile like %s order by user_id asc limit 20",
        (search_string, search_string,)
    )

    users = []
    while True:
        user_data = FetchOneAssoc(cursor)
        if not user_data:
            break

        users.append(user_data)

    return users

