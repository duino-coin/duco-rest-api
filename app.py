from gevent import monkey
monkey.patch_all()
from flask_caching import Cache
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from re import sub
from hashlib import sha1
from xxhash import xxh64
from fastrand import pcg32bounded as fastrandint
from re import match
from time import sleep, time
from sqlite3 import connect as sqlconn
from flask import Flask, request, jsonify, render_template
from json import load
from bcrypt import hashpw, gensalt, checkpw
from Server import (
    now,
    jail,
    global_last_block_hash,
    DATABASE,
    DUCO_EMAIL,
    DUCO_PASS,
    DB_TIMEOUT,
    CONFIG_MINERAPI,
    CONFIG_TRANSACTIONS,
    API_JSON_URI,
    BCRYPT_ROUNDS,
    user_exists,
    email_exists,
    send_registration_email,
    DECIMALS,
    perm_ban,
    CONFIG_BANS, CONFIG_JAIL,
    NodeS_Overide
)
import ssl
import requests
import traceback
import smtplib
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_ipban import IpBan


transactions = []
last_transactions_update = 0
miners = []
last_miners_update = 0
balances = []
last_balances_update = 0
last_transfer = {}
rate_count = {}
banlist = []
jailedusr = []
overrides = [NodeS_Overide, DUCO_PASS]
DB_TIMEOUT = 5
SAVE_TIME = 10
config = {
    "DEBUG": False,
    "CACHE_TYPE": "SimpleCache",
    "CACHE_DEFAULT_TIMEOUT": 10
}

app = Flask(__name__, template_folder='config/error_pages')
app.config.from_mapping(config)
cache = Cache(app)
limiter = Limiter(
    app,
    default_limits=["10000 per day", "1 per second"]
)
ip_ban = IpBan(ban_seconds=60)
ip_ban.init_app(app)

with open(CONFIG_JAIL, "r") as jailedfile:
    jailedusr = jailedfile.read().splitlines()
    for username in jailedusr:
        jail.append(username)
    print("Successfully loaded jailed usernames file")

with open(CONFIG_BANS, "r") as bannedusrfile:
    bannedusr = bannedusrfile.read().splitlines()
    for username in bannedusr:
        banlist.append(username)
    print("Successfully loaded banned usernames file")



def dbg(*message):
    pass
    #print(*message)


@app.errorhandler(429)
def perror429(e):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    dbg("/GET/429", ip_addr)

    ip_ban.add(ip=ip_addr)

    return render_template('429.html'), 429


@app.errorhandler(404)
def rror404(e):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    dbg("/GET/404")

    ip_ban.add(ip=ip_addr)

    return render_template('404.html'), 404


@app.errorhandler(500)
def error500(e):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    dbg("/GET/500")

    ip_ban.add(ip=ip_addr)

    return render_template('500.html'), 500


def _success(result, code=200):
    return jsonify(success=True, result=result), code


def _error(string, code=200):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    ip_ban.add(ip=ip_addr)
    return jsonify(success=False, message=string), code


def get_all_transactions():
    global last_transactions_update
    global transactions

    now = time()
    if now - last_transactions_update > SAVE_TIME:
        try:
            with sqlconn(CONFIG_TRANSACTIONS, timeout=DB_TIMEOUT) as conn:
                # print(f'fetching transactions from {CONFIG_TRANSACTIONS}')
                datab = conn.cursor()
                datab.execute("SELECT * FROM Transactions")
                rows = datab.fetchall()

            transactions = {}
            for row in rows:
                transactions[row[4]] = row_to_transaction(row)

            last_transactions_update = time()
        except Exception as e:
            print(traceback.format_exc())
            pass

    return transactions.copy()


def row_to_transaction(row):
    return {
        'datetime': str(row[0]),
        'sender': str(row[1]),
        'recipient': str(row[2]),
        'amount': float(row[3]),
        'hash': str(row[4]),
        'memo': str(row[5])
    }


def get_transactions(username: str, limit=20):
    # transactions for user
    transactions = get_all_transactions()

    user_transactions = []
    for transaction in transactions:
        if (transactions[transaction]["sender"] == username
                or transactions[transaction]["recipient"] == username):
            user_transactions.append(transactions[transaction])

    return user_transactions[-limit:]


def get_all_miners():
    global last_miners_update
    global miners

    now = time()
    if now - last_miners_update > SAVE_TIME:
        try:
            with sqlconn(CONFIG_MINERAPI, timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute("SELECT * FROM Miners")
                rows = datab.fetchall()

            if len(rows) > 1500:
                miners_cp = {}
                for row in rows:
                    if not row[1] in miners_cp:
                        miners_cp[row[1]] = []
                    miners_cp[row[1]].append(row_to_miner(row))
                miners = miners_cp
            last_miners_update = time()
        except:
            pass

    return miners.copy()


def row_to_miner(row):
    return {
        "threadid":   row[0],
        "username":   row[1],
        "hashrate":   row[2],
        "sharetime":  row[3],
        "accepted":   row[4],
        "rejected":   row[5],
        "diff":       row[6],
        "software":   row[7],
        "identifier": row[8],
        "algorithm":  row[9]
    }


def get_miners(username: str):
    # For /users/
    miners = get_all_miners()
    return miners[username]


def get_all_balances():
    global last_balances_update
    global balances

    now = time()
    if now - last_balances_update > SAVE_TIME:
        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            # print(f'fetching balances from {DATABASE}')
            datab = conn.cursor()
            datab.execute("SELECT * FROM Users")
            rows = datab.fetchall()
            # print(f'done fetching balances from {DATABASE}')

        balances = {}
        for row in rows:
            balances[row[0]] = row[3]

        last_balances_update = time()

    return balances.copy()


def row_to_balance(row):
    return {
        'username': str(row[0]),
        'balance': float(row[3])
    }


def get_balance(username: str):
    balances = get_all_balances()
    balance = {
        "username": username,
        "balance": balances[username]
    }
    return balance


@app.route("/ping/")
@cache.cached(timeout=SAVE_TIME)
def ping():
    return _success("Pong!")


@app.route("/auth/")
@limiter.limit("2 per minute")
def api_auth():
    username = str(request.args.get('username', None))
    unhashed_pass = str(request.args.get('password', None)).encode('utf-8')
    dbg("/GET/auth", username, unhashed_pass)

    if unhashed_pass.decode() == DUCO_PASS:
        return _success("Logged in")

    if username in banlist:
        return _error("User banned")

    try:
        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            # print(f'fetching user from {DATABASE}')
            # User exists, read his password
            datab = conn.cursor()
            datab.execute(
                """SELECT *
                    FROM Users
                    WHERE username = ?""",
                (str(username),))
            stored_password = datab.fetchone()[1]

        try:
            if checkpw(unhashed_pass, stored_password):
                return _success("Logged in")
            else:
                print("Invalid", unhashed_pass, username)
                return _error("Invalid password")
        except Exception as e:
            if checkpw(unhashed_pass, stored_password.encode('utf-8')):
                return _success("Logged in")
            else:
                return _error("Invalid password")
    except Exception as e:
        return _error("No user found")


@app.route("/new_wallet/")
@limiter.limit("1 per day")
def api_wallet():
    username = request.args.get('username', None)
    unhashed_pass = str(request.args.get('password', None)).encode('utf-8')
    email = request.args.get('email', None)
    dbg("/GET/new_wallet", username, unhashed_pass, email)

    if not match(r"^[A-Za-z0-9_-]*$", username):
        return _error("You have used unallowed characters in the username")

    if len(username) > 64 or len(unhashed_pass) > 128 or len(email) > 64:
        return _error("Submited data is too long")

    if user_exists(username):
        return _error("This username is already registered")

    if not "@" in email or not "." in email:
        return _error("You have provided an invalid e-mail address")

    if email_exists(email):
        return _error("This e-mail address was already used")

    try:
        password = hashpw(unhashed_pass, gensalt(rounds=BCRYPT_ROUNDS))
    except Exception as e:
        return _error("Bcrypt error: " +
                      str(e) + ", plase try using a different password")

    if send_registration_email(username, email):
        while True:
            try:
                with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
                    datab = conn.cursor()
                    datab.execute(
                        """INSERT INTO Users
                        (username, password, email, balance)
                        VALUES(?, ?, ?, ?)""",
                        (username, password, email, .0))
                    conn.commit()
                    break
            except:
                pass
        print("Registered", username, email, unhashed_pass)
        return _success("Sucessfully registered a new wallet")
    else:
        return _error("Error sending verification e-mail")


@app.route("/miners/<username>")
@cache.cached(timeout=SAVE_TIME)
def get_miners_api(username: str):
    # Get all miners
    try:
        miners = get_all_miners()
        return _success(miners[username])
    except:
        return _error("No miners detected on that account")


@app.route("/users/<username>")
@cache.cached(timeout=SAVE_TIME)
def api_get_user_objects(username: str):
    limit = int(request.args.get('limit', 20))
    try:
        balance = get_balance(username)
    except Exception as e:
        return _error("This user doesn't exist")

    try:
        miners = get_miners(username)
    except Exception as e:
        miners = []

    try:
        transactions = get_transactions(username, limit=limit)
    except Exception as e:
        transactions = []

    result = {
        'balance': balance,
        'miners': miners,
        'transactions': transactions
    }

    return _success(result)


@app.route("/transactions/<hash>")
@cache.cached(timeout=SAVE_TIME)
def get_transaction_by_hash(hash: str):
    # Get all transactions
    try:
        transactions = get_all_transactions()
        for transaction in transactions:
            if transactions[transaction]["hash"] == hash:
                return _success(transactions[transaction])
        return _error("No transaction found")
    except Exception as e:
        return _error("No transaction found")


@app.route("/balances/<username>")
@cache.cached(timeout=SAVE_TIME)
def api_get_user_balance(username: str):
    try:
        return _success(get_balance(username))
    except Exception as e:
        return _error("This user doesn't exist")


@app.route("/balances")
@cache.cached(timeout=SAVE_TIME)
def api_get_all_balances():
    try:
        return _success(get_all_balances())
    except Exception as e:
        return _error("Error fetching balances: " + str(e))


@app.route("/transactions")
@cache.cached(timeout=SAVE_TIME)
def api_get_all_transactions():
    try:
        return _success(get_all_transactions())
    except Exception as e:
        return _error("Error fetching transactions: " + str(e))


@app.route("/miners")
@cache.cached(timeout=SAVE_TIME)
def api_get_all_miners():
    try:
        return _success(get_all_miners())
    except Exception as e:
        print(str(e))
        return _error("Error fetching miners: " + str(e))


@app.route("/statistics")
@cache.cached(timeout=SAVE_TIME)
def get_api_data():
    data = {}
    with open(API_JSON_URI, 'r') as f:
        try:
            data = load(f)
        except:
            pass

    return jsonify(data)


@app.route("/exchange_request/")
@limiter.limit("3 per day")
def exchange_request():
    username = str(request.args.get('username', None))
    unhashed_pass = request.args.get('password', None).encode('utf-8')
    email = str(request.args.get('email', None))

    dbg("/GET/exchange_request", username, email)

    ex_type = str(request.args.get('type', None)).upper()
    amount = float(request.args.get('amount', None))
    coin = str(request.args.get('coin', None))
    address = str(request.args.get('address', None))

    if username in banlist:
        return _error("User is banned")

    # Check email
    try:
        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """SELECT *
                    FROM Users
                    WHERE username = ?""",
                (str(username),))
            stored_mail = datab.fetchone()[2]
        if not email == stored_mail:
            return _error(
                "This e-mail is not associated with your Duino-Coin account")
    except Exception as e:
        return _error("No user found: " + str(e))

    # Check password
    try:
        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """SELECT *
                    FROM Users
                    WHERE username = ?""",
                (str(username),))
            stored_password = datab.fetchone()[1]
        try:
            if not checkpw(unhashed_pass, stored_password):
                return _error("Invalid password")
        except Exception as e:
            if not checkpw(unhashed_pass, stored_password.encode('utf-8')):
                return _error("Invalid password")
    except Exception as e:
        return _error("No user found: " + str(e))

    # Check the amount
    if coin.lower() == "xrp" and amount < 240:
        return _error("Minimum exchangeable amount for XRP is 240 DUCO")
    if amount < 200:
        return _error("Minimum exchangeable amount is 200 DUCO")
    if amount > 10000:
        return _error("Maximum exchangeable amount is 10000 DUCO")

    if ex_type.upper() == "SELL":
        balance = get_balance(username)["balance"]
        if amount > balance:
            return _error("You don't have enough DUCO in your account ("
                          + str(balance)+")")

    # Get currenct exchange rates
    try:
        de_api = requests.get("https://github.com/revoxhere/duco-exchange/"
                              + "raw/master/api/v1/rates",
                              data=None).json()["result"]
    except Exception as e:
        print("Using cached exchange data", traceback.format_exc())
        de_api = {
            "result": {
                "bch": {
                    "sell": 0.000002,
                    "buy": 0.0000035,
                    "liquidity": "MEDIUM"
                },
                "xmg": {
                    "sell": 0.5,
                    "buy": 1,
                    "liquidity": "GOOD"
                },
                "lke": {
                    "sell": 1,
                    "buy": 1.1,
                    "liquidity": "GOOD"
                },
                "trx": {
                    "sell": 0.015,
                    "buy": 0.0375,
                    "liquidity": "LOW"
                },
                "dgb": {
                    "sell": 0.0225,
                    "buy": 0.0375,
                    "liquidity": "LOW"
                },
                "xrp": {
                    "sell": 0.00125,
                    "buy": 0.00325,
                    "liquidity": "LOW"
                },
                "nano": {
                    "sell": 0.00025,
                    "buy": 0.000375,
                    "liquidity": "LOW"
                }
            },
            "success": true
        }

        de_api = de_api["result"]
    try:
        exchanged_amount = round(
            de_api[coin.lower()][ex_type.lower()]*amount,
            len(str(de_api[coin.lower()][ex_type.lower()]))
        )
    except Exception as e:
        return _error("That coin isn't listed (yet): " + str(e))

    # Send exchange request
    html = """\
        <html>
          <body>
            <p style="font-size:18px">
                All checks for this user passed, exchange data:<br>
                Type: <b>""" + str(ex_type) + """</b><br>
                Username: <b>""" + str(username) + """</b><br>
                Amount: <b>""" + str(amount) + """</b> DUCO<br>

                Email: <b>""" + str(email) + """</b><br>

                Address: <b>""" + str(address) + """</b><br>
                Send: <b>""" + str(exchanged_amount) + """</b> """ + coin.upper() + """<br>
            </p>
          </body>
        </html>"""

    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = ("DUCO - "
                              + str(coin).upper()
                              + " "
                              + ex_type.upper()
                              + " Request")
        message["From"] = DUCO_EMAIL
        message["To"] = DUCO_EMAIL
        part = MIMEText(html, "html")
        message.attach(part)
        context = ssl.create_default_context()

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
            smtp.login(
                DUCO_EMAIL, DUCO_PASS)
            smtp.sendmail(
                DUCO_EMAIL, DUCO_EMAIL, message.as_string())
    except Exception as e:
        print(traceback.format_exc())
        return _error("Error sending an e-mail to the exchange system")

    return _success("Your exchange request has been successfully submited")


@app.route("/transaction/")
@limiter.limit("2 per minute")
def api_transaction():
    global last_transfer
    global banlist
    global rate_count
    username = request.args.get('username', None)
    unhashed_pass = request.args.get('password', None).encode('utf-8')
    recipient = request.args.get('recipient', None)
    amount = request.args.get('amount', None)
    memo = request.args.get('memo', None)[0:30]
    memo = sub(r'[^A-Za-z0-9 .()-:/!#_+-]+', ' ', str(memo))

    dbg("/GET/transaction", username, amount, recipient, memo)

    if recipient in banlist:
        return _error("NO,Cant send funds to that user")

    if username in banlist:
        print("Banning", username, request.environ.get(
            'HTTP_X_REAL_IP', request.remote_addr))
        perm_ban(str(request.environ.get(
            'HTTP_X_REAL_IP', request.remote_addr)), perm=True)
        return _error("NO,User baned")

    if memo == "-" or memo == "":
        memo = "None"

    if round(float(amount), DECIMALS) <= 0:
        return _error("NO,Incorrect amount")

    if not user_exists(username):
        return _error("NO,User doesnt exist")

    if not user_exists(recipient):
        return _error("NO,Recipient doesnt exist")

    if username in rate_count:
        if rate_count[username] >= 3:
            banlist.append(username)

    if username in last_transfer:
        if (now() - last_transfer[username]).total_seconds() <= 30:
            print("Rate limiting", username,
                  (now() - last_transfer[username]).total_seconds(), "s")
            return _error(
                "NO,Please wait some time before doing the next transaction")
            try:
                rate_count[username] += 1
            except:
                rate_count[username] = 1

    if not unhashed_pass.decode() in overrides:
        try:
            with sqlconn(DATABASE, timeout=15) as conn:
                # print(f'fetching user from {DATABASE}')
                # User exists, read his password
                datab = conn.cursor()
                datab.execute(
                    """SELECT *
                        FROM Users
                        WHERE username = ?""",
                    (str(username),))
                stored_password = datab.fetchone()[1]

            try:
                if not checkpw(unhashed_pass, stored_password):
                    return _error("NO,Invalid password")
            except:
                if not checkpw(unhashed_pass, stored_password.encode('utf-8')):
                    return _error("NO,Invalid password")
        except Exception as e:
            return _error("NO,No user found: " + str(e))
    else:
        memo = str(memo) + " OVERRIDE"

    try:
        import random
        random = random.randint(0, 77777)
        if random < 37373:
            global_last_block_hash_cp = sha1(
                bytes(str(username)+str(amount)+str(random),
                      encoding='ascii')).hexdigest()
        else:
            global_last_block_hash_cp = xxh64(
                bytes(str(username)+str(amount)+str(random),
                      encoding='ascii'), seed=2811).hexdigest()

        if str(recipient) == str(username):
            return _error("NO,You\'re sending funds to yourself")

        if (str(amount) == "" or float(amount) <= 0):
            return _error("NO,Incorrect amount")

        with sqlconn(DATABASE,
                     timeout=15) as conn:
            datab = conn.cursor()
            datab.execute(
                """SELECT *
                        FROM Users
                        WHERE username = ?""",
                (username,))
            balance = float(datab.fetchone()[3])

        if (float(balance) <= float(amount)):
            return _error("NO,Incorrect amount")

        try:
            with sqlconn(DATABASE,
                         timeout=15) as conn:
                datab = conn.cursor()
                datab.execute(
                    """SELECT *
                        FROM Users
                        WHERE username = ?""",
                    (recipient,))
                recipientbal = float(datab.fetchone()[3])
        except:
            return _error("NO,Recipient doesn\'t exist")

        if float(balance) >= float(amount):
            balance -= float(amount)
            recipientbal += float(amount)

            while True:
                try:
                    with sqlconn(DATABASE,
                                 timeout=15) as conn:
                        datab = conn.cursor()
                        datab.execute(
                            """UPDATE Users
                            set balance = ?
                            where username = ?""",
                            (balance, username))
                        datab.execute(
                            """UPDATE Users
                            set balance = ?
                            where username = ?""",
                            (round(float(recipientbal), 20), recipient))
                        conn.commit()
                        break
                except:
                    pass

            formatteddatetime = now().strftime("%d/%m/%Y %H:%M:%S")
            with sqlconn(CONFIG_TRANSACTIONS,
                         timeout=15) as conn:
                datab = conn.cursor()
                datab.execute(
                    """INSERT INTO Transactions
                    (timestamp, username, recipient, amount, hash, memo)
                    VALUES(?, ?, ?, ?, ?, ?)""",
                    (formatteddatetime,
                        username,
                        recipient,
                        amount,
                        global_last_block_hash_cp,
                        memo))
                conn.commit()

            print("Successfully transferred", amount, "from",
                  username, "to", recipient, global_last_block_hash_cp)
            last_transfer[username] = now()
            return _success("OK,Successfully transferred funds,"
                            + str(global_last_block_hash_cp))
    except Exception as e:
        return _success(
            "NO,Internal server error: "
            + str(traceback.format_exc()))
