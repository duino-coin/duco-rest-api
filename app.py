#!/usr/bin/env python3
"""
Duino-Coin REST API © MIT licensed
https://duinocoin.com
https://github.com/revoxhere/duco-rest-api
Duino-Coin Team & Community 2019-2021
"""

import gevent.monkey
gevent.monkey.patch_all()
from wrapped_duco_functions import *
from Server import (
    now, SAVE_TIME, POOL_DATABASE, CONFIG_WHITELIST_USR,
    jail, global_last_block_hash, HOSTNAME,
    DATABASE, DUCO_EMAIL, DUCO_PASS, alt_check, acc_check,
    DB_TIMEOUT, CONFIG_MINERAPI, SERVER_VER,
    CONFIG_TRANSACTIONS, API_JSON_URI,
    BCRYPT_ROUNDS, user_exists, SOCKET_TIMEOUT,
    email_exists, send_registration_email,
    DECIMALS, CONFIG_BANS, protocol_verified_mail,
    CONFIG_JAIL, CONFIG_WHITELIST, perm_ban,
    NodeS_Overide, CAPTCHA_SECRET_KEY)
from fastrand import pcg32bounded as fastrandint
from xxhash import xxh64
from hashlib import sha1
import threading
import traceback
import os
from json import load
from bcrypt import hashpw, gensalt, checkpw
from sqlite3 import connect as sqlconn
from time import sleep, time
from re import sub, match
from colorama import Back, Fore, Style, init
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from nano_lib_rvx import Account
from tronapi import HttpProvider
from tronapi import Tron
from cashaddress import convert
from bitcash import Key
import requests
import random
import json
from socket import socket
from flask_ipban import IpBan
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
from flask import Flask, request, jsonify, render_template
from flask_caching import Cache
import functools
from dotenv import load_dotenv


def forwarded_ip_check():
    return request.environ.get('HTTP_X_REAL_IP', request.remote_addr)


def dbg(*message):
    if "TX" in str(message):
        fg_color = Fore.YELLOW
    elif "EX" in str(message):
        fg_color = Fore.CYAN
    elif "Error" in str(message):
        fg_color = Fore.RED
    elif "Success" in str(message):
        fg_color = Fore.GREEN
    else:
        fg_color = Fore.WHITE

    print(now().strftime(
        Style.RESET_ALL
        + Style.DIM
        + Fore.WHITE
        + "%H:%M:%S")
        + Style.BRIGHT
        + fg_color,
        *message,
        Style.RESET_ALL)


# Exchange settings
exchange_address = {
    "duco": "coinexchange",
    "xmg": "95JLhkyWVDce5D17LyApULc5YC4vrVzaio",
    "lke": "Like3yYC34YQJRMQCSbTDWKLhnzCoZvo9AwWuu5kooh",
    "bch": "bitcoincash:qpgpd7slludx5h9p53qwf8pxu9z702n95qteeyzay3",
    "trx": "TQUowTaHwvkWHbNVkxkAbcnbYyhF4or1Qy",
    "xrp": "rGT84ryubURwFMmiJChRbWUg9iQY18VGuQ (Destination tag: 2039609160)",
    "dgb": "DHMV4BNGpWbdhpq6Za3ArncuhpmtCjyQXg",
    "nano": "nano_3fpqpbcgt3nga3s81td6bk7zcqdr7ockgnyjkcy1s8nfn98df6c5wu14fuuq",
    "fjc": "FsfCoLL8JmLJoU57bUr2W3u3TA8acL9kf3",
    "rvn": "RH4bTDaHH7LSSCVSvXJzJ5KkiGR1QRMaqN",
    "nim": "NQ88 Q9ME 470X 8KY8 HXQG J96N 6FHR 8G0B EDMH"}

load_dotenv()
IPDB_KEY = os.getenv('IPDB_KEY')
PROXYCHECK_KEY = os.getenv('PROXYCHECK_KEY')
TRX_SECRET_KEY = os.getenv('TRX_SECRET_KEY')
BCH_SECRET_KEY = os.getenv('BCH_SECRET_KEY')
LIKECOIN_SECRET_KEY = os.getenv('LIKECOIN_SECRET_KEY')
NANO_SECRET_KEY = os.getenv('NANO_SECRET_KEY')
EXCHANGE_MAIL = DUCO_EMAIL

IP_CHECK_DISABLED = False
XXHASH_TX_PROB = 30

overrides = [
    NodeS_Overide,
    DUCO_PASS]

config = {
    "DEBUG": False,
    "CACHE_TYPE": "redis",
    "CACHE_REDIS_URL": "redis://localhost:6379/0",
    "CACHE_DEFAULT_TIMEOUT": SAVE_TIME,
    "JSONIFY_PRETTYPRINT_REGULAR": False}

limiter = Limiter(
    key_func=forwarded_ip_check,
    default_limits=["5000 per day", "1 per 1 second"],)

ip_ban = IpBan(
    ban_seconds=60*60,
    ban_count=3,
    persist=True,
    ip_header='HTTP_X_REAL_IP',
    record_dir="config/ipbans/",
    ipc=True,
    secret_key=DUCO_PASS,
    abuse_IPDB_config={
        "key": IPDB_KEY,
        "report": True,
        "load": False})

app = Flask(__name__, template_folder='config/error_pages')
app.config.from_mapping(config)
cache = Cache(app)
limiter.init_app(app)
ip_ban.init_app(app)
requests_session = requests.Session()
thread_lock = threading.Lock()

nano_key = Account(priv_key=NANO_SECRET_KEY)
bch_key = Key(BCH_SECRET_KEY)
trx_key = Tron(
    full_node=HttpProvider('https://api.trongrid.io'),
    solidity_node=HttpProvider('https://api.trongrid.io'),
    event_server=HttpProvider('https://api.trongrid.io'))
trx_key.private_key = TRX_SECRET_KEY
trx_key.default_address = exchange_address["trx"]

last_transactions_update, last_miners_update, last_balances_update = 0, 0, 0
miners, balances, transactions = [], [], []
rate_count, last_transfer, checked_ips = {}, {}, {}
banlist, jailedusr, registrations, whitelisted_usr = [], [], [], []

with open('config/sell_email.html', 'r') as file:
    html_exc = file.read()
with open('config/sell_email.html', 'r') as file:
    html_auto = file.read()
with open('config/buy_email.html', 'r') as file:
    html_buy = file.read()

with open(CONFIG_JAIL, "r") as jailedfile:
    jailedusr = jailedfile.read().splitlines()
    for username in jailedusr:
        jail.append(username)
    dbg("Successfully loaded jailed usernames file")

with open(CONFIG_BANS, "r") as bannedusrfile:
    bannedusr = bannedusrfile.read().splitlines()
    for username in bannedusr:
        banlist.append(username)
    dbg("Successfully loaded banned usernames file")

with open(CONFIG_WHITELIST_USR, "r") as whitelistedusrfile:
    whitelist = whitelistedusrfile.read().splitlines()
    for username in whitelist:
        whitelisted_usr.append(username)
    dbg("Successfully loaded whitelisted usernames file")

with open(CONFIG_WHITELIST, "r") as whitelistfile:
    whitelist = whitelistfile.read().splitlines()
    for ip in whitelist:
        ip_ban.ip_whitelist_add(ip)
    dbg("Successfully loaded whitelisted IPs file")


def likecoin_transaction(recipient: str, amount: int, comment: str):
    data = {
        "address": str(recipient),
        "amount": str(int(amount) * 1000000000),
        "comment": str(comment),
        "prv": LIKECOIN_SECRET_KEY}

    r = requests.post(
        "https://wallet.likecoin.pro/api/v0/new-transfer",
        data=data).json()

    if "error" in r:
        raise Exception(r["error"])
    else:
        return r["hash"]


def error_log(message: str):
    with open('exchange_erorrs.txt', 'a') as file:
        file.write(str(message))


observations = {}


@app.errorhandler(429)
def error429(e):
    global observations
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    ip_ban.add(ip=ip_addr)

    try:
        observations[ip_addr] += 1
    except:
        observations[ip_addr] = 1

    if observations[ip_addr] > 20:
        dbg("Too many observations", ip_addr)
        if not ip_addr in whitelist:
            ip_ban.block(ip_addr)
        return render_template('403.html'), 403
    else:
        limit_err = str(e).replace("429 Too Many Requests: ", "")
        dbg("Error 429", ip_addr, limit_err, os.getpid())
        return render_template('429.html', limit=limit_err), 429


@app.errorhandler(404)
def error404(e):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    page_name = str(request.url)
    ip_ban.add(ip=ip_addr)

    dbg("Error 404", ip_addr, page_name)
    return render_template('404.html', page_name=page_name), 404


@app.errorhandler(500)
def error500(e):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

    dbg("Error 500", ip_addr)
    return render_template('500.html'), 500


@app.errorhandler(403)
def error403(e):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    ip_ban.add(ip=ip_addr)
    ip_ban.block(ip_addr)

    dbg("Error 403", ip_addr)

    try:
        observations[ip_addr] += 1
    except:
        observations[ip_addr] = 1

    if observations[ip_addr] > 40:
        dbg("Too many observations - banning", ip_addr)
        if not ip_addr in whitelist:
            ip_addr_ban(ip_addr)

    return render_template('403.html'), 403


def login(username: str, unhashed_pass: str):
    if not match(r"^[A-Za-z0-9_-]*$", username):
        return (False, "Incorrect username")

    try:
        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """SELECT *
                    FROM Users
                    WHERE username = ?""",
                (str(username),))
            data = datab.fetchone()

        if len(data) > 1:
            stored_password = data[1]
        else:
            return (False, "No user found")

        try:
            if checkpw(unhashed_pass, stored_password):
                return (True, "Logged in")
            return (False, "Invalid password")

        except Exception:
            if checkpw(unhashed_pass, stored_password.encode('utf-8')):
                return (True, "Logged in")
            return (False, "Invalid password")
    except Exception as e:
        return (False, "DB Err: " + str(e))


def check_ip(ip):
    global checked_ips
    global IP_CHECK_DISABLED
    try:
        if IP_CHECK_DISABLED:
            return (False, None)

        elif not ip:
            return (True, "Your IP address is hidden")

        elif ip in whitelist:
            return (False, None)

        elif ip in checked_ips:
            return checked_ips[ip]

        response = requests_session.get(
            f"http://proxycheck.io/v2/{ip}"
            + f"?key={PROXYCHECK_KEY}&vpn=1&proxy=1").json()
        if response["status"] != "error":
            if "proxy" in response[ip]:
                if response[ip]["proxy"] == "yes":
                    dbg("Proxy detected: " + str(ip))
                    checked_ips[ip] = (True, "You're using a proxy")
                    return checked_ips[ip]
            if "vpn" in response[ip]:
                if response[ip]["vpn"] == "yes":
                    dbg("VPN detected: " + str(ip))
                    checked_ips[ip] = (True, "You're using a VPN")
                    return checked_ips[ip]
            else:
                # dbg("No proxy: " + str(ip))
                checked_ips[ip] = (False, None)
                return (False, None)
        else:
            IP_CHECK_DISABLED = True
            return (False, None)
    except Exception as e:
        return (False, None)


def ip_addr_ban(ip, show=True, perm=False):
    if not ip in whitelist:
        if show:
            dbg(">>> Ip addr banning", ip)
            ip_ban.block(ip)
            perm_ban(ip)


def _success(result, code=200):
    return jsonify(result=result, success=True), code


def _error(result, code=200):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    ip_ban.add(ip=ip_addr)
    return jsonify(message=result, success=False), code


def _proxy():
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    threading.Thread(target=ip_addr_ban, args=[ip_addr, False, True]).start()
    return _error("You're using a proxy or VPN")


def get_all_transactions():
    global transactions
    global last_transactions_update

    if time() - last_transactions_update > SAVE_TIME*3:
        # print(f'fetching transactions from {CONFIG_TRANSACTIONS}')
        try:
            with sqlconn(CONFIG_TRANSACTIONS, timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute("SELECT * FROM Transactions")
                rows = datab.fetchall()

            transactions = {}
            for row in rows:
                transactions[row[4]] = row_to_transaction(row)
            last_transactions_update = time()
        except Exception as e:
            print(traceback.format_exc())

    return transactions


def row_to_transaction(row):
    return {
        'datetime': str(row[0]),
        'sender': str(row[1]),
        'recipient': str(row[2]),
        'amount': float(row[3]),
        'hash': str(row[4]),
        'memo': str(row[5]),
        'id': int(row[6])
    }


def get_transactions(username: str, limit=10, reverse=True):
    try:
        order = "DESC"
        if reverse:
            order = "ASC"

        with sqlconn(CONFIG_TRANSACTIONS, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute("""
                SELECT * FROM ( 
                    SELECT * FROM Transactions
                    WHERE username = ?
                    OR recipient = ?
                    ORDER BY id DESC
                    LIMIT ?
                ) ORDER BY id """ + order,
                          (username, username, limit))
            rows = datab.fetchall()

        return [row_to_transaction(row) for row in rows]
    except Exception as e:
        return str(e)


def get_all_miners():
    global last_miners_update
    global miners

    if time() - last_miners_update > SAVE_TIME*3:
        try:
            # print(f'fetching miners from {CONFIG_MINERAPI}')
            with sqlconn(CONFIG_MINERAPI, timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute("SELECT * FROM Miners")
                rows = datab.fetchall()

            last_miners_update = time()
            miners = {}
            for row in rows:
                if not row[1] in miners:
                    miners[row[1]] = []
                miners[row[1]].append(row_to_miner(row))
        except Exception as e:
            print(traceback.format_exc())

    return miners


def row_to_miner(row):
    return {
        "threadid":   str(row[0]),
        "username":   str(row[1]),
        "hashrate":   float(row[2]),
        "sharetime":  float(row[3]),
        "accepted":   int(row[4]),
        "rejected":   int(row[5]),
        "diff":       int(row[6]),
        "software":   str(row[7]),
        "identifier": str(row[8]),
        "algorithm":  str(row[9]),
        "pool":       str(row[10]),
        "wd":         row[11]
    }


def get_miners(username: str):
    with sqlconn(CONFIG_MINERAPI, timeout=DB_TIMEOUT) as conn:
        datab = conn.cursor()
        datab.execute("SELECT * FROM Miners WHERE username = ?", (username, ))
        rows = datab.fetchall()

    if len(rows) < 1:
        raise Exception("No miners detected")

    rows.sort(key=lambda tup: tup[1])
    return [row_to_miner(row) for row in rows]


trusted = {}
creation = {}


def get_all_balances():
    global balances
    global last_balances_update
    global balances
    global trusted
    global creation

    if time() - last_balances_update > SAVE_TIME*3:
        try:
            # print(f'fetching balances from {DATABASE}')
            with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute("SELECT * FROM Users")
                rows = datab.fetchall()

            balances = {}
            trusted = {}
            for row in rows:
                balances[row[0]] = row[3]
                creation[row[0]] = row[4].lower()
                trusted[row[0]] = row[5].lower()
            last_balances_update = time()
        except Exception as e:
            print(traceback.format_exc())

    return balances


def get_user_data(username: str):
    with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
        datab = conn.cursor()
        datab.execute("""
            SELECT * 
            FROM Users 
            WHERE username = ?""",
            (username, ))
        row = datab.fetchone()

    if not row:
        raise Exception("User not found")

    return {
        "username": username,
        "balance": round(row[3], DECIMALS),
        "verified": row[5].lower(),
        "created": row[4].lower()
    }


def is_verified(username: str):
    with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
        datab = conn.cursor()
        datab.execute("""
            SELECT * 
            FROM Users 
            WHERE username = ?""",
                      (username, ))
        row = datab.fetchone()

    if len(row) < 1:
        return "no"

    return row[5].lower()


@app.route("/ping")
@cache.cached(timeout=60)
def ping():
    return _success("Pong!")


@app.route("/404")
@cache.cached(timeout=60)
def test404():
    dbg("Error 404 test")
    return render_template('404.html'), 404


@app.route("/429")
@cache.cached(timeout=60)
def test429():
    dbg("Error 429 test")
    return render_template('429.html'), 429


@app.route("/403")
@cache.cached(timeout=60)
def test403():
    dbg("Error 403 test")
    return render_template('403.html'), 403


@app.route("/500")
@cache.cached(timeout=60)
def test500():
    dbg("Error 500 test")
    return render_template('500.html'), 500


@app.route("/all_pools")
@cache.cached(timeout=SAVE_TIME)
def all_pools():
    pools = []

    try:
        with sqlconn(POOL_DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute("SELECT * FROM PoolList")
            data = datab.fetchall()

        for row in data:
            if row[4] == "True":
                pool = {
                    "name":          row[1],
                    "cpu":           int(row[6]),
                    "ram":           int(row[7]),
                    "connections":   int(row[8])}
                pools.append(pool)

        return _success(pools)
    except Exception as e:
        return _error(str(e))


@app.route("/autopool")
@cache.cached(timeout=SAVE_TIME)
def getpool():
    pools = []

    try:
        with sqlconn(POOL_DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute("SELECT * FROM PoolList")
            data = datab.fetchall()

        for row in data:
            if row[4] == "True":
                pool = {
                    "name":          row[1],
                    "cpu":           int(row[6]),
                    "ram":           int(row[7]),
                    "ip":            str(row[2]),
                    "port":          int(row[3]),
                    "connections":   int(row[8])}
                pools.append(pool)

        if not pools:
            return _error("No pools available")

        pool = functools.reduce(
            lambda curr, prev: a
            if (curr["cpu"]*2 + curr["ram"]) > (curr["cpu"]*2 + curr["ram"])
            else curr, pools)

        return jsonify({
            "name": pool["name"],
            "ip": pool["ip"],
            "port": pool["port"],
            "success": True})
    except Exception as e:
        return _error(str(e))


registration_db = {}


@app.route("/auth/<username>")
@limiter.limit("6 per 1 minute")
def api_auth(username=None):
    global registration_db
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        unhashed_pass = str(request.args.get('password', None)).encode('utf-8')
    except Exception as e:
        return _error(f"Invalid data: {e}")

    if not user_exists(username) or not username:
        return _error("This user doesn't exist")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    #dbg("/GET/auth", username, unhashed_pass.decode())

    if unhashed_pass.decode() in overrides:
        return _success("Logged in")

    if username in banlist:
        ip_addr_ban(ip_addr)
        return _error("User banned")

    login_protocol = login(username, unhashed_pass)
    if login_protocol[0] == True:
        alt_check(ip_addr, username)
        return _success(login_protocol[1])
    else:
        return _error(login_protocol[1])


@app.route("/register/")
@limiter.limit("5 per hour")
def register():
    global registrations
    try:
        username = str(request.args.get('username', None))
        unhashed_pass = str(request.args.get('password', None)).encode('utf-8')
        email = str(request.args.get('email', None))
        captcha = request.args.get('captcha', None)
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        postdata = {'secret': CAPTCHA_SECRET_KEY,
                    'response': captcha}
    except Exception as e:
        return _error(f"Invalid data: {e}")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    altcheck = alt_check(ip_addr, username, False)
    if altcheck[0]:
        return _error(
            f"You are already registered as {altcheck[1]}, why do you need another account?")

    try:
        captcha_data = requests.post(
            'https://hcaptcha.com/siteverify', data=postdata).json()
        if not captcha_data["success"]:
            return _error("Incorrect captcha")
    except Exception as e:
        return _error("Captcha error: "+str(e))

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

    try:
        threading.Thread(
            target=send_registration_email,
            args=[username, email]).start()
        created = str(now().strftime("%d/%m/%Y %H:%M:%S"))

        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """INSERT INTO Users
                (username, password, email, balance, created)
                VALUES(?, ?, ?, ?, ?)""",
                (username, password, email, 0.0, created))
            conn.commit()

        dbg(f"Success: registered {username} ({email})")
        registrations.append(ip_addr)
        return _success("Sucessfully registered a new wallet")
    except Exception as e:
        return _error(f"Error registering new account: {e}")


@app.route("/miners/<username>")
@cache.cached(timeout=SAVE_TIME)
def get_miners_api(username: str):
    # Get all miners
    try:
        return _success(get_miners(username))
    except:
        return _error("No miners detected on that account")


@app.route("/wduco_wrap/<username>")
@limiter.limit("3 per 1 minute")
def api_wrap_duco(username: str):
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        unhashed_pass = request.args.get('password', None).encode("utf-8")
        amount = float(request.args.get('amount', None))
        tron_address = str(request.args.get('address', None))
    except Exception as e:
        return _error(f"Invalid data: {e}")

    dbg("GET/wduco_wrap", username, amount, tron_address)

    login_protocol = login(username, unhashed_pass)
    if not login_protocol[0]:
        return _error(login_protocol[1])

    if amount < 30:
        return _error("Minimum wrappable amount is 30 DUCO")

    if username in jail or username in banlist:
        return _error("User can not wrap DUCO")

    altfeed = alt_check(ip_addr, username, True, False)
    if altfeed[0]:
        if not username in altfeed[1][:2]: # Filter first two accounts
            return _error(f"You're using alt-account(s): {altfeed[1][2]}")

    wrapfeedback = protocol_wrap_wduco(username, tron_address, amount)
    wrapfeedback = wrapfeedback.replace("NO,", "").replace("OK,", "")
    if "OK" in wrapfeedback:
        return _success(wrapfeedback)
    else:
        return _error(wrapfeedback)


@app.route("/users/<username>")
@limiter.limit("60 per 1 minute")
@cache.cached(timeout=SAVE_TIME)
def api_get_user_objects(username: str):
    try:
        try:
            limit = int(request.args.get('limit', None))
        except:
            limit = 5
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    except Exception as e:
        return _error(f"Invalid data: {e}")

    # dbg("/GET/users/"+str(username))

    try:
        balance = get_user_data(username)
    except Exception as e:
        return _error(f"This user doesn't exist: {e}")

    try:
        miners = get_miners(username)
    except Exception as e:
        miners = []

    try:
        transactions = get_transactions(username, limit)
    except Exception as e:
        transactions = []

    result = {
        'balance': balance,
        'miners': miners,
        'transactions': transactions
    }

    return _success(result)


@app.route("/users/")
@cache.cached(timeout=60)
def user_error():
    return _error("Usage: /users/<username>")


@app.route("/changepass/<username>")
@limiter.limit("1 per 1 minute")
def api_changepass(username: str):
    try:
        old_password = request.args.get('password', None).encode("utf-8")
        new_password = request.args.get('newpassword', None).encode("utf-8")
        new_password_encrypted = hashpw(
            new_password, gensalt(rounds=BCRYPT_ROUNDS))

        if old_password == new_password:
            return _error("New password must be different")

        try:
            with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute("""SELECT *
                        FROM Users
                        WHERE username = ?""",
                              (username,))
                old_password_database = datab.fetchone()[1].encode('utf-8')
        except:
            with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute("""SELECT *
                        FROM Users
                        WHERE username = ?""",
                              (username,))
                old_password_database = datab.fetchone()[1]

        if (checkpw(old_password, old_password_database)
                or old_password in overrides):
            with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute("""UPDATE Users
                        set password = ?
                        where username = ?""",
                              (new_password_encrypted, username))
                conn.commit()
                print("Changed password of user " + username)
                return _success("Your password has been changed")
        else:
            print("Passwords of user " + username + " don't match")
            return _error("Your old password doesn't match!")
    except Exception as e:
        print("Error changing password: " + str(e))
        return _error("Internal server error: " + str(e))


@app.route("/verify/<username>")
def api_verify(username: str):
    try:
        pwd = str(request.args.get('pass', None))
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        admin = str(request.args.get('admin', "revox"))
    except Exception as e:
        return _error(f"Invalid data: {e}")

    if not user_exists(username):
        return _error("Invalid username :(")

    if not pwd in overrides:
        return _error("Invalid password!!!")

    if is_verified(username) == "yes":
        return _error("This user is already verified :P")

    try:
        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """UPDATE Users
                set rig_verified = ?
                where username = ?""",
                ("Yes", username))
            conn.commit()
    except Exception as e:
        return _error(str(e))

    try:
        threading.Thread(target=protocol_verified_mail, args=[username, admin]).start()
    except Exception as e:
        return _error(str(e))

    dbg(f"Verified {username} by {ip_addr} ({pwd})")
    return _success("Success")


@app.route("/user_transactions/<username>")
@cache.cached(timeout=SAVE_TIME)
def get_transaction_by_username(username: str):
    dbg("/GET/user_transactions/"+str(username))
    try:
        limit = int(request.args.get('limit', 5))
    except Exception as e:
        return _error(f"Invalid data: {e}")

    try:
        transactions = get_transactions(username, limit)
        return _success(transactions)
    except Exception as e:
        return _error(f"Error: {e}")


@app.route("/id_transactions/<tx_id>")
@cache.cached(timeout=SAVE_TIME)
def get_transaction_by_id(tx_id: str):
    # dbg("/GET/id_transactions/"+str(tx_id))
    try:
        return _success(api_tx_by_id(tx_id))
    except Exception as e:
        return _error("No transaction found")


def api_tx_by_id(tx_id: str):
    with sqlconn(CONFIG_TRANSACTIONS, timeout=DB_TIMEOUT) as conn:
        datab = conn.cursor()
        datab.execute("""
            SELECT * 
            FROM Transactions 
            WHERE id = ?""",
                      (tx_id, ))
        row = datab.fetchone()

    if not row:
        raise Exception("No transaction found")

    return row_to_transaction(row)


@app.route("/transactions/<hash>")
@cache.cached(timeout=SAVE_TIME)
def get_transaction_by_hash(hash: str):
    # dbg("/GET/transactions/"+str(hash))
    try:
        return _success(api_tx_by_hash(hash))
    except Exception as e:
        return _error("No transaction found")


def api_tx_by_hash(hash: str):
    with sqlconn(CONFIG_TRANSACTIONS, timeout=DB_TIMEOUT) as conn:
        datab = conn.cursor()
        datab.execute("""
            SELECT * 
            FROM Transactions 
            WHERE hash = ?""",
                      (hash, ))
        row = datab.fetchone()

    if not row:
        raise Exception("No transaction found")

    return row_to_transaction(row)


@app.route("/balances/<username>")
@cache.cached(timeout=SAVE_TIME)
def api_get_user_balance(username: str):
    # dbg("/GET/balances/"+str(username))
    try:
        return _success(get_user_data(username))
    except Exception as e:
        return _error("This user doesn't exist")


@app.route("/balances")
@cache.cached(timeout=SAVE_TIME*3)
def api_get_all_balances():
    dbg("/GET/balances")
    try:
        return _success(get_all_balances())
    except Exception as e:
        return _error("Error fetching balances: " + str(e))


@app.route("/transactions")
@cache.cached(timeout=SAVE_TIME*3)
def api_get_all_transactions():
    dbg("/GET/transactions")
    try:
        return _success(get_all_transactions())
    except Exception as e:
        return _error("Error fetching transactions: " + str(e))


@app.route("/miners")
@cache.cached(timeout=SAVE_TIME*3)
def api_get_all_miners():
    dbg("/GET/miners")
    try:
        return _success(get_all_miners())
    except Exception as e:
        return _error("Error fetching miners: " + str(e))


@app.route("/statistics")
@cache.cached(timeout=SAVE_TIME*3)
def get_api_data():
    # dbg("/GET/statistics")
    data = {}
    with open(API_JSON_URI, 'r') as f:
        try:
            data = load(f)
        except:
            pass

    return jsonify(data)


@app.route("/ip")
def get_ip():
    dbg("/GET/ip")
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    return _success(ip_addr)


@app.route("/statistics_miners")
@cache.cached(timeout=SAVE_TIME*3)
def get_api_data_miners():
    dbg("/GET/statistics_miners")
    all_miners = get_all_miners()
    get_all_balances()
    try:
        to_return = {}
        for user in all_miners:
            try:
                to_return[user] = {
                    "w": len(all_miners[user]),
                    "v": trusted[user]}
            except:
                continue
        return _success(to_return)
    except Exception as e:
        return _error(str(e))


@app.route("/exchange_request/")
@limiter.limit("2 per 1 day")
def exchange_request():
    try:
        username = str(request.args.get('username', None))
        unhashed_pass = request.args.get('password', None).encode('utf-8')
        email = str(request.args.get('email', None))
        ex_type = str(request.args.get('type', None)).upper()
        amount = int(request.args.get('amount', None))
        coin = str(request.args.get('coin', None)).lower()
        address = str(request.args.get('address', None))
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    except Exception as e:
        return _error(f"Invalid data: {e}")

    dbg("EX:", username, email)

    # return _error("Exchange requests on DUCO Exchange are currently disabled, use other exchange")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    if is_verified(username) != "yes":
        return _error("Your account is not verified, see https://server.duinocoin.com/verify.html")

    if username in banlist or username in jailedusr:
        return _error("You are not elgible for the exchange (ToS violation)")

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

    altfeed = alt_check(ip_addr, username, True, False)
    if altfeed[0]:
        if not username in altfeed[1][:2]: # Filter first two accounts
            return _error(f"You're using alt-account(s): {altfeed[1][2]}")

    # Check the amount
    if amount < 200:
        return _error("Minimum exchangeable amount is 200 DUCO")
    if amount > 10000:
        return _error("Maximum exchangeable amount is 10000 DUCO")

    if ex_type.upper() == "SELL":
        balance = get_user_data(username)["balance"]
        if amount > balance:
            return _error("You don't have enough DUCO in your account ("
                          + str(round(balance, 3))+")")
    else:
        exchange_balance = get_user_data(exchange_address["duco"])["balance"]
        if amount > exchange_balance:
            return _error("We don't have enough DUCO in our reserves ("
                          + str(round(exchange_balance, 3))+"). "
                          + "Try again later or with a smaller amount")

    # Get current exchange rates
    try:
        de_api = requests.get("https://github.com/revoxhere/duco-exchange/"
                              + "raw/master/api/v1/rates",
                              data=None).json()["result"]
    except Exception as e:
        return _error("Error getting exchange rates: " + str(e))

    try:
        exchanged_amount = round(
            de_api[coin.lower()][ex_type.lower()]*amount,
            len(str(de_api[coin.lower()][ex_type.lower()])))
    except Exception:
        return _error("That coin isn't listed")

    # XRP has a high transaction fee so we need to check for that
    if coin.lower() == "xrp" and ex_type.upper() == "SELL":
        min_amount = round(0.3 / de_api["xrp"]["sell"])
        if amount < min_amount:
            return _error(f"Minimum sellable amount for XRP is {min_amount} DUCO")

    # Generate TXID
    import random
    random = random.randint(0, XXHASH_TX_PROB+1)
    if random != XXHASH_TX_PROB:
        global_last_block_hash_cp = sha1(
            bytes(str(username)+str(amount)+str(random),
                  encoding='ascii')).hexdigest()
    else:
        global_last_block_hash_cp = xxh64(
            bytes(str(username)+str(amount)+str(random),
                  encoding='ascii'), seed=2811).hexdigest()

    def _quickexchange(ex_type, username, email, amount, exchanged_amount, coin, address):
        if coin.lower() == "bch":
            tx_api = "https://blockchair.com/bitcoin-cash/transaction/"
            try:
                if len(str(address)) == 34:
                    address = str(convert.to_cash_address(address))
                coin_txid = bch_key.send([(str(address),
                                           float(exchanged_amount), 'bch')],
                                         unspents=bch_key.get_unspents())
                dbg("EX: Sent BCH", coin_txid)
            except Exception as e:
                print("EX: Error sending BCH", traceback.format_exc())
                error_log(
                    "Exchange error: " +
                    f"{ex_type} from {username} ({email}) - {amount} DUCO ({exchanged_amount} {coin}) {address} - {e}")
                # return _error("Error transferring coins, please try again later: "+str(e))

        elif coin.lower() == "xmg":
            tx_api = "https://magi.duinocoin.com/?search="
            try:
                coin_txid = requests.get(
                    "https://magi.duinocoin.com/transaction"
                    + f"?username=revox&recipient={address}"
                    + f"&password={DUCO_PASS}&amount={exchanged_amount}"
                    + f"&memo=DUCO Exchange payment").json()
                if "result" in coin_txid:
                    coin_txid = coin_txid["result"].split(",")[2]
                    dbg("EX: Sent XMG", coin_txid)
                else:
                    raise Exception(coin_txid["message"])
            except Exception as e:
                print("EX: Error sending XMG", traceback.format_exc())
                error_log(
                    "\nExchange error: " +
                    f"{ex_type} from {username} ({email}) - {amount} DUCO ({exchanged_amount} {coin}) {address} - {e}")
                # return _error("Error transferring coins, please try again later: "+str(e))

        elif coin.lower() == "trx":
            tx_api = "https://tronscan.org/#/transaction/"
            try:
                coin_txid = trx_key.trx.send_transaction(str(address),
                                                         float(exchanged_amount-1))["txid"]
                dbg("EX: Sent TRX", coin_txid)
            except Exception as e:
                print("EX: Error sending TRX", traceback.format_exc())
                error_log(
                    "\nExchange error: " +
                    f"{ex_type} from {username} ({email}) - {amount} DUCO ({exchanged_amount} {coin}) {address} - {e}")
                # return _error("Error transferring coins, please try again later: "+str(e))

        elif coin.lower() == "lke":
            tx_api = "https://explorer.likecoin.pro/tx/"
            try:
                coin_txid = likecoin_transaction(str(address), int(exchanged_amount), "DUCO Exchange payment")
                dbg("EX: Sent LKE", coin_txid)
            except Exception as e:
                print("EX: Error sending LKE", traceback.format_exc())
                error_log(
                    "\nExchange error: " +
                    f"{ex_type} from {username} ({email}) - {amount} DUCO ({exchanged_amount} {coin}) {address} - {e}")
                # return _error("Error transferring coins, please try again later: "+str(e))

        elif coin.lower() == "nano":
            tx_api = "https://nanocrawler.cc/explorer/block/"
            try:
                coin_txid = nano_key.send(str(address), float(exchanged_amount))
                dbg("EX: Sent NANO", coin_txid)
            except Exception as e:
                print("EX: Error sending NANO", traceback.format_exc())
                error_log(
                    "\nExchange error: " +
                    f"{ex_type} from {username} ({email}) - {amount} DUCO ({exchanged_amount} {coin}) {address} - {e}")
                # return _error("Error transferring coins, please try again later: "+str(e))

        html = """\
            <html>
              <body>
                <p style="font-size:18px">
                    Automatic exchange finished<br>
                    Type: <b>""" + str(ex_type) + """</b><br>
                    Username: <b>""" + str(username) + """</b><br>
                    Amount: <b>""" + str(amount) + """</b> DUCO<br>
                    Email: <b>""" + str(email) + """</b><br>
                    Address: <b>""" + str(address) + """</b><br>
                    Sent: <b>""" + str(exchanged_amount) + """</b> """ + coin.upper() + """<br>
                    TXID: <a href='""" + str(tx_api) + str(coin_txid) + """'>"""+str(coin_txid)+"""</a><br>
                    DUCO TXID: <a href="https://explorer.duinocoin.com?search=""" + str(global_last_block_hash_cp) + """">"""+str(global_last_block_hash_cp)+"""</a>
                </p>
              </body>
            </html>"""

        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = ("✅ Auto DUCO - "
                                  + str(coin).upper()
                                  + " "
                                  + ex_type.upper()
                                  + " exchange finished")
            message["From"] = DUCO_EMAIL
            message["To"] = EXCHANGE_MAIL
            part = MIMEText(html, "html")
            message.attach(part)
            context = ssl.create_default_context()

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
                smtp.login(
                    DUCO_EMAIL, DUCO_PASS)
                smtp.sendmail(
                    DUCO_EMAIL, EXCHANGE_MAIL, message.as_string())
        except Exception as e:
            return _error("Error sending an e-mail to the exchange system")

        ####

        email_body = html_auto.replace(
            "{user}", str(username)
        ).replace(
            "{amount}", str(amount)
        ).replace(
            "{tx_api}", str(tx_api)
        ).replace(
            "{txid}", str(coin_txid)
        ).replace(
            "{duco_tx}", str(global_last_block_hash_cp))

        message = MIMEMultipart("alternative")
        message["Subject"] = "✨ Your DUCO - "+str(coin).upper()+" exchange is done!"
        try:
            message["From"] = DUCO_EMAIL
            message["To"] = email
            part = MIMEText(email_body, "html")
            message.attach(part)
            context = ssl.create_default_context()

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
                smtp.login(
                    DUCO_EMAIL, DUCO_PASS)
                smtp.sendmail(
                    DUCO_EMAIL, email, message.as_string())
        except Exception:
            print(traceback.format_exc())

    quickexchange = ["bch", "trx", "lke", "nano", "xmg"]
    if ex_type.lower() == "sell" and coin.lower() in quickexchange:
        try:
            threading.Thread(
                target=_quickexchange,
                args=[ex_type, username, email, amount, exchanged_amount, coin, address]).start()
            dbg("Launched exchange thread")
        except Exception as e:
            return _error(f"Error lanching transaction thread: {e}")

    elif ex_type.lower() == "sell":
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
            message["Subject"] = ("⚠️ Manual DUCO - "
                                  + str(coin).upper()
                                  + " "
                                  + ex_type.lower()
                                  + " request")
            message["From"] = DUCO_EMAIL
            message["To"] = EXCHANGE_MAIL
            part = MIMEText(html, "html")
            message.attach(part)
            context = ssl.create_default_context()

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
                smtp.login(
                    DUCO_EMAIL, DUCO_PASS)
                smtp.sendmail(
                    DUCO_EMAIL, EXCHANGE_MAIL, message.as_string())
        except Exception as e:
            return _error("Error sending an e-mail to the exchange system")

        ###

        message = MIMEMultipart("alternative")
        message["Subject"] = "🍒 Your DUCO Exchange sell request has been received"
        try:
            message["From"] = DUCO_EMAIL
            message["To"] = email

            email_body = html_exc.replace(
                "{user}", str(username)
            ).replace(
                "{ex_type}", str(ex_type.lower())
            ).replace(
                "{amount}", str(amount)
            ).replace(
                "{address}", str(address)
            )
            part = MIMEText(email_body, "html")
            message.attach(part)
            context = ssl.create_default_context()

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
                smtp.login(
                    DUCO_EMAIL, DUCO_PASS)
                smtp.sendmail(
                    DUCO_EMAIL, email, message.as_string())
        except Exception:
            print(traceback.format_exc())

    elif ex_type.lower() == "buy":
        ###
        message = MIMEMultipart("alternative")
        message["Subject"] = "🔥 Finish your DUCO Exchange buy request"
        try:
            message["From"] = DUCO_EMAIL
            message["To"] = email

            email_body = html_buy.replace(
                "{user}", str(username)
            ).replace(
                "{coin}", str(coin.upper())
            ).replace(
                "{amount}", str(amount)
            ).replace(
                "{exchanged_amount}", str(exchanged_amount)
            ).replace(
                "{exchange_address}", str(exchange_address[coin.lower()])
            )
            part = MIMEText(email_body, "html")
            message.attach(part)
            context = ssl.create_default_context()

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
                smtp.login(
                    DUCO_EMAIL, DUCO_PASS)
                smtp.sendmail(
                    DUCO_EMAIL, email, message.as_string())
        except Exception:
            print(traceback.format_exc())

    if ex_type.lower() == "sell":
        try:
            recipient = "coinexchange"
            memo = ("DUCO Exchange transaction "
                    + "(sell for "
                    + str(coin.upper())
                    + ")")

            try:
                with sqlconn(DATABASE,
                             timeout=DB_TIMEOUT) as conn:
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
                                     timeout=DB_TIMEOUT) as conn:
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
                             timeout=DB_TIMEOUT) as conn:
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
        except Exception:
            return _success("Error deducting balance")

    return _success("Your exchange request has been successfully submited")


@app.route("/transaction/")
@limiter.limit("2 per 1 minute")
def api_transaction():
    global last_transfer
    global banlist
    global rate_count
    # return _error("Temporarily disabled")
    try:
        username = str(request.args.get('username', None))
        unhashed_pass = str(request.args.get('password', None)).encode('utf-8')
        recipient = str(request.args.get('recipient', None))
        amount = float(request.args.get('amount', None))
        memo = sub(r'[^A-Za-z0-9 .()-:/!#_+-]+', ' ', str(request.args.get('memo', None)))
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    except Exception as e:
        print(e)
        return _error(f"NO,Invalid data: {e}")

    dbg(f"New TX request: {username}",
        f"\n\t amount: {amount}",
        f"\n\t recipient: {recipient}",
        f"\n\t memo: {memo}")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    #return _error("Temporarily disabled")

    chain_accounts = ["bscDUCO", "celoDUCO", "maticDUCO"]
    if recipient in chain_accounts:
        acccheck = acc_check(memo, username)
        if acccheck[0]:
            jail.append(username)
            return _error(f"NO,This address is associated with another account(s): {acccheck[1]}")

    if len(str(memo)) > 256:
        memo = str(memo[0:253]) + "..."

    if not match(r"^[A-Za-z0-9_-]*$", username):
        return _error("NO,Incorrect username")

    if not match(r"^[A-Za-z0-9_-]*$", recipient):
        return _error("NO,Incorrect recipient")

    if is_verified(username) == "no":
        return _error("NO,Verify your account first")

    if username in jail:
        return _error("NO,BONK - go to kolka jail")

    if recipient in banlist or recipient in jailedusr:
        return _error("NO,Can\'t send funds to that user")

    if username in banlist:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        ip_addr_ban(ip_addr)
        return _error("NO,User baned")

    if memo == "-" or memo == "":
        memo = "None"

    if round(float(amount), DECIMALS) <= 0:
        return _error("NO,Incorrect amount")

    if not user_exists(username):
        return _error("NO,User doesn\'t exist")

    if not user_exists(recipient):
        return _error("NO,Recipient doesn\'t exist")

    if username in rate_count:
        if rate_count[username] >= 3:
            banlist.append(username)

    if username in last_transfer:
        if (now() - last_transfer[username]).total_seconds() <= 30:
            ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
            if not ip_addr in whitelist:
                dbg("TX: rate limiting", username,
                    (now() - last_transfer[username]).total_seconds(), "s")
                return _error(
                    "NO,Please wait some time before making a transaction")
                try:
                    rate_count[username] += 1
                except:
                    rate_count[username] = 1

    if not unhashed_pass.decode() in overrides:
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
                    return _error("NO,Invalid password")
            except:
                if not checkpw(unhashed_pass, stored_password.encode('utf-8')):
                    return _error("NO,Invalid password")
        except Exception as e:
            print(e)
            return _error("NO,No user found: " + str(e))
    else:
        if memo != "None":
            memo = str(memo) + " OVERRIDE"
        else:
            memo = "OVERRIDE"

    altfeed = alt_check(ip_addr, username, True, False)
    if altfeed[0]:
        if not username in altfeed[1][:2]: # Filter first two accounts
            return _error(f"NO,You're using alt-account(s): {altfeed[1][2]}")

    try:
        import random
        random = random.randint(0, XXHASH_TX_PROB+1)
        if random != XXHASH_TX_PROB:
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
                     timeout=DB_TIMEOUT) as conn:
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
                         timeout=DB_TIMEOUT) as conn:
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
                                 timeout=DB_TIMEOUT) as conn:
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
                         timeout=DB_TIMEOUT) as conn:
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

            dbg(f"Success: transferred {amount} DUCO from",
                f"{username} to {recipient} ({memo})")
            last_transfer[username] = now()
            return _success("OK,Successfully transferred funds,"
                            + str(global_last_block_hash_cp))
    except Exception as e:
        return _error("NO,Internal server error")


@app.route("/pool_sync/")
def api_sync_proxy():
    s = socket()
    loginInfos = {}
    syncData = {"blocks": {}}

    try:
        loginInfos["host"] = str(request.args.get('host', None))
        loginInfos["port"] = str(request.args.get('port', None))
        loginInfos["version"] = str(request.args.get('version', None))
        loginInfos["identifier"] = str(request.args.get('identifier', None))
        loginInfos["name"] = request.args.get('name', None)

        syncData["blocks"]["blockIncrease"] = str(request.args.get('blockIncrease', None))
        syncData["blocks"]["bigBlocks"] = str(request.args.get('bigBlocks', None))
        syncData["cpu"] = str(request.args.get('cpu', None))
        syncData["ram"] = str(request.args.get('ram', None))
        syncData["connections"] = str(request.args.get('connections', None))
    except Exception as e:
        return _error(f"Invalid data: {e}")

    try:
        s.settimeout(10)
        port = random.choice([2810, 2809, 2808, 2807, 2806])
        s.connect(("127.0.0.1", port))
        recv_ver = s.recv(5).decode().rstrip("\n")
        if not recv_ver:
            dbg(f"Warning: {loginInfos['name']} connection interrupted")
            return _error(f"Connection interrupted")
        elif float(recv_ver) != 2.7:
            dbg(f"Warning: {loginInfos['name']} server versions don't match: {2.7}, {recv_ver}")
            return _error(f"Invalid ver: {recv_ver}")

        s.sendall(f"PoolLogin,{json.dumps(loginInfos)}\n".encode("utf-8"))
        login_state = s.recv(16).decode().rstrip("\n")
        if not login_state:
            dbg(f"Warning: {loginInfos['name']} connection interrupted")
            return _error(f"Connection interrupted")
        if login_state != "LoginOK":
            dbg(f"Error: {loginInfos['name']} invalid login state: {login_state}")
            return _error(login_state)

        s.sendall(f"PoolSync,{json.dumps(syncData)}\n".encode("utf-8"))
        sync_state = s.recv(16).decode().rstrip("\n")
        if not sync_state:
            dbg(f"Warning: {loginInfos['name']} connection interrupted")
            return _error(f"Connection interrupted")
        if sync_state != "SyncOK":
            dbg(f"Error: {loginInfos['name']} invalid sync state: {sync_state}")
            return _error(sync_state)
        s.close()

        # dbg(f"Success: {loginInfos['name']} synced")
        return _success(sync_state)

    except Exception as e:
        if str(e) == "timed outZ":
            dbg(f"Error: {loginInfos['name']} timed out")
        else:
            dbg(f"Error: {loginInfos['name']} {e}")
        return _error("Sync error: " + str(e))
