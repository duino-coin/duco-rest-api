#!/usr/bin/env python3
"""
Duino-Coin REST API © MIT licensed
https://duinocoin.com
https://github.com/revoxhere/duco-rest-api
Duino-Coin Team & Community 2019-2021
"""
import gevent.monkey
gevent.monkey.patch_all()
from werkzeug.utils import secure_filename
import string
import secrets
from datetime import timedelta
from functools import reduce
from time import time
from dotenv import load_dotenv
import base64
import functools
from flask_caching import Cache
from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_ipban import IpBan
from socket import socket
import json
import random
import requests
from bitcash import Key
from cashaddress import convert
from tronapi import Tron
from tronapi import HttpProvider
from nano_lib_rvx import Account
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ssl
import smtplib
from colorama import Back, Fore, Style, init
from re import sub, match
from random import randint, choice
from time import sleep, time
from sqlite3 import connect as sqlconn
from bcrypt import hashpw, gensalt, checkpw
from json import load
import os
import traceback
import threading
from hashlib import sha1
from xxhash import xxh64
from fastrand import pcg32bounded as fastrandint
from Server import (
    now, SAVE_TIME, POOL_DATABASE, CONFIG_WHITELIST_USR,
    jail, global_last_block_hash, HOSTNAME,
    DATABASE, DUCO_EMAIL, DUCO_PASS, alt_check, acc_check,
    DB_TIMEOUT, CONFIG_MINERAPI, SERVER_VER,
    CONFIG_TRANSACTIONS, API_JSON_URI, temporary_ban,
    BCRYPT_ROUNDS, user_exists, SOCKET_TIMEOUT,
    email_exists, send_registration_email, protocol_ban, protocol_loved_verified_mail,
    DECIMALS, CONFIG_BANS, protocol_verified_mail, protocol_unverified_mail,
    CONFIG_JAIL, CONFIG_WHITELIST, perm_ban,
    NodeS_Overide, CAPTCHA_SECRET_KEY, CONFIG_BASE_DIR)
from validate_email import validate_email
from wrapped_duco_functions import *
import datetime
import jwt

TOKENS_DATABASE = CONFIG_BASE_DIR + '/tempTokens.db'

try:
    with sqlconn(TOKENS_DATABASE, timeout=DB_TIMEOUT) as conn:
        datab = conn.cursor()
        datab.execute(
            """CREATE TABLE IF NOT EXISTS tmpTokens (username VARCHAR(255), email VARCHAR(255), token VARCHAR(255), time VARCHAR(255))""")
        conn.commit()
except Exception as e:
    print(e)

html_recovery_template = """\
<html lang="en-US">
<head>
    <style type="text/css">
        @import url('https://fonts.googleapis.com/css2?family=Lato:wght@300&display=swap');
        * {
            font-family: 'Lato', sans-serif;
        }
        a:hover {
            text-decoration: none !important;
        }
        .btn {
            background: #ff9f43;
            text-decoration: none !important;
            font-weight: semibold;
            border-radius: 16px;
            margin-top: 35px;
            color: #fff !important;
            text-transform: uppercase;
            font-size: 14px;
            padding: 10px 24px;
            display: inline-block;
        }
        .btn:hover {
            background: #feca57;
        }
    </style>
</head>
<body marginheight="0" topmargin="0" marginwidth="0" style="margin: 0px; background-color: #fff8ee;" leftmargin="0">
    <table cellspacing="0" border="0" cellpadding="0" width="100%" bgcolor="#fff8ee"">
        <tr>
            <td>
                <table style=" background-color: #ffffff; max-width:670px; margin:0 auto;" width="100%" border="0"
        align="center" cellpadding="0" cellspacing="0">
        <tr>
            <td style="height:80px;">&nbsp;</td>
        </tr>
        <tr>
            <td style="text-align:center;">
                <a href="https://www.duinocoin.com" title="logo" target="_blank">
                    <img src="https://github.com/revoxhere/duino-coin/raw/master/Resources/ducobanner.png?raw=true"
                        width="50%" height="auto">
                </a>
            </td>
        </tr>
        <tr>
            <td style="height:20px;">&nbsp;</td>
        </tr>
        <tr>
            <td>
                <table width="95%" border="0" align="center" cellpadding="0" cellspacing="0"
                    style="max-width:670px;background:#fff; border-radius:3px; text-align:center; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);">
                    <tr>
                        <td style="text-align:center; padding-top: 25px; height:40px; font-size: 32px;">
                            Hey there, {username}!
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:0 35px; text-align:center;">
                            <h1 style="color:#1e1e2d; font-weight:500; margin:0; margin-top: 25px; font-size:16px;">
                                You have requested to reset your private key</h1>
                            <span
                                style="display:inline-block; vertical-align:middle; margin:29px 0 26px; border-bottom:1px solid #cecece; width:100px;"></span>
                            <p style="color:#455056; font-size:15px;line-height:24px; margin:0;">
                                Because we don't store the private keys directly, we can't just send you your old key.<br>
                                <b>A unique link to reset your passphrase has been generated for you.</b><br>
                                To reset your private key, click the following link and follow the instructions.<br>
                                <b>You have 30 minutes to reset your key.</b><br>
                                If you did not request a passphrase reset, please ignore this email.
                            </p>
                            <a href="{link}" class="btn">
                                Reset passphrase
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <td style="height:40px;">&nbsp;</td>
                    </tr>
                </table>
            </td>
        <tr>
            <td style="height:20px;">&nbsp;</td>
        </tr>
        <tr>
            <td style="text-align:center;">
                <p style="font-size:14px; color:rgba(69, 80, 86, 0.7411764705882353); line-height:18px; margin:0 0 0;">
                    Have a great day, <a href="https://duinocoin.com/team">the Duino-Coin Team</a> 😊</p>
            </td>
        </tr>
        <tr>
            <td style="height:80px;">&nbsp;</td>
        </tr>
    </table>
    </td>
    </tr>
    </table>
</body>
</html>
"""


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
    # "xrp": "rGT84ryubURwFMmiJChRbWUg9iQY18VGuQ (Destination tag: 2039609160)",
    # "dgb": "DHMV4BNGpWbdhpq6Za3ArncuhpmtCjyQXg",
    "nano": "nano_3fpqpbcgt3nga3s81td6bk7zcqdr7ockgnyjkcy1s8nfn98df6c5wu14fuuq",
    # "rvn": "RH4bTDaHH7LSSCVSvXJzJ5KkiGR1QRMaqN",
    # "nim": "NQ88 Q9ME 470X 8KY8 HXQG J96N 6FHR 8G0B EDMH"
}

fees = {
    "duco": 0,
    "xmg": 0.05,
    "lke": 0,
    "bch": 0.0000023,
    "trx": 1,
    "nano": 0
}

load_dotenv()
IPDB_KEY = os.getenv('IPDB_KEY')
PROXYCHECK_KEY = os.getenv('PROXYCHECK_KEY')
TRX_SECRET_KEY = os.getenv('TRX_SECRET_KEY')
BCH_SECRET_KEY = os.getenv('BCH_SECRET_KEY')
LIKECOIN_SECRET_KEY = os.getenv('LIKECOIN_SECRET_KEY')
NANO_SECRET_KEY = os.getenv('NANO_SECRET_KEY')
EXCHANGE_MAIL = DUCO_EMAIL
SERVER_NAME = "duino-master-1"

IP_CHECK_DISABLED = True
XXHASH_TX_PROB = 30
POOL_SYNC_TIME = 15
chain_accounts = ["bscDUCO", "celoDUCO", "maticDUCO"]

overrides = [
    NodeS_Overide,
    DUCO_PASS
]

config = {
    "DEBUG": False,
    "CACHE_TYPE": "RedisCache",
    "CACHE_REDIS_URL": "redis://localhost:6379/0",
    "CACHE_DEFAULT_TIMEOUT": SAVE_TIME,
    "JSONIFY_PRETTYPRINT_REGULAR": False}

limiter = Limiter(
    key_func=forwarded_ip_check,
    default_limits=["5000 per day", "5 per 1 second"])

ip_ban = IpBan(
    ban_seconds=60*60,
    ban_count=10,
    persist=False,
    ip_header='HTTP_X_REAL_IP',
    record_dir="config/ipbans/",
    ipc=True,
    secret_key=DUCO_PASS)

app = Flask(__name__, template_folder='config/error_pages')

app.config['SECRET_KEY'] = 'ChangeMe'

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

network = {
    "name": "Duino-Coin",
    "color": 'e67e22',
    "avatar": 'https://github.com/revoxhere/duino-coin/raw/master/Resources/duco.png?raw=true',
}

last_transactions_update, last_miners_update, last_balances_update = 0, 0, 0
miners, balances, transactions = [], [], []
rate_count, last_transfer, checked_ips = {}, {}, {}
banlist, jailedusr, registrations, whitelisted_usr = [], [], [], []
registration_db = {}

with open('config/emails/sell_manual_email.html', 'r') as file:
    html_exc = file.read()
with open('config/emails/sell_email.html', 'r') as file:
    html_auto = file.read()
with open('config/emails/buy_email.html', 'r') as file:
    html_buy = file.read()
with open('config/emails/sell_error.html', 'r') as file:
    html_error = file.read()


def fetch_bans():
    global jail, banlist, whitelisted_usr, whitelist
    jail, banlist, whitelisted_usr, whitelist = [], [], [], []
    while True:
        with open(CONFIG_JAIL, "r") as jailedfile:
            jailedusr = jailedfile.read().splitlines()
            for username in jailedusr:
                jail.append(username.strip())

        with open(CONFIG_BANS, "r") as bannedusrfile:
            bannedusr = bannedusrfile.read().splitlines()
            for username in bannedusr:
                banlist.append(username.strip())

        with open(CONFIG_WHITELIST_USR, "r") as whitelistedusrfile:
            whitelist = whitelistedusrfile.read().splitlines()
            for username in whitelist:
                whitelisted_usr.append(username.strip())

        with open(CONFIG_WHITELIST, "r") as whitelistfile:
            whitelist = whitelistfile.read().splitlines()
            for ip in whitelist:
                ip_ban.ip_whitelist_add(ip.strip())
        dbg("Loaded bans and whitelist")
        sleep(30)


jail, banlist, whitelisted_usr, whitelist = [], [], [], []

with open(CONFIG_JAIL, "r") as jailedfile:
    jailedusr = jailedfile.read().splitlines()
    for username in jailedusr:
        jail.append(username.strip())

with open(CONFIG_BANS, "r") as bannedusrfile:
    bannedusr = bannedusrfile.read().splitlines()
    for username in bannedusr:
        banlist.append(username.strip())

with open(CONFIG_WHITELIST_USR, "r") as whitelistedusrfile:
    whitelist = whitelistedusrfile.read().splitlines()
    for username in whitelist:
        whitelisted_usr.append(username.strip())

with open(CONFIG_WHITELIST, "r") as whitelistfile:
    whitelist = whitelistfile.read().splitlines()
    for ip in whitelist:
        ip_ban.ip_whitelist_add(ip.strip())
dbg("Loaded bans and whitelist")


# threading.Thread(target=fetch_bans).start()

def clear_obs():
    global observations

    while True:
        observations = {}
        dbg("Cleared observations")
        sleep(15*60)

# threading.Thread(target=clear_obs).start()


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

    if observations[ip_addr] > 30:
        # if not ip_addr in whitelist:
        #dbg("Too many observations", ip_addr)
        # ip_addr_ban(ip_addr)
        # ip_ban.block(ip_addr)
        return render_template('403.html'), 403
    else:
        limit_err = str(e).replace("429 Too Many Requests: ", "")
        #dbg("Error 429", ip_addr, limit_err, os.getpid())
        return render_template('429.html', limit=limit_err), 429


@app.errorhandler(404)
def error404(e):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    page_name = str(request.url)
    ip_ban.add(ip=ip_addr)

    if "php" in page_name:
        print("serio xD")
        return "we're not even using php you dumb fuck"
    elif "eval" in page_name:
        print("serio 2 xD")
        return "debil XD"

    try:
        observations[ip_addr] += 1
    except:
        observations[ip_addr] = 1

    if observations[ip_addr] > 30:
        # if not ip_addr in whitelist:
        #dbg("Too many observations", ip_addr)
        # ip_addr_ban(ip_addr)
        # ip_ban.block(ip_addr)
        return render_template('403.html'), 403
    else:
        if "auth" in page_name:
            return _success("OK")
        dbg("Error 404", ip_addr, page_name)
        return render_template('404.html', page_name=page_name), 404


@app.errorhandler(500)
def error500(e):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

    dbg("Error 500", ip_addr)

    try:
        observations[ip_addr] += 1
    except:
        observations[ip_addr] = 1

    if observations[ip_addr] > 30:
        # if not ip_addr in whitelist:
        #dbg("Too many observations - banning", ip_addr)
        # ip_addr_ban(ip_addr)
        # ip_ban.block(ip_addr)
        return render_template('403.html'), 403
    else:
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

    if observations[ip_addr] > 30:
        if not ip_addr in whitelist:
            dbg("Too many observations - banning", ip_addr)
            ip_addr_ban(ip_addr)
            # ip_ban.block(ip_addr)

    return render_template('403.html'), 403


cached_logins = {}


def login(username: str, unhashed_pass: str):
    global cached_logins

    try:
        try:
            data = jwt.decode(unhashed_pass, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return (False, 'Token expired. Please log in again.')
        except jwt.DecodeError: # if the token is invalid
            if not match(r"^[A-Za-z0-9_-]*$", username):
                return (False, "Incorrect username")

            if username in cached_logins:
                if unhashed_pass == cached_logins[username]:
                    return (True, "Logged in")
                else:
                    return (False, "Invalid password")

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
                        cached_logins[username] = unhashed_pass
                        return (True, "Logged in")
                    return (False, "Invalid password")

                except Exception:
                    if checkpw(unhashed_pass, stored_password.encode('utf-8')):
                        cached_logins[username] = unhashed_pass
                        return (True, "Logged in")
                    return (False, "Invalid password")
            except Exception as e:
                return (False, "DB Err: " + str(e))

        try:
            with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute("""
                    SELECT * 
                    FROM Users 
                    WHERE username = ?""",
                            (username, ))
                email = datab.fetchone()[2]
                if data['email'] == email:
                    return (True, "Logged in")
        except Exception as e:
            return (False, "DB Err:" + str(e))
    except Exception as e:
        print(e)


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

        try:
            response = requests_session.get(
                f"http://proxycheck.io/v2/{ip}"
                + f"?key={PROXYCHECK_KEY}&vpn=1&proxy=1").json()

            if "proxy" in response[ip]:
                if response[ip]["proxy"] == "yes":
                    dbg("Proxy detected: " + str(ip))
                    checked_ips[ip] = (True, "You're using a proxy")
                    # threading.Thread(target=ip_addr_ban, args=[ip, True]).start()
                    return checked_ips[ip]
            if "vpn" in response[ip]:
                if response[ip]["vpn"] == "yes":
                    dbg("VPN detected: " + str(ip))
                    checked_ips[ip] = (True, "You're using a VPN")
                    # threading.Thread(target=ip_addr_ban, args=[ip, True]).start()
                    return checked_ips[ip]
        except:
            IP_CHECK_DISABLED = True
        else:
            checked_ips[ip] = (False, None)
            return (False, None)
    except Exception as e:
        return (False, None)


def ip_addr_ban(ip, perm=False):
    if not ip in whitelist:
        ip_ban.block(ip)
        if perm:
            perm_ban(ip)
        else:
            temporary_ban(ip)


def _success(result, code=200):
    return jsonify(result=result, success=True, server=SERVER_NAME), code


def _error(result, code=200):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    ip_ban.add(ip=ip_addr)
    print(result)

    try:
        observations[ip_addr] += 1
    except:
        observations[ip_addr] = 1

    if observations[ip_addr] > 30:
        if not ip_addr in whitelist:
            dbg("Too many observations - banning", ip_addr)
            ip_addr_ban(ip_addr)
            ip_ban.block(ip_addr)
        sleep(observations[ip_addr])
        return render_template('403.html'), 403
    else:
        return jsonify(message=result, success=False, server=SERVER_NAME), code


def _proxy():
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    threading.Thread(target=ip_addr_ban, args=[ip_addr, True]).start()
    return _error("You're using a proxy or VPN")


def get_all_transactions():
    global transactions
    global last_transactions_update

    if time() - last_transactions_update > SAVE_TIME:
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
        'memo': str(sub(r"[^A-Za-z0-9 .-:!#_+-]+", ' ', str(row[5]))),
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

    if time() - last_miners_update > SAVE_TIME:
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
            pass

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
        "wd":         row[11],
        "ki":         int(row[13])
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

    if time() - last_balances_update > 30:
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
        raise Exception(f"{username} not found")

    return {
        "username": username,
        "balance": round(row[3], DECIMALS),
        "verified": row[5].lower(),
        "created": row[4].lower()
    }


def is_verified(username: str):
    try:
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
    except:
        return "no"


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
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    except Exception as e:
        return _error(f"Invalid data: {e}")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    try:
        with sqlconn(POOL_DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute("SELECT * FROM PoolList")
            data = datab.fetchall()

        pools = []
        for row in data:
            if row[4] == "True":
                if row[10]:
                    lastsync = int(time()) - int(row[10])
                    if lastsync == 0:
                        lastsync = "now"
                    else:
                        lastsync = f"{lastsync}s ago"
                else:
                    lastsync = "unknown"

                pool = {
                    "name":          str(row[1]),
                    "cpu":           int(row[6]),
                    "ram":           int(row[7]),
                    "connections":   int(row[8]),
                    "icon":          str(row[9]),
                    "lastsync":      str(lastsync)}
                pools.append(pool)

        return _success(pools)
    except Exception as e:
        return _error(str(e))


@cache.cached(timeout=5)
def poolfetchdb():
    try:
        def lowest_load(curr, prev):
            if (prev[4]*2 + prev[5]) < (curr[4]*2 + curr[5]):
                return prev
            return curr

        with sqlconn(POOL_DATABASE) as conn:
            datab = conn.cursor()
            datab.execute(
                """SELECT name, ip, port, Status, ram, 
                cpu, connections, lastsync 
                FROM PoolList 
                WHERE hidden != 'True'""")
            rows = datab.fetchall()

        pool_list = []
        for pool in rows:
            lastsync = time() - pool[-1]
            if pool[3] == "True" and pool[5] < 95 and pool[4] < 95 and lastsync < 120:
                pool_list.append(pool)

        if len(pool_list) < 1:
            pool_list = []
            for pool in rows:
                lastsync = time() - pool[-1]
                if lastsync < 600:
                    pool_list.append(pool)

        best_pool = reduce(lowest_load, pool_list)

        to_return = {
            "name": str(best_pool[0]),
            "ip": str(best_pool[1]),
            "port": int(best_pool[2]),
            "server": str(SERVER_NAME),
            "success": True
        }
        return to_return
    except Exception as e:
        return _error(str(e))


@app.route("/getPool")
def getpool():
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    except Exception as e:
        return _error(f"Invalid data: {e}")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    return poolfetchdb()


@app.route("/auth/<username>")
@limiter.limit("6 per 1 minute")
def api_auth(username=None):
    global registration_db
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        unhashed_pass = request.args.get('password', None).encode('utf-8')
    except Exception as e:
        return _error(f"Invalid data: {e}")

    if not user_exists(username) or not username:
        return _error(f"This user doesn't exist (auth): {username}")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    # dbg("/GET/auth", username, unhashed_pass.decode())
    try:
        if unhashed_pass.decode() in overrides:
            return _success("Logged in")

        if username in banlist:
            ip_addr_ban(ip_addr, True)
            return _error("User banned")

        login_protocol = login(username, unhashed_pass)
        if login_protocol[0] == True:
            threading.Thread(target=alt_check, args=[
                             ip_addr, username]).start()
            return _success(login_protocol[1])
        else:
            return _error(login_protocol[1])
    except:
        return _error("Invalid password")



@app.route("/v2/auth/check/<username>")
@limiter.limit("6 per 1 minute")
def api_auth_check(username=None):
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        token = request.args.get('token', None)
    except Exception as e:
        return _error(f"Invalid data: {e}")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    try:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return _error('Signature expired. Please log in again.')
        except jwt.InvalidTokenError:
            return _error('Invalid token. Please log in again.')
        try:
            with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute("""
                    SELECT * 
                    FROM Users 
                    WHERE username = ?""",
                              (username, ))
                email = datab.fetchone()[2]
                if data['email'] == email:
                    return _success(["Logged in", email])
        except Exception as e:
            return _error('Auth token is invalid')
    except:
        return _error('Auth token is invalid')


@app.route("/v2/auth/<username>")
@limiter.limit("6 per 1 minute")
def new_api_auth(username=None):
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        unhashed_pass_b64 = request.args.get('password', None)
    except Exception as e:
        return _error(f"Invalid data: {e}")

    if unhashed_pass_b64:
        unhashed_pass_b64 = str(unhashed_pass_b64).encode('utf-8')

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    try:
        if username in banlist:
            ip_addr_ban(ip_addr, True)
            return _error("User banned")

        try:
            unhashed_pass = base64.b64decode(unhashed_pass_b64)
        except Exception as e:
            return _error(f"Decoding error")

        # dbg("/GET/auth", username, unhashed_pass.decode())

        if not unhashed_pass:
            return _error("Provide a password")

        if not user_exists(username) or not username:
            return _error(f"This user doesn't exist (auth 2): {username}")

        try:
            with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute("""
                    SELECT * 
                    FROM Users 
                    WHERE username = ?""",
                              (username, ))
                email = datab.fetchone()[2]
        except:
            email = "unknown"

        if unhashed_pass.decode() in overrides:
            return _success(["Logged in (override)", email])

        login_protocol = login(username, unhashed_pass)
        if login_protocol[0] == True:
            threading.Thread(target=alt_check, args=[ip_addr, username]).start()
            token = jwt.encode({'email': email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, app.config['SECRET_KEY'], algorithm='HS256')  
            return _success([login_protocol[1], email, token.decode('UTF-8')])
        else:
            return _error(login_protocol[1])
    except Exception as e:
        print(e)
        return _error("Invalid password")


@app.route("/v2/users/<username>")
@app.route("/v3/users/<username>")
@cache.cached(timeout=SAVE_TIME)
def new_api_get_user_objects(username: str):
    try:
        try:
            limit = int(request.args.get('limit', None))
        except:
            limit = 5
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    except Exception as e:
        return _error(f"Invalid data: {e}")

    if username in banlist:
        return _error("User banned")

    try:
        balance = get_user_data(username)
    except Exception as e:
        return _error(f"This user doesn't exist (users): {e}")

    try:
        miners = get_miners(username)
    except Exception as e:
        miners = []

    try:
        transactions = get_transactions(username, limit)
    except Exception as e:
        transactions = []

    try:
        with open("config/prices.json", 'r') as f:
            duco_prices = load(f)
    except:
        duco_prices = {}

    result = {
        'balance': balance,
        'miners': miners,
        'transactions': transactions,
        'prices': duco_prices
    }

    return _success(result)


@app.route("/register/")
@limiter.limit("5 per hour")
def register():
    global registrations
    try:
        username = request.args.get('username', None)
        unhashed_pass = request.args.get('password', None)
        email = request.args.get('email', None)
        captcha = request.args.get('captcha', None)
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        postdata = {'secret': CAPTCHA_SECRET_KEY,
                    'response': captcha}
    except Exception as e:
        return _error(f"Invalid data: {e}")

    if not username:
        return _error("No username provided")

    if unhashed_pass:
        unhashed_pass = str(unhashed_pass).encode('utf-8')
    else:
        return _error("No password provided")

    if not email:
        return _error("No e-mail provided")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    #altcheck = alt_check(ip_addr, username)
    # if altcheck[0]:
    #    return _error(
    #        f"You are already registered as {altcheck[1]}, why do you need another account?")

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

    if not validate_email(email, check_smtp=False):
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
@cache.cached(timeout=POOL_SYNC_TIME)
def get_miners_api(username: str):
    # Get all miners
    try:
        return _success(get_miners(username))
    except:
        return _error(f"No miners detected for: {username}")


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

    if amount < 50:
        return _error("Minimum wrappable amount is 50 DUCO")

    if username in jail or username in banlist or not is_verified(username) == "yes":
        return _error("User can not wrap DUCO")

    #acccheck = acc_check(tron_address, username)
    # if acccheck[0]:
    #    jail.append(username)
    #    return _error(f"This address is associated with another account(s): {acccheck[1]}")

    try:
        altfeed = alt_check(ip_addr, username)
        if altfeed[0]:
            return _error(f"You're using multiple accounts: {altfeed[1]}, this is not allowed")
    except Exception as e:
        print(traceback.format_exc())

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

    if username in banlist:
        return _error("User banned")

    # dbg("/GET/users/"+str(username))

    try:
        balance = get_user_data(username)
    except Exception as e:
        return _error(f"This user doesn't exist (users v1): {e}")

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
        reason = str(request.args.get('reason', None))
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
        if not reason:
            threading.Thread(target=protocol_verified_mail,
                             args=[username, admin]).start()
        else:
            threading.Thread(target=protocol_loved_verified_mail,
                             args=[username, admin]).start()
    except Exception as e:
        return _error(str(e))

    dbg(f"Verified {username} by {ip_addr} ({pwd})")
    return _success("Success")


@app.route("/notverify/<username>")
def api_not_verify(username: str):
    try:
        pwd = str(request.args.get('pass', None))
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        admin = str(request.args.get('admin', "revox"))
        reason = str(request.args.get("reason", ""))
    except Exception as e:
        return _error(f"Invalid data: {e}")

    if not user_exists(username):
        return _error("Invalid username :(")

    if not pwd in overrides:
        return _error("Invalid password!!!")

    try:
        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """UPDATE Users
                set rig_verified = ?
                where username = ?""",
                ("No", username))
            conn.commit()
    except Exception as e:
        return _error(str(e))

    try:
        threading.Thread(target=protocol_unverified_mail, args=[
                         username, admin, reason]).start()
    except Exception as e:
        return _error(str(e))

    dbg(f"Rejected verification of user {username} by {ip_addr} ({pwd})")
    return _success("Success")


@app.route("/userban/<username>")
def api_ban(username: str):
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

    protocol_ban(username)

    dbg(f"Banned user {username} by {ip_addr} ({pwd})")
    return _success("Success")


@app.route("/user_transactions/<username>")
@cache.cached(timeout=SAVE_TIME)
def get_transaction_by_username(username: str):
    # dbg("/GET/user_transactions/"+str(username))
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
        return _error(f"No transaction found: {tx_id}")


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
        raise Exception(f"No transaction found: {tx_id}")

    return row_to_transaction(row)


@app.route("/transactions/<hash>")
@cache.cached(timeout=SAVE_TIME)
def get_transaction_by_hash(hash: str):
    # dbg("/GET/transactions/"+str(hash))
    try:
        return _success(api_tx_by_hash(hash))
    except Exception as e:
        return _error(f"No transaction found: {hash}")


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
        raise Exception(f"No transaction found: {hash}")

    return row_to_transaction(row)


@app.route("/balances/<username>")
@cache.cached(timeout=SAVE_TIME)
def api_get_user_balance(username: str):
    # dbg("/GET/balances/"+str(username))
    try:
        return _success(get_user_data(username))
    except Exception as e:
        return _error(f"This user doesn't exist: {username}")


@app.route("/balances")
@cache.cached(timeout=60)
def api_get_all_balances():
    # dbg("/GET/balances")
    try:
        return _success(get_all_balances())
    except Exception as e:
        return _error(f"Error fetching balances: {e}")


@app.route("/transactions")
@cache.cached(timeout=60)
def api_get_all_transactions():
    # dbg("/GET/transactions")
    try:
        return _success(get_all_transactions())
    except Exception as e:
        return _error(f"Error fetching transactions: {e}")


@app.route("/miners")
@cache.cached(timeout=60)
def api_get_all_miners():
    # dbg("/GET/miners")
    try:
        return _success(get_all_miners())
    except Exception as e:
        return _error(f"Error fetching miners: {e}")


@app.route("/statistics")
@cache.cached(timeout=30)
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
@cache.cached(timeout=10)
def get_api_data_miners():
    # dbg("/GET/statistics_miners")
    all_miners = get_all_miners()
    get_all_balances()
    try:
        to_return = {}
        for user in all_miners:
            count = len(all_miners[user])
            try:
                to_return[user] = {
                    "w": count,
                    "v": trusted[user]}
            except:
                continue
        return _success(to_return)
    except Exception as e:
        return _error(str(e))


def row_to_day(day):
    return {
        "day_unix": day[0],
        "day":      day[1],
        "price":    day[2]
    }


@app.route("/historic_prices")
@cache.cached(timeout=60)
def get_api_prices():
    try:
        currency = str(request.args.get('currency', None))
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        limit = int(request.args.get('limit', 5))

        allowed_currencies = ["bch", "xmg", "trx",
                              "nano", "justswap", "sushi", "max", "all"]
        if not currency in allowed_currencies:
            raise Exception("Invalid currency")
    except Exception as e:
        return _error(f"Invalid data: {e}")

    try:
        if currency == "all":
            to_return = {}
            for currency in allowed_currencies:
                try:
                    with sqlconn("charts/prices.db", timeout=DB_TIMEOUT) as conn:
                        datab = conn.cursor()
                        datab.execute(
                            f"""SELECT * FROM prices_{currency} ORDER BY day_unix DESC""")
                        data = datab.fetchall()

                    i = 0

                    to_return[currency] = []
                    for day in data:
                        to_return[currency].append(row_to_day(day))
                        i += 1
                        if i >= limit:
                            break
                except:
                    pass
        else:
            with sqlconn("charts/prices.db", timeout=DB_TIMEOUT) as conn:
                datab = conn.cursor()
                datab.execute(
                    f"""SELECT * FROM prices_{currency} ORDER BY day_unix DESC""")
                data = datab.fetchall()

            i = 0
            to_return = []
            for day in data:
                to_return.append(row_to_day(day))
                i += 1
                if i >= limit:
                    break

        return _success(to_return)
    except Exception as e:
        return _error(str(e))


def get_txid():
    random = randint(-28110001, 28110001)
    random_type = randint(0, XXHASH_TX_PROB+1)
    if random_type != XXHASH_TX_PROB:
        global_last_block_hash_cp = sha1(
            bytes(str(random), encoding='ascii')).hexdigest()
    else:
        global_last_block_hash_cp = xxh64(
            bytes(str(random), encoding='ascii'), seed=2811).hexdigest()
    return global_last_block_hash_cp


def send_exchange_error(error, email, txid, username, amount):
    try:
        global_last_block_hash_cp = get_txid()

        recipient = username
        sender = "coinexchange"
        memo = "DUCO Exchange refund"

        balance = get_user_data(sender)["balance"]

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
            return _error("Recipient doesn\'t exist")

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
                            (balance, sender))
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
                        sender,
                        recipient,
                        amount,
                        global_last_block_hash_cp,
                        memo))
                conn.commit()
    except Exception as e:
        print(f"Error refunding balance: {e}")

    message = MIMEMultipart("alternative")
    message["Subject"] = "⚠️ Error handling your DUCO exchange request"
    try:
        message["From"] = DUCO_EMAIL
        message["To"] = email

        email_body = html_error.replace(
            "{error}", str(error)
        ).replace(
            "{txid}", str(txid)
        ).replace(
            "{refund_txid}", str(global_last_block_hash_cp)
        ).replace(
            "{user}", str(username)
        ).replace(
            "{amount}", str(amount)
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


@app.route("/exchange_request/")
@limiter.limit("4 per 1 day")
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

    try:
        altfeed = alt_check(ip_addr, username)
        if altfeed[0]:
            return _error(f"You're using multiple accounts: {altfeed[1]}, this is not allowed")
    except Exception as e:
        print(traceback.format_exc())

    # Check the amount
    if amount < 200:
        return _error("Minimum exchangeable amount is 200 DUCO")
    if amount > 10000:
        return _error("Maximum exchangeable amount is 10000 DUCO.")

    #acccheck = acc_check(address, username)
    # if acccheck[0]:
    #    jail.append(username)
    #    return _error(f"This address is associated with another account(s): {acccheck[1]}")

    if ex_type.upper() == "SELL":
        balance = get_user_data(username)["balance"]
        if amount > balance:
            return _error("You don't have enough DUCO in your account ("
                          + str(round(balance, 3))+")")
    else:
        exchange_balance = get_user_data(exchange_address["duco"])["balance"]
        if amount > exchange_balance*10:
            return _error("We don't have enough DUCO in our reserves. "
                          + "Try again later or with a smaller amount")

    # Get current exchange rates
    try:
        de_api = requests.get("https://github.com/revoxhere/duco-exchange/"
                              + "raw/master/api/v1/rates",
                              data=None, headers={'Cache-Control': 'no-cache'}
                              ).json()["result"]
    except Exception as e:
        return _error("Error getting exchange rates: " + str(e))

    try:
        exchanged_amount = round(
            de_api[coin.lower()][ex_type.lower()]*amount,
            len(str(de_api[coin.lower()][ex_type.lower()])))
    except Exception:
        return _error("That coin isn't listed")

    if ex_type.upper() == "SELL":
        min_amount = round(fees[coin.lower()] / de_api[coin.lower()]["sell"])
        if amount < min_amount:
            return _error(f"Minimum sellable amount for {(coin.upper())} is {min_amount} DUCO")

    global_last_block_hash_cp = get_txid()

    def _quickexchange(ex_type, username, email, amount, exchanged_amount, coin, address):
        duco_txid = global_last_block_hash_cp
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
                send_exchange_error(str(e), email, duco_txid, username, amount)

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
                send_exchange_error(str(e), email, duco_txid, username, amount)

        elif coin.lower() == "trx":
            tx_api = "https://tronscan.org/#/transaction/"
            try:
                coin_txid = trx_key.trx.send_transaction(str(address),
                                                         float(exchanged_amount-1))["txid"]
                dbg("EX: Sent TRX", coin_txid)
            except Exception as e:
                print("EX: Error sending TRX", traceback.format_exc())
                send_exchange_error(str(e), email, duco_txid, username, amount)

        elif coin.lower() == "lke":
            tx_api = "https://explorer.likecoin.pro/tx/"
            try:
                coin_txid = likecoin_transaction(str(address), int(
                    exchanged_amount), "DUCO Exchange payment")
                dbg("EX: Sent LKE", coin_txid)
            except Exception as e:
                print("EX: Error sending LKE", traceback.format_exc())
                send_exchange_error(str(e), email, duco_txid, username, amount)

        elif coin.lower() == "nano":
            tx_api = "https://nanocrawler.cc/explorer/block/"
            try:
                coin_txid = nano_key.send(
                    str(address), float(exchanged_amount))
                dbg("EX: Sent NANO", coin_txid)
            except Exception as e:
                print("EX: Error sending NANO", traceback.format_exc())
                send_exchange_error(str(e), email, duco_txid, username, amount)

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
            pass
            #message = MIMEMultipart("alternative")
            # message["Subject"] = ("✅ Auto DUCO - "
            #                      + str(coin).upper()
            #                      + " "
            #                      + ex_type.upper()
            #                      + " exchange finished")
            #message["From"] = DUCO_EMAIL
            #message["To"] = EXCHANGE_MAIL
            #part = MIMEText(html, "html")
            # message.attach(part)
            #context = ssl.create_default_context()

            # with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
            #    smtp.login(
            #        DUCO_EMAIL, DUCO_PASS)
            #    smtp.sendmail(
            #        DUCO_EMAIL, EXCHANGE_MAIL, message.as_string())
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
        message["Subject"] = "✨ Your DUCO - " + \
            str(coin).upper()+" exchange is done!"
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

    quickexchange = ["bch", "trx", "lke", "nano", "xmg", "bkc"]
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
                return _error("Recipient doesn\'t exist")

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

    try:
        username = str(request.args.get('username', None))
        unhashed_pass = str(request.args.get('password', None)).encode('utf-8')
        recipient = str(request.args.get('recipient', None))
        amount = float(request.args.get('amount', None))
        memo = sub(r'[^A-Za-z0-9 .-:!#_+-]+', ' ',
                   str(request.args.get('memo', None)))
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    except Exception as e:
        return _error(f"NO,Invalid data: {e}")

    dbg(f"New TX request: {username}",
        f"\n\t pwd: {unhashed_pass}",
        f"\n\t amount: {amount}",
        f"\n\t recipient: {recipient}",
        f"\n\t memo: {memo}")

    if not user_exists(username):
        return _error("NO,User doesn\'t exist")

    if not user_exists(recipient):
        return _error("NO,Recipient doesn\'t exist")

    if not username in chain_accounts:
        ip_feed = check_ip(ip_addr)
        if ip_feed[0]:
            return _error(ip_feed[1])

    # return _error("Temporarily disabled")

    """try:
        if not username in chain_accounts:
            if recipient in chain_accounts:
                acccheck = acc_check(memo, username)
                if acccheck[0]:
                    jail.append(username)
                    return _error(f"NO,This address is associated with another account(s): {acccheck[1]}")
    except Exception as e:
        print(traceback.format_exc())"""

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
        print(username, "in banlist")
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        ip_addr_ban(ip_addr, True)
        return _error("NO,User baned")

    if memo == "-" or memo == "":
        memo = "None"

    if round(float(amount), DECIMALS) <= 0:
        return _error("NO,Incorrect amount")

    if username in rate_count:
        if rate_count[username] >= 3:
            banlist.append(username)

    if username in last_transfer:
        if (now() - last_transfer[username]).total_seconds() <= 30:
            ip_addr = request.environ.get(
                'HTTP_X_REAL_IP', request.remote_addr)
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
                user = datab.fetchone()
                stored_password = user[1]
                stored_email = user[2]
            try:
                data = jwt.decode(unhashed_pass.decode("utf-8"), app.config['SECRET_KEY'], algorithms=['HS256'])
                if data["email"] != stored_email:
                    return _error("NO,Invalid token")
            except Exception as e:
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
        if memo == "None":
            memo = "OVERRIDE"

    try:
        if not username in chain_accounts:
            altfeed = alt_check(ip_addr, username)
            if altfeed[0]:
                checked_u = altfeed[1].split(" ")[0]
                if username != checked_u:
                    return _error(f"NO,You're using multiple accounts: {altfeed[1]}, this is not allowed")
    except Exception as e:
        print(traceback.format_exc())

    try:
        global_last_block_hash_cp = get_txid()

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
        print(e)
        return _error("NO,Internal server error")


@app.route("/pool_sync/", methods=['GET', 'POST'])
@limiter.limit("10 per 1 minute")
def api_sync_proxy():
    try:
        if request.method == 'POST':
            rewards = request.files['rewards']
            filename = secure_filename(rewards.filename)
            rewards.save(os.path.join("/home/debian/websites/", filename))

            workers = request.files['workers']
            filename = secure_filename(workers.filename)
            workers.save(os.path.join("/home/debian/websites/", filename))

            # dbg("Downloaded files from", request.args.get('name', None))
    except Exception as e:
        print(traceback.format_exc())

    s = socket()
    s.settimeout(15)
    loginInfos = {}
    syncData = {"blocks": {}}

    try:
        loginInfos["host"] = str(request.args.get('host', None))
        loginInfos["port"] = str(request.args.get('port', None))
        loginInfos["version"] = str(request.args.get('version', None))
        loginInfos["identifier"] = str(request.args.get('identifier', None))
        loginInfos["name"] = request.args.get('name', None)

        syncData["blocks"]["blockIncrease"] = str(
            request.args.get('blockIncrease', None))
        syncData["cpu"] = str(request.args.get('cpu', None))
        syncData["ram"] = str(request.args.get('ram', None))
        syncData["connections"] = str(request.args.get('connections', None))

        syncData["post"] = "False"
        if request.method == 'POST':
            syncData["post"] = "True"
    except Exception as e:
        return _error(f"Invalid data: {e}")

    while True:
        try:
            port = choice([2810, 2809, 2808, 2807, 2806])
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
            if not "timed out" in str(e) and not "abort" in str(e):
                dbg(f"Error: {loginInfos['name']} {e}")
                return _error("Sync error: " + str(e))


@app.route("/recovering/<username>")
@limiter.limit("1 per 1 day")
def api_recovering(username: str):
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        pwd_hash = request.args.get('hash', None)
    except Exception as e:
        return _error(f"Invalid data: {e}")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    if pwd_hash == "None" or pwd_hash == '':
        return _error("Invalid data.")

    if username == "None" or username == '':
        return _error("Invalid data.")

    decoded_hash = str(base64.b64decode(pwd_hash)).strip("b").strip("'").strip("'")
    decoded_hash_email = decoded_hash.split("=")[1]

    try:
        with sqlconn(TOKENS_DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """SELECT *
                FROM tmpTokens
                WHERE
                username = ?""",
                (username,))
            data = datab.fetchone()

            if data is None:
                return _error("Invalid token.")

            hashDate = datetime.datetime.strptime(data[3], '%m/%d/%Y-%H:%M:%S')
            if now() > hashDate:
                return _error("Invalid time.")

            if pwd_hash != data[2]:
                return _error("Invalid hash.")
    except Exception as e:
        print(e)
        return _error("Error connecting to DataBase")

    try:
        with sqlconn(DATABASE,
                    timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute("""SELECT email
                FROM Users
                WHERE
                username = ?""",
                        (username,))
            data = datab.fetchone()
            if str(decoded_hash_email) != str(''.join(data)):
                return _error("Invalid hash")
    except Exception as e:
        print(e)
        return _error("Invalid hash")

    if username:
        if user_exists(username):
            alphabet = string.ascii_letters + string.digits
            genPassword = ''.join(secrets.choice(alphabet) for i in range(20))
            try:
                tmpPass = hashpw(genPassword.encode("utf-8"),
                                gensalt(rounds=BCRYPT_ROUNDS))
                try:
                    with sqlconn(TOKENS_DATABASE, timeout=DB_TIMEOUT) as conn:
                        datab = conn.cursor()
                        datab.execute(
                            """DELETE FROM tmpTokens
                            WHERE username = ?""",
                            (username,))
                except Exception as e:
                    return _error("Error connecting to DataBase")

                with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
                    datab = conn.cursor()
                    datab.execute("""UPDATE Users
                            set password = ?
                            where username = ?""",
                                (tmpPass, username))
                    conn.commit()
                    return jsonify(result="Your password has been changed, you can now login with your new password", password=genPassword, success=True), 200
            except Exception as e:
                print(e)
                return _error(f"Error fetching database")
        else:
            return _error("This username doesn't exist")
    else:
        return _error("Username not provided")

@app.route("/recovery/")
@limiter.limit("1 per 1 day")
def api_recovery():
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        username = request.args.get('username', None)
        print(repr(username), "recv")
    except Exception as e:
        return _error(f"Invalid data: {e}")

    ip_feed = check_ip(ip_addr)
    if ip_feed[0]:
        return _error(ip_feed[1])

    if username:
        if user_exists(username):
            try:
                with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
                    datab = conn.cursor()
                    datab.execute(
                        """SELECT * FROM Users WHERE username = ?""", (username,))
                    email = str(datab.fetchone()[2])
                try:
                    message = MIMEMultipart("alternative")
                    message["Subject"] = "🔗 Your Duino-Coin passphrase reset link"
                    message["From"] = DUCO_EMAIL
                    message["To"] = email

                    hashStr = str(
                        (now() + timedelta(minutes=30)).strftime('%m/%d/%Y-%H:%M:%S')).encode("utf-8")

                    hash = base64.b64encode(
                        hashStr + str("=" + email).encode("utf-8"))

                    recoveryUrl = "https://wallet.duinocoin.com/recovery.html?username=" + \
                        username + "&hash=" + \
                        str(hash).strip("b").strip("'").strip("'")

                    try:
                        with sqlconn(TOKENS_DATABASE, timeout=DB_TIMEOUT) as conn:
                            datab = conn.cursor()
                            datab.execute(
                                """INSERT INTO tmpTokens
                                (username, email, token, time)
                                VALUES(?, ?, ?, ?)""",
                                (str(username), str(email), str(hash, 'utf-8'), str(hashStr, 'utf-8')))
                            conn.commit()
                    except Exception as e:
                        print(e)
                        return _error("Error connecting to DataBase")

                    email_body = html_recovery_template.replace(
                        "{username}", str(username)).replace(
                        "{link}", str(recoveryUrl))
                    part = MIMEText(email_body, "html")
                    message.attach(part)
                    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtpserver:
                        smtpserver.login(DUCO_EMAIL, DUCO_PASS)
                        smtpserver.sendmail(
                            DUCO_EMAIL, email, message.as_string())
                    return jsonify(result="An e-mail has been sent to you with the reset link - please check your mailbox", success=True), 200
                except Exception as e:
                    return _error("Error sending e-mail, please try again later")
            except Exception as e:
                return _error("Error fetching database, please try again later")
        else:
            return _error("This username isn't registered, make sure you're entering the correct name")
    else:
        return _error("Username not provided")