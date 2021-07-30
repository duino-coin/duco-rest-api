from flask_caching import Cache
from Server import (
    now,
    jail,
    global_last_block_hash,
    DATABASE,
    DUCO_PASS,
    DB_TIMEOUT,
    CONFIG_MINERAPI,
    CONFIG_TRANSACTIONS,
    API_JSON_URI,
    BCRYPT_ROUNDS,
    user_exists,
    email_exists,
    send_registration_email
)
from re import sub
from hashlib import sha1
from fastrand import pcg32bounded as fastrandint
import traceback
from operator import itemgetter
from collections import OrderedDict
from re import match
from bcrypt import checkpw
from time import sleep, time
from sqlite3 import connect as sqlconn
from flask import Flask, request, jsonify
import json
import sys
import os
from bcrypt import hashpw, gensalt
from gevent import monkey
monkey.patch_all()

DB_TIMEOUT = 10
SAVE_TIME = 10
config = {
    "DEBUG": False,
    "CACHE_TYPE": "SimpleCache",
    "CACHE_DEFAULT_TIMEOUT": SAVE_TIME
}

app = Flask(__name__)
app.config.from_mapping(config)
cache = Cache(app)

transactions = []
last_transactions_update = 0
miners = []
last_miners_update = 0
balances = []
last_balances_update = 0
use_cache = True


def _success(result, code=200):
    return jsonify(success=True, result=result), code


def _error(string, code=200):
    return jsonify(success=False, message=string), code


def row_to_transaction(row):
    return {
        'datetime': str(row[0]),
        'sender': str(row[1]),
        'recipient': str(row[2]),
        'amount': float(row[3]),
        'hash': str(row[4]),
        'memo': str(row[5])
    }


@app.route("/transaction/")
def api_transaction():
    username = request.args.get('username', None)
    unhashed_pass = request.args.get('password', None).encode('utf-8')
    recipient = request.args.get('recipient', None)
    amount = request.args.get('amount', None)
    memo = request.args.get('memo', None)

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
            if not checkpw(unhashed_pass, stored_password):
                return _error("Invalid password")
        except:
            if not checkpw(unhashed_pass, stored_password.encode('utf-8')):
                return _error("Invalid password")
    except Exception as e:
        return _error("No user found: " + str(e))

    try:
        random = fastrandint(1000)
        global_last_block_hash_cp = sha1(
            bytes(str(username)+str(amount)+str(random),
                  encoding='ascii')).hexdigest()
        memo = sub(r'[^A-Za-z0-9 .()-:/!#_+-]+', ' ', str(memo))

        if memo == "-" or memo == "":
            memo = "None"

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

        with sqlconn(DATABASE,
                     timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """SELECT *
                    FROM Users
                    WHERE username = ?""",
                (recipient,))
            recipientbal = float(datab.fetchone()[3])

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

            print("Successfully transferred", amount, "from",
                  username, "to", recipient, global_last_block_hash_cp)
            return _success("OK,Successfully transferred funds,"
                            + str(global_last_block_hash_cp))
    except Exception as e:
        return _success(
            "NO,Internal server error: "
            + str(traceback.format_exc()))


@app.route("/new_wallet/")
def api_register():
    """ 
    Register a new user, return on error 
    """
    username = request.args.get('username', None)
    unhashed_pass = str(request.args.get('password', None)).encode('utf-8')
    email = request.args.get('email', None)

    """ 
    Do some basic checks 
    """
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
        """ 
        Register a new account if  the registration
        e-mail was sent successfully 
        """
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


@app.route("/auth/")
def api_auth():
    username = str(request.args.get('username', None))
    unhashed_pass = str(request.args.get('password', None)).encode('utf-8')

    if unhashed_pass.decode() == DUCO_PASS:
        return _success("Logged in")

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
                print("Invalid", username, unhashed_pass, stored_password)
                return _error("Invalid password")
        except Exception as e:
            if checkpw(unhashed_pass, stored_password.encode('utf-8')):
                return _success("Logged in")
            else:
                return _error("Invalid password 2"+str(e))
    except Exception as e:
        return _error("No user found: " + str(e))


def get_all_transactions():
    global last_transactions_update
    global transactions

    now = time()
    if now - last_transactions_update >= SAVE_TIME:
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


def get_transactions(username: str, limit=20):
    # transactions for user
    transactions = get_all_transactions()

    user_transactions = []
    for transaction in transactions:
        if (transactions[transaction]["sender"] == username
                or transactions[transaction]["recipient"] == username):
            user_transactions.append(transactions[transaction])

    return user_transactions[-limit:]


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


def get_all_miners():
    global last_miners_update
    global miners

    now = time()
    if now - last_miners_update < SAVE_TIME:
        pass
        # print(f'returning a copy of miners')
    else:
        try:
            with sqlconn(CONFIG_MINERAPI, timeout=DB_TIMEOUT) as conn:
                # print(f'fetching miners from {DATABASE}')
                datab = conn.cursor()

                datab.execute("SELECT * FROM Miners")
                rows = datab.fetchall()
            # print(f'done fetching miners from {CONFIG_MINERAPI}')
            if len(rows) > 500:
                miners_cp = {}
                for row in rows:
                    if not row[1] in miners_cp:
                        miners_cp[row[1]] = []
                    miners_cp[row[1]].append(row_to_miner(row))
                miners = miners_cp
            # print(f'done creating miner dict from {CONFIG_MINERAPI}')

            last_miners_update = time()
        except:
            pass

    return miners.copy()


@app.route("/miners/<username>")
@cache.cached()
def get_miners_api(username: str):
    # Get all miners
    try:
        miners = get_all_miners()
        return _success(miners[username])
    except:
        return _error("No miners detected on that account")


def get_miners(username: str):
    # For /users/
    miners = get_all_miners()
    return miners[username]


def row_to_balance(row):
    return {
        'username': str(row[0]),
        'balance': float(row[3])
    }


def get_all_balances():
    global last_balances_update
    global balances

    now = time()
    if now - last_balances_update < SAVE_TIME:
        pass
        # print(f'returning a copy of balances')
    else:
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


def get_balance(username: str):
    balances = get_all_balances()
    balance = {
        "username": username,
        "balance": balances[username]
    }
    return balance


@app.route("/users/<username>")
@cache.cached()
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
@cache.cached()
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
@cache.cached()
def api_get_user_balance(username: str):
    try:
        return _success(get_balance(username))
    except Exception as e:
        return _error("This user doesn't exist")


@app.route("/balances")
@cache.cached()
def api_get_all_balances():
    try:
        return _success(get_all_balances())
    except Exception as e:
        return _error("Error fetching balances: " + str(e))


@app.route("/transactions")
@cache.cached()
def api_get_all_transactions():
    try:
        return _success(get_all_transactions())
    except Exception as e:
        return _error("Error fetching transactions: " + str(e))


@app.route("/miners")
@cache.cached()
def api_get_all_miners():
    try:
        return _success(get_all_miners())
    except Exception as e:
        print(str(e))
        return _error("Error fetching miners: " + str(e))


@app.route("/statistics")
@cache.cached()
def get_api_data():
    data = {}
    with open(API_JSON_URI, 'r') as f:
        try:
            data = json.load(f)
        except:
            pass

    return jsonify(data)
