# duco-rest-api

This is a forked version of [dansinclair25's original duco-rest-api](https://github.com/dansinclair25/duco-rest-api) that's currently being used on the Duino-Coin master server.<br>
It differs by having caching and some other small improvements or fixes. At this point it doesn't have all the "original" calls, but they will be added as soon as I'll have some free time.

API endpoints can be accessed on the `https://server.duinocoin.com/<query>` URL.

### Host it yourself

1. Install requirements using `pip3 install -r requirements.txt`
2. Run it using `gunicorn app:app` 
3. Locally, this is available on `127.0.0.1:5000`

## API Endpoints

#### User
* `/users/<username>` - [return username's balance, last transactions and miners in one request](#usersusername)
* `/auth/<username>/?password=<password>` - check username's password

#### Transactions
* `/transactions` - [return **all** transactions](#transactions-1)
* `/transactions/<hash>` - [return transaction with that hash](#transactionshash)
* `/transaction?username=<username>&password=<password>&recipient=<recipient>&amount=<amount>&memo=memo` - transfer funds from username to recipient

#### Miners
* `/miners` - [return **all** miners](#miners-1)
* `/miners/<username>` - return username's miners

#### Balances
* `/balances` - [return **all** balances](#balances-1)
* `/balances/<username>` - [return username's balance](#balancesusername)

#### Other
* `/statistics` - [return server statistics (same as /api.json)](#statistics)
* `/exchange_request/?username=<username>&password=<password>&email=<email>&type=<ex_type>&amount=<amount>&coin=<coin>&address=<address>` - submit exchange request in the DUCO Exchange

##

### `/users/<username>`

- Example GET success response:

  ```json
  {
   "result":{
      "balance":{
         "balance":2935.2533704999164,
         "username":"revox"
      },
      "miners":[
         {
            "accepted":44,
            "algorithm":"DUCO-S1",
            "diff":1000,
            "hashrate":9070.0,
            "identifier":"Wemos",
            "rejected":0,
            "sharetime":11.59862,
            "software":"ESP8266 Miner v2.53",
            "threadid":"140632166046520",
            "username":"revox"
         }
      ],
      "transactions":[
         {
            "amount":1.0,
            "datetime":"22/06/2021 11:54:13",
            "hash":"18514d5a1e7c6f33c7bc8b3751e8b5ca1bfa9682",
            "memo":"None",
            "recipient":"Bilaboz",
            "sender":"revox"
         }
       ]
     }, 
     "success":true
  }
  ```

### `/transactions`

- Example GET success response:

  ```json
  {
   "result":{
      "1crtsk":[
         {
            "amount":203.0,
            "datetime":"22/06/2021 20:59:51",
            "hash":"54587c23cbd729dba4c44f20cdf60a9321e3deb1",
            "memo":"DUCO Exchange transaction",
            "recipient":"coinexchange",
            "sender":"1crtsk"
         },
         {
            "amount":35.02745118438233,
            "datetime":"28/06/2021 06:16:08",
            "hash":"fae931de744612e3624d5d77250b82b0c3f115f3",
            "memo":"Kolka ban",
            "recipient":"giveaways",
            "sender":"1crtsk"
         }
      ],
      "2002020":[
         {
            "amount":2.45,
            "datetime":"01/07/2021 01:16:33",
            "hash":"5444522a1e0cdec623624d3dfcee68dd2114d91f",
            "memo":"None",
            "recipient":"revox",
            "sender":"2002020"
         }
      ]
     }, 
     "success":true
  }
  ```

### `/transactions/<hash>`

- Example GET success response:

  ```json
  {
    "success": true,
    "result": {
        "amount": 5,
        "datetime": "18/04/2021 09:27:16",
        "hash": "b11019a12589831ccab2447bb69b08de51206693",
        "memo": "-",
        "recipient": "ATAR4XY",
        "sender": "revox"
      }
  }
  ```

### `/balances`

- Example GET success response:

  ```json
  {
    "success": true,
    "result": [
      {
        "balance": 47071.64148509737,
        "username": "chipsa"
      },
      {
        "balance": 45756.09652071045,
        "username": "coinexchange"
      },
      {
        "balance": 31812.522314445283,
        "username": "aarican"
      }
    ]
  }
  ```

### `/balances/<username>`

- Example GET success response:

  ```json
  {
    "success": true,
    "result": {
      "balance": 45756.09652071045,
      "username": "coinexchange"
    }
  }
  ```


### `/miners`

- Example GET success response:

  ```json
  {
    "success": true,
    "result": [
      {
        "accepted": 2935,
        "algorithm": "DUCO-S1",
        "diff": 5,
        "hashrate": 168,
        "id": "139797360490200",
        "identifier": "ProMiniRig Node6",
        "is estimated": "False",
        "rejected": 0,
        "sharetime": 3.324042,
        "software": "Official AVR Miner (DUCO-S1A) v2.45",
        "user": "MPM"
      },
      {
        "accepted": 1234,
        "algorithm": "DUCO-S1",
        "diff": 98765,
        "hashrate": 169000,
        "id": "139797360421968",
        "identifier": "PC Miner 1",
        "is estimated": "False",
        "rejected": 0,
        "sharetime": 2.065604,
        "software": "Official PC Miner (DUCO-S1) v2.45",
        "user": "dansinclair25"
      }
    ]
  }
  ```

### `/statistics`

- Example GET success response:

  ```json
  {
    "Active connections": 6596,
    "Active workers": {
      "revox": 70,
      "bilaboz": 1
    },
    "All-time mined DUCO": 936804.132060897,
    "Current difficulty": 212500,
    "DUCO-S1 hashrate": "1.6 GH/s",
    "Duco JustSwap price": 0.00791081,
    "Duco Node-S price": 0.001013,
    "Duco price": 0.0112407,
    "Duino-Coin Server API": "github.com/revoxhere/duino-coin",
    "Last block hash": "f76f5524b9...",
    "Last update": "08/05/2021 11:43:51 (UTC)",
    "Mined blocks": 1593769271,
    "Miners": "server.duinocoin.com/miners.json",
    "Open threads": 14,
    "Pool hashrate": "1.68 GH/s",
    "Registered users": 4837,
    "Server CPU usage": 43.2,
    "Server RAM usage": 26.3,
    "Server version": 2.4,
    "Top 10 richest miners": [
      "47079.374 DUCO - chipsa",
      "[...]",
      "15486.71 DUCO - MaddestHoldings"
    ],
    "XXHASH hashrate": "118.5 MH/s"
  }
  ```
  
More docs to come in the future
