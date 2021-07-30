bind = "127.0.0.1:5000"
workers = 5
threads = 5
keepalive = 1
worker_class = "gevent"
keyfile = "/etc/letsencrypt/live/server.duinocoin.com/privkey.pem"
certfile = "/etc/letsencrypt/live/server.duinocoin.com/fullchain.pem"
