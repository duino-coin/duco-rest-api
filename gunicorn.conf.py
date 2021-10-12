from multiprocessing import cpu_count

bind = "0.0.0.0:5000"
keyfile = "/etc/letsencrypt/live/server.duinocoin.com/privkey.pem"
certfile = "/etc/letsencrypt/live/server.duinocoin.com/fullchain.pem"

worker_class = "gevent"
workers = 6
backlog = 0

graceful_timeout = 5
timeout = 600
limit_request_line = 7777
