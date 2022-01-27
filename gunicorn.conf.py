bind = "0.0.0.0:5000"

worker_class = "gevent"
workers = 3
worker_connections = 281100
max_requests = 1500
max_requests_jitter = 150

graceful_timeout = 15
keepalive = 64
timeout = 600
limit_request_line = 7777
