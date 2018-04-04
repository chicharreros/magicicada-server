; supervisor config file
[supervisord]
logfile=%(basepath)s/tmp/supervisor-dev.log          ; (main log file;default $CWD/supervisord.log)
pidfile=%(basepath)s/tmp/supervisor-dev.pid          ; (supervisord pidfile;default supervisord.pid)
childlogdir=%(basepath)s/tmp/supervisor-dev-childlog/ ; ('AUTO' child log dir, default $TEMP)
logfile_maxbytes = 50MB
logfile_backups = 10
loglevel = info
nodaemon = false
minfds = 1024
minprocs = 200
identifier = supervisor-dev

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=http://localhost:%(inet_http_server_port)s

[inet_http_server]
port=%(inet_http_server_port)s

[include]
files=services-supervisor.conf workers-supervisor.conf

[eventlistener:heartbeat]
command=python %(basepath)s/lib/ubuntuone/supervisor/heartbeat_listener.py --interval=10 --timeout=20 --log_level=DEBUG --log_file=%(tmp_dir)s/heartbeat.log --groups=filesync-server
environment=PYTHONPATH="%(basepath)s:%(basepath)s/lib"
events=PROCESS_COMMUNICATION,TICK_5
buffer_size=42

[program:filesync]
command=%(basepath)s/.env/bin/twistd --pidfile %(tmp_dir)s/filesync.pid -n -y %(basepath)s/magicicada/server/server.tac --reactor=epoll
environment=PYTHONPATH="%(basepath)s:%(basepath)s/lib",DJANGO_SETTINGS_MODULE="magicicada.settings",PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=cpp
stdout_capture_maxbytes=16384
autostart=false
stopsignal=INT

[program:ssl-proxy]
command=%(basepath)s/.env/bin/twistd --pidfile %(tmp_dir)s/ssl-proxy.pid -n -y %(basepath)s/magicicada/server/ssl_proxy.tac  --reactor=epoll
environment=PYTHONPATH="%(basepath)s:%(basepath)s/lib",DJANGO_SETTINGS_MODULE="magicicada.settings"
stdout_capture_maxbytes=16384
autostart=false
stopsignal=INT

[group:filesync-server]
programs=filesync,ssl-proxy
