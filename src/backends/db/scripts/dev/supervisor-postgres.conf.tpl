[program:postgres]
command=python %(basepath)s/lib/backends/db/scripts/dev/start-postgres.py
environment=PYTHONPATH="%(basepath)s:%(basepath)s/lib",DJANGO_SETTINGS_MODULE="magicicada.settings"
redirect_stderr=true                          ; send stderr to the log file
stdout_logfile=%(tmp_dir)s/postgres.log
autostart=false
stopsignal=INT
