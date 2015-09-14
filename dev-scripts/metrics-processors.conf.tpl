[program:graphite]
command=%(basepath)s/dev-scripts/run-graphite-devserver.py
environment=PYTHONPATH="%(basepath)s:%(basepath)s/lib",DJANGO_SETTINGS_MODULE="filesync.settings"
autostart=false
kill_as_group=true

[program:statsd]
command=%(basepath)s/dev-scripts/run-statsd.py
environment=PYTHONPATH="%(basepath)s:%(basepath)s/lib",DJANGO_SETTINGS_MODULE="filesync.settings"
autostart=false
kill_as_group=true
