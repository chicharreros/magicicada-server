Magicicada Server
=================

![tests](https://github.com/chicharreros/magicicada-server/actions/workflows/tests.yml/badge.svg)


How to setup Magicicada Server and Client
=========================================

These are the general instructions to do all the needed setup to have
a proper file synchronization service up and running.

Let's assume you will work on a given directory, such as::

    ~/magicicada

Let's create that folder and cd into it, and you should run all the following
instructions using ~/magicicada as your cwd (current working directory)::

    mkdir ~/magicicada
    cd ~/magicicada


Before server or client
-----------------------

Create the SSL certificates for client to communicate with server
securely. These certificates need to be stored in the folder::

    ~/magicicada/certs

To do so::

    mkdir ~/magicicada/certs
    cd ~/magicicada/certs

Now, generate a private key::

    openssl genrsa -out privkey.pem

Then generate a self-signed certificate. Note that at some point it will
ask you to write the "Common Name (e.g. server FQDN or YOUR name)", I found
that what you put there needs to match the '--host' parameter you pass to the
client (see below, in the part where the client is started), so this host name
must be such the client machine can ping it::

    openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095

The just generated 'privkey.pem' and 'cacert.pem' will be used below.
The 'privkey.pem' is only of interest of the server, so once used to setup the
server config, please remove the file or move it to another location.


Server setup
------------

Start with a clean Ubuntu Xenial environment (e.g., in a VPS, or using
an LXC). As example, if you want to create a Xenial LXC, you can use::

    lxc launch ubuntu:bionic -p default -p $USER magicicada-server


Dependencies
^^^^^^^^^^^^

Find the instance IP (and optionally configure `/etc/hosts` to be able to ssh
into the container by name) and ssh into it:

    ssh `lxc list magicicada-server -c4 -fcsv | cut -d ' ' -f 1`

Install ``make``, you'll need it for the rest of the process::

    sudo apt-get install make

Branch the project and get into that dir::

    cd ~/magicicada
    git clone https://github.com/chicharreros/magicicada-server.git
    cd magicicada-server

Install tools and dependencies (you will be prompted for your password for sudo
access)::

    make bootstrap

Ensure the files 'privkey.pem' and 'cacert.pem' produced in the "Before server
or client" section are copied into the ~/magicicada/magicicada-server/certs
folder.


Using a temporary setup
^^^^^^^^^^^^^^^^^^^^^^^

Just run::

    make start-db

...and the server will use a in-memory database, and will store any transferred
files in the ``./tmp`` temporary directory.


Using a system-level setup
^^^^^^^^^^^^^^^^^^^^^^^^^^

Assuming you created a Postgresql 9.5 database named "filesync" with a
"magicicada" user as owner::

    sudo su - postgres
    createuser magicicada -P
    createdb filesync -O magicicada

Edit or create the file ``magicicada/settings/local.py`` so it makes to use
the external DB and store the files in an external directory (change at
will)::

    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql_psycopg2',
            'NAME': 'filesync',
            'HOST': 'localhost',
            'USER': 'magicicada',
            'PASSWORD': <what you choose in createuser>,
        },
    }
    STORAGE_BASEDIR = '/var/lib/magicicada/filestorage'

Then, to confirm you have configured your database correctly, run::

    make manage ARGS=dbshell

and you should obtain a prompt in the PG database. Now, create the database
schema::

    make manage ARGS=migrate


Run the filesync server
^^^^^^^^^^^^^^^^^^^^^^^

Start the server via command line this way::

    cd ~/magicicada/magicicada-server
    make start

Note that the server will listen on port 21101, so you need to assure that the
client could reach it (open the whole it in your firewall config, etc).

Finally, create all the users you want::

    make manage ARGS="user_mgr create testuser John Doe jdoe@gmail.com testpass"

(with this django command you'll be able to also retrieve and update user data,
and delete users)

After that, you could stop the server doing::

    make stop

...and resume back doing::

    make resume


How to autostart the server on reboot
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These are the instructions using systemd. Create a file named
``/lib/systemd/system/magicicada.service`` with the following
content (be sure to fix the ``User`` and ``WorkingDirectory`` fields)::

    [Unit]
    Description=Magicicada Server
    After=network.target

    [Service]
    User=<your user>
    WorkingDirectory=<path to where you have the server>
    Type=oneshot
    ExecStart=/usr/bin/make resume
    RemainAfterExit=true
    ExecStop=/usr/bin/make stop

    [Install]
    WantedBy = multi-user.target

After that file is in place, doing the following you should see in the
magicicada logs as it stops and resumes::

    systemctl start magicicada
    systemctl stop magicicada

When you are sure that those previous commands work ok, enable magicicada to
be started at machine's boot time::

    systemctl enable magicicada


Client setup
------------

This is to be repeated in all places that you want the system to run.
Instructions are for an Ubuntu Focal environment, adapt as needed. It's
assuming you're starting from a clean machine (e.g.: a just installed one,
or an LXC), if you're not you may have some of the needed parts
already installed.

Following the folder structure we started above, branch the client and the
protocol so the final layout will be as follow:

- ~/magicicada/magicicada-protocol   <-- a subproject needed by the client
- ~/magicicada/magicicada-client   <-- the proper magicicada client
- ~/magicicada/certs   <-- where you'll store the SSL certs for the client

First branch the client and install all the needed tools and dependencies::

    cd ~/magicicada
    git clone https://github.com/chicharreros/magicicada-client.git
    cd magicicada-client
    make bootstrap

Ensure the proper certificate is the right folder, for the client you only need
`cacert.pem` (be sure the `private.pem` file is NOT there)::

    ls ~/magicicada/certs

You should see something like::

    -rw-rw-r-- 1 user user 765 Aug 13 09:18 cacert.pem

Finally, start the client::

    export $(dbus-launch)  # seems this is needed if you're inside a LXC or VPS
    PYTHONPATH=. SSL_CERTIFICATES_DIR=~/magicicada/certs \
        bin/ubuntuone-syncdaemon --auth=testuser:testpass \
        --server=testfsyncserver:21101 --logging-level=DEBUG

If you want, check logs to see all went ok::

    less $HOME/.cache/ubuntuone/log/syncdaemon.log


There, this line will show that the client started ok::

    ubuntuone.SyncDaemon.Main - NOTE - ---- MARK (state: <State: 'INIT' ...


And this line will show that the client reached the server ok (so no
network issues)::

    ubuntuone.SyncDaemon.StateManager - DEBUG - received event 'SYS_CONNECTION_MADE'


Finally, this line will show that client authenticated OK to the server
(no username/password issues)::

    ubuntuone.SyncDaemon.StateManager - DEBUG - received event 'SYS_AUTH_OK'


Enjoy.
