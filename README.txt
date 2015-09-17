How to setup Magicicada Server and Client
=======================================

These are the general instructions to do all the needed setup to have
a proper file synchronization service up and running.

Let's assume you will work on a given directory, such as:

~/magicicada

Let's create that folder and cd into it, and you should run all the following
instructions using ~/magicicada as your cwd (current working directory):

    mkdir ~/magicicada
    cd ~/magicicada


Before server or client
-----------------------

Create the SSL certificates for client to communicate with server
securely. These certificates need to be stored in the folder:

~/magicicada/certs

To do so:

    mkdir ~/magicicada/certs
    cd ~/magicicada/certs

Now, generate a private key:

    openssl genrsa -out privkey.pem

Then, then generate a self-signed certificate. Note that at some point it will
ask you to write the "Common Name (e.g. server FQDN or YOUR name)", I found
that what you put there needs to match the '--host' parameter you pass to the
client (see below, in the part where the client is started), so this host name
must be such the client machine can ping it.

    openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095

The just generated 'privkey.pem' and 'cacert.pem' will be used below.
The 'privkey.pem' is only of interest of the server, so once used to setup the
server config, please remove the file or move it to another location.


Server setup
------------

Start with a clean Ubuntu Precise environment (for example, in a VPS, or using
an LXC). As example, if you want to create a precise LXC, you can use:

    sudo lxc-create -t ubuntu -n magicicada-precise -- -r precise -a amd64 -b $USER

Then you need to start the LXC instance and ssh into it:

    sudo lxc-start -n magicicada-precise
    ssh magicicada-precise

Install tools and dependencies (you will be prompted for your password for sudo
access):

    make bootstrap

Branch the project and get into that dir:

    cd ~/magicicada
    bzr branch lp:magicicada-server

Ensure the files 'privkey.pem' and 'cacert.pem' produced in the "Before server
or client" section are copied into the ~/magicicada/magicicada-server/certs
folder.

Start the server:

    cd ~/magicicada/magicicada-server
    make start-oauth

Note that the server will listen on port 21101, so you need to assure that the
client could reach it (open the whole it in your firewall config, etc).

Finally, create all the users you want:

    dev-scripts/user-mgr.py create testuser John Doe jdoe@gmail.com testpass

(with this script you'll be able to also retrieve and update user data,
and delete users)


Client setup
------------

This is to be repeated in all places that you want the system to run.
Instructions are for an Ubuntu Trusty environment, adapt as needed. It's
assuming you're starting from a clean machine (e.g.: a just installed one,
or an LXC), if you're not you may have some of the needed parts
already installed.

First, install tools and dependencies:

    sudo apt-get install python-twisted-bin python-twisted-core \
        python-dirspec python-pyinotify python-configglue \
        python-twisted-names python-ubuntu-sso-client \
        python-distutils-extra protobuf-compiler python-protobuf

Following the folder structure we started above, branch the client and the
protocol so the final layout will be as follow:

    ~/magicicada/magicicada-protocol   <-- this is a subproject needed by the client
    ~/magicicada/magicicada-client   <-- this is the proper magicicada client
    ~/magicicada/certs   <-- this is where you'll store the SSL certs for the client

So, branch and build the storage protocol:

    cd ~/magicicada
    bzr branch lp:magicicada-protocol
    cd magicicada-protocol
    ./setup.py build

Ensure the proper certificate is the right folder, for the client you only need
'cacert.pem':

    ls ~/magicicada/certs

You should see something like:

-rw-rw-r-- 1 user user 765 Aug 13 09:18 cacert.pem

Also branch and build the client:

    cd ~/magicicada
    bzr branch lp:magicicada-client
    cd magicicada-client/ubuntuone
    ln -s ~/magicicada/magicicada-protocol/ubuntuone/storageprotocol .
    cd ..
    ./setup.py build

Finally, start the client

    export $(dbus-launch)  # seems this is needed if you're inside a LXC or VPS
    PYTHONPATH=. SSL_CERTIFICATES_DIR=~/magicicada/certs bin/ubuntuone-syncdaemon \
        --auth=testuser:testpass --host=testfsyncserver \
        --port=21101 --logging-level=DEBUG

If you want, check logs to see all went ok

    less $HOME/.cache/ubuntuone/log/syncdaemon.log


There, this line will show that the client started ok:

    ubuntuone.SyncDaemon.Main - NOTE - ---- MARK (state: <State: 'INIT' ...


And this line will show that the client reached the server ok (so no network issues):

    ubuntuone.SyncDaemon.StateManager - DEBUG - received event 'SYS_CONNECTION_MADE'


Finally, this line will show that client authenticated OK to the server
(no username/password issues):

    ubuntuone.SyncDaemon.StateManager - DEBUG - received event 'SYS_AUTH_OK'


Enjoy.
