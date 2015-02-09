#!/bin/bash

set -e

apt-get update
apt-get install -y git python-pip python-dev
pip install virtualenv

SCRIPTS=`dirname $0`

cd /opt/
git clone https://github.com/keepwatch/hpfeeds-arcsight.git
cd hpfeeds-arcsight
virtualenv env
. env/bin/activate
pip install -r requirements.txt
chmod 755 -R .

IDENT=hpfeeds-arcsight
SECRET=`python -c 'import uuid;print str(uuid.uuid4()).replace("-","")'`
CHANNELS='amun.events,dionaea.connections,dionaea.capture,glastopf.events,beeswarm.hive,kippo.sessions,conpot.events,snort.alerts,wordpot.events,shockpot.events,p0f.events'

cat > /opt/hpfeeds-arcsight/arcsight.json <<EOF
{
    "host": "localhost",
    "port": 10000,
    "ident": "${IDENT}",
    "secret": "${SECRET}",
    "channels": [
        "amun.events",
        "dionaea.connections",
        "dionaea.capture",
        "glastopf.events",
        "beeswarm.hive",
        "kippo.sessions",
        "conpot.events",
        "snort.alerts",
        "wordpot.events",
        "shockpot.events",
        "p0f.events"
    ],
    "log_file": "/var/log/mhn-arcsight.log",
    "formatter_name": "arcsight"
}
EOF

deactivate

. /opt/hpfeeds/env/bin/activate
python /opt/hpfeeds/broker/add_user.py "$IDENT" "$SECRET" "" "$CHANNELS"

apt-get install -y supervisor

cat >> /etc/supervisor/conf.d/hpfeeds-arcsight.conf <<EOF
[program:hpfeeds-arcsight]
command=/opt/hpfeeds-arcsight/env/bin/python logger.py arcsight.json
directory=/opt/hpfeeds-arcsight
stdout_logfile=/var/log/hpfeeds-arcsight.log
stderr_logfile=/var/log/hpfeeds-arcsight.err
autostart=true
autorestart=true
startsecs=1
EOF

supervisorctl update
