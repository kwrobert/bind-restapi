#!/bin/bash
DOMAIN=mathworks.com

dnssec-keygen -a HMAC-SHA512 -b 512 -n USER $DOMAIN
cp ./bind-api.service /etc/systemd/system/
cp ./bind-api.conf /etc/
cp ./bind-restapi.py /usr/local/bin/
pip3 install -r requirements.txt
