#!/bin/bash

yum install -y python3-pip bind-utils

cp ./bind-api.service /etc/systemd/system/
cp ./bind-api.conf /etc/
cp ./bind-restapi.py /usr/local/bin/
pip3 install -r requirements.txt
systemctl enable bind-api.service
systemctl start bind-api.service
