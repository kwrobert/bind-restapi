#!/bin/bash

cp ./bind-api.service /etc/systemd/system/
cp ./bind-api.conf /etc/
cp ./bind-restapi.py /usr/local/bin/
pip3 install -r requirements.txt
