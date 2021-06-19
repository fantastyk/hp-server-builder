# Introduction

This is a collection of python scripts that will flash firmware, format storage and install windows to a HPE Proliant baremetal server. I prototyped this to work with a RaspberryPI hosting the ISOs, MQ, and DHCP server so it could be portable if it needed to be. The main script itself is designed to be ran from WSL so you can still run the windows native ilo console binaries. 

Other required infrastrcture
- MQ service
- DHCP server that can run off the raspberryPI

**Note:** I no longer have access to HPE hardware so I can no longer add features to this script. 

## api.py 

This script is flask web api thats host information from a REST POST request and pushes the information to a message queue. 

## server_info.yml

This is a settings file that `server-build.py` reads in for configuration data. Currently only RAID1 and RAID10 are supported but RAID5 could be easily added. 

## server-build.py

This is the main script. It reads in the server_info.yml variable file and provisions the server.  Ansible playbooks can be launch after installation if the `--ansible` flag is set. 

