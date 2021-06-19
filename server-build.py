#!/usr/bin/env python3

import re
import time
import yaml
import colorama
from colorama import Fore
import os
import subprocess
import yaml
import json
import argparse
from ipaddress import ip_address
import sys
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError
from get_resource_directory import get_resource_directory
import netifaces
import pika

messages = 0
body_return = {}

# this might fail to authenticate. It doesn't handle ^ because of the escaping in wondows -_-
def connect_console(hostname, user, password):
    pw = password.replace('^', '^^') #windows escape character helper
    subprocess.call(["cmd.exe", "/c", "start", "./exes/HPLOCONS.exe", "-addr", hostname, "-name", user, "-password", pw])
    return

#starts golang http server to host ISO files.
def start_http():
    subprocess.call(["cmd.exe", "/c", "start", "./iso/serve.exe"])
    return

def ansible_launch(inventory):
#     #Yay Stackoverflow - https://stackoverflow.com/a/49702745
    which = lambda y: next(filter(lambda x: os.path.isfile(x) and os.access(x, os.X_OK),
                                  [x + os.path.sep + y for x in os.getenv("PATH").split(os.pathsep)]), None)
    ansible = which('ansible-playbook')
    print(Fore.GREEN + "    [+]" + Fore.RESET + " Running this command - " + ansible, "-i", inventory, "./playbooks/hp-windows-build.yml")
    #subprocess.call([ansible, "-i", inventory, "./ansible/hp-windows-build.yml", "--vault-password-file", "./playbooks/vault"]
    subprocess.call([ansible, "-i", inventory, "./ansible/hp-windows-build.yml"])
   



def _on_message(ch, method, properties, body):
    info = json.loads(body)
    mes_hostname = info['hostname']
    mes_ip = info['ipaddress']
    mes_mac = info['MAC']

    #create inventory file
    channel.basic_ack(method.delivery_tag)
    print(Fore.GREEN + "    [+]" + Fore.RESET + " Callback received!")
    print(Fore.GREEN + "    [+]" + Fore.RESET + " Hostname: " + mes_hostname )
    print(Fore.GREEN + "    [+]" + Fore.RESET + " IP: " + mes_ip)
    print(Fore.GREEN + "    [+]" + Fore.RESET + " MAC: " + mes_mac)

    global messages
    global body_return
    body_return = body
    messages += 1
    if messages > 0:
        channel.stop_consuming()

def ilo_login(SYSTEM_URL, LOGIN_ACCOUNT, LOGIN_PASSWORD):
    try:
        # Create a Redfish client object
        REDFISHOBJ = RedfishClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, \
                                                                            password=LOGIN_PASSWORD)
        # Login with the Redfish client
        REDFISHOBJ.login()
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write(Fore.RED + "ERROR: server not reachable or does not support RedFish.\n" + Fore.RESET)
        sys.exit()
    return REDFISHOBJ

def boot_check(_redfishobj, STATUS, bootstate, osboot):
    #bootstate is passed to control the flow. Sometimes you want it to look for a boot OS. 
    # Other times you want to check for booting status" 
    attempted_reboot = False
    os_boot_attempt = 0
    while True:
        time.sleep(60)
        status = ""
        status = system_details(REDFISHOBJ, STATUS)
        #Debugging
        #print(Fore.YELLOW + "DEBUG - Status: " + status + Fore.RESET)
        if status == "InPostDiscoveryComplete" and attempted_reboot == True:
            print(Fore.RED + "  [-]" + Fore.RESET + " Something is wrong - please investigate. Aborting.")
            sys.exit()
        if status == "InPost":

            if  bootstate == "InPost":
                print(Fore.GREEN + "    [+]" + Fore.RESET + " Server is booting.")
                break    
            else: 
                continue

        elif status == "InPostDiscoveryComplete":
            if bootstate == "InPostDiscoveryComplete":
                print(Fore.GREEN + "    [+]" + Fore.RESET + " POST complete.")
                break
            if osboot == True and os_boot_attempt <= 10:
                os_boot_attempt = os_boot_attempt + 1
                continue
            else:
                print(Fore.RED + "  [-]" + Fore.RESET + " Server failed to boot in a OS - Sending Reboot Command.")
                reboot_server(REDFISHOBJ)
                attempted_reboot = True
                continue

        if status == "FinishedPost":
            if bootstate == "FinishedPost":
                print(Fore.GREEN + "    [+]" + Fore.RESET + " Server booted into a OS!")
                break
            else:
                continue

        elif status == "Poweroff":
            print(Fore.RED + "  [-]" + Fore.RESET + " Server is off. Power on please. ")

        else: 
            print("Aborting - Unrecognized status " + status)
            sys.exit()
    
def system_details(_redfishobj, location):
    systems_members_uri = None
    systems_members_response = None

    resource_instances = get_resource_directory(_redfishobj)
    if DISABLE_RESOURCE_DIR or not resource_instances:
        #if we do not have a resource directory or want to force it's non use to find the
        #relevant URI
        systems_uri = _redfishobj.root.obj['Systems']['@odata.id']
        systems_response = _redfishobj.get(systems_uri)
        systems_members_uri = next(iter(systems_response.obj['Members']))['@odata.id']
        systems_members_response = _redfishobj.get(systems_members_uri)
    else:
        for instance in resource_instances:
            #Use Resource directory to find the relevant URI
            if '#ComputerSystem.' in instance['@odata.type']:
                systems_members_uri = instance['@odata.id']
                systems_members_response = _redfishobj.get(systems_members_uri)

    #print("\n\nPrinting computer system details:\n\n")
    #print(json.dumps(systems_members_response.dict, indent=4, sort_keys=True))
    #print(systems_members_response.dict[])
    #print("Boot Status: " + systems_members_response.dict['Status']['State'])
    #print("Post State: " + systems_members_response.dict['Oem']['Hpe']['PostState'])
    if len(location) == 3:
        status = systems_members_response.dict[location[0]][location[1]][location[2]]
    elif len(location) == 2:
        status = systems_members_response.dict[location[0]][location[1]]
    return status

def set_license_key(_redfishobj, ilo_key):

    ilo_lic_uri = None

    resource_instances = get_resource_directory(_redfishobj)
    if DISABLE_RESOURCE_DIR or not resource_instances:
        #if we do not have a resource directory or want to force it's non use to find the
        #relevant URI
        managers_uri = _redfishobj.root.obj['Managers']['@odata.id']
        managers_response = _redfishobj.get(managers_uri)
        managers_members_uri = next(iter(managers_response.obj['Members']))['@odata.id']
        managers_members_response = _redfishobj.get(managers_members_uri)
        ilo_lic_uri = managers_members_response.obj.Oem.Hpe.Links['LicenseService']['@odata.id']
    else:
        #Use Resource directory to find the relevant URI
        for instance in resource_instances:
            if '#HpeiLOLicense.' in instance['@odata.type']:
                ilo_lic_uri = instance['@odata.id']

    if ilo_lic_uri:
        ilo_license_collection = _redfishobj.get(ilo_lic_uri)
        ilo_license_member_uri = next(iter(ilo_license_collection.obj['Members']))['@odata.id']
        try:
            ilo_license_data = _redfishobj.get(ilo_license_member_uri).obj['ConfirmationRequest']\
                                                                                            ['EON']
        except KeyError:
            sys.stdout.write("This machine will not show the full License Key.\n")
            ilo_license_data = _redfishobj.get(ilo_license_member_uri).obj['LicenseKey']

        #sys.stdout.write("Current iLO License Data:\n")
        #print(json.dumps(ilo_license_data, indent=4, sort_keys=True))
        resp = _redfishobj.post(ilo_lic_uri, {'LicenseKey' : ilo_key})
        #If iLO responds with soemthing outside of 200 or 201 then lets check the iLO extended info
        #error message to see what went wrong
        if resp.status == 400:
            try:
                print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, \
                                                                                sort_keys=True))
                sys.stderr.write("Check the validity of your license key...\n")
            except Exception as excp:
                sys.stderr.write("A response error occurred, unable to access iLO " \
                                 "Extended Message Info...")
        if resp.status != 200 and resp.status != 201:
            sys.stderr.write("An http response of \'%s\' was returned.\n" % resp.status)
        if resp.status == 201: 
            print(Fore.GREEN + "    [+]" + Fore.RESET + " ILO is already licensed")
        else:
            print(Fore.GREEN + "    [+]" + Fore.RESET + " Success!")
            #print(json.dumps(resp.dict, indent=4, sort_keys=True))

def mount_virtual_media_iso(_redfishobj, iso_url, media_type, boot_on_next_server_reset):

    virtual_media_uri = None
    virtual_media_response = []

    resource_instances = get_resource_directory(_redfishobj)
    if DISABLE_RESOURCE_DIR or not resource_instances:
        #if we do not have a resource directory or want to force it's non use to find the
        #relevant URI
        managers_uri = _redfishobj.root.obj['Managers']['@odata.id']
        managers_response = _redfishobj.get(managers_uri)
        managers_members_uri = next(iter(managers_response.obj['Members']))['@odata.id']
        managers_members_response = _redfishobj.get(managers_members_uri)
        virtual_media_uri = managers_members_response.obj['VirtualMedia']['@odata.id']
    else:
        for instance in resource_instances:
            #Use Resource directory to find the relevant URI
            if '#VirtualMediaCollection.' in instance['@odata.type']:
                virtual_media_uri = instance['@odata.id']

    if virtual_media_uri:
        virtual_media_response = _redfishobj.get(virtual_media_uri)
        for virtual_media_slot in virtual_media_response.obj['Members']:
            data = _redfishobj.get(virtual_media_slot['@odata.id'])
            if media_type in data.dict['MediaTypes']:
                virtual_media_mount_uri = data.obj['Actions']['#VirtualMedia.InsertMedia']['target']
                post_body = {"Image": iso_url}

                if iso_url:
                    resp = _redfishobj.post(virtual_media_mount_uri, post_body)
                    if boot_on_next_server_reset is not None:
                        patch_body = {}
                        patch_body["Oem"] = {"Hpe": {"BootOnNextServerReset": \
                                                 boot_on_next_server_reset}}
                        boot_resp = _redfishobj.patch(data.obj['@odata.id'], patch_body)
                        if not boot_resp.status == 200:
                            sys.stderr.write("Failure setting BootOnNextServerReset")
                    if resp.status == 400:
                        try:
                            print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, \
                                                                                    sort_keys=True))
                        except Exception as excp:
                            sys.stderr.write("A response error occurred, unable to access iLO"
                                             "Extended Message Info...")
                    elif resp.status != 200:
                        sys.stderr.write("An http response of \'%s\' was returned.\n" % resp.status)
                    else:
                        print(Fore.GREEN + "    [+]" + Fore.RESET + f" Success! - mounted {iso_url}")
                        #print(json.dumps(resp.dict, indent=4, sort_keys=True))
                break
def reboot_server(_redfishobj):

    systems_members_response = None

    resource_instances = get_resource_directory(_redfishobj)
    if DISABLE_RESOURCE_DIR or not resource_instances:
        #if we do not have a resource directory or want to force it's non use to find the
        #relevant URI
        systems_uri = _redfishobj.root.obj['Systems']['@odata.id']
        systems_response = _redfishobj.get(systems_uri)
        systems_members_uri = next(iter(systems_response.obj['Members']))['@odata.id']
        systems_members_response = _redfishobj.get(systems_members_uri)
    else:
        for instance in resource_instances:
            #Use Resource directory to find the relevant URI
            if '#ComputerSystem.' in instance['@odata.type']:
                systems_members_uri = instance['@odata.id']
                systems_members_response = _redfishobj.get(systems_uri)

    if systems_members_response:
        system_reboot_uri = systems_members_response.obj['Actions']['#ComputerSystem.Reset']\
                                                                                        ['target']
        body = dict()
        body['Action'] = 'ComputerSystem.Reset'
        body['ResetType'] = "ForceRestart"
        resp = _redfishobj.post(system_reboot_uri, body)
        #If iLO responds with soemthing outside of 200 or 201 then lets check the iLO extended info
        #error message to see what went wrong
        if resp.status == 400:
            try:
                print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, \
                                                                                    sort_keys=True))
            except Exception as excp:
                sys.stderr.write("A response error occurred, unable to access iLO Extended "
                                 "Message Info...")
        elif resp.status != 200:
            sys.stderr.write("An http response of \'%s\' was returned.\n" % resp.status)
        else:
            print(Fore.GREEN + "    [+]" + Fore.RESET + " Reboot Sent!")
            #print(json.dumps(resp.dict, indent=4, sort_keys=True))

def set_SmartArray_LogicalDrives(_redfishobj, raidtype, drives_to_configure, logicaldrivenum):

    smartstorage_response = []
    smartarraycontrollers = dict()
    #Need to add support for Raid 5
    if raidtype == "Raid1":
        newraid_body = {
        "DataGuard": "Permissive",
        "LogicalDrives": [
           {
              "CapacityGiB": -1,
              "Raid": raidtype,
              "StripSizeBytes": 262144,
              "LogicalDriveName": raidtype,
              "DataDrives": drives_to_configure,
              "Accelerator": "ControllerCache" 
           }
        ]
    }

    if raidtype == "Raid10":
        newraid_body = {
        "DataGuard": "Permissive",
        "LogicalDrives": [
           {
              "CapacityGiB": -1,
              "Raid": raidtype,
              "StripSizeBytes": 262144,
              "StripeSizeBytes": 786432,
              "LogicalDriveName": raidtype,
              "DataDrives": drives_to_configure,
              "Accelerator": "ControllerCache" 
           }
        ]
    }
    #print (newraid_body)
    resp = _redfishobj.put("/redfish/v1/systems/1/smartstorageconfig/settings", newraid_body)
    check_status = _redfishobj.get("/redfish/v1/systems/1/smartstorageconfig")
    #print(json.dumps(check_status.obj, indent=4 , sort_keys=True))

    #print(raid_build_response)
    #print(raid_build_response.obj)
    if resp.status == 400:
        try:
            print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, \
                                                                            sort_keys=True))
        except Exception as excp:
            sys.stderr.write("A response error occurred, unable to access iLO Extended "\
                             "Message Info...")
    elif resp.status != 200:
        sys.stderr.write("An http response of \'%s\' was returned.\n" % resp.status)
    else:
        print(Fore.GREEN + "    [+]" + Fore.RESET + " Command Sent - Need to reboot")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='HPE Proliant Automated Build Script.')
    parser.add_argument( '-ip', type=str)
    parser.add_argument( '-u', type=str)
    parser.add_argument( '-p', type=str)
    parser.add_argument( '-c', type=str)
    parser.add_argument('--ansible', help="switch to launch straight into ansible", action='store_true')

    args = parser.parse_args()
    # When running on the server locally use the following commented values
    #SYSTEM_URL = None
    #LOGIN_ACCOUNT = None
    #LOGIN_PASSWORD = None

    # When running remotely connect using the secured (https://) address,
    # account name, and password to send https requests
    # SYSTEM_URL acceptable examples:
    # "https://10.0.0.100"
    # "https://ilo.hostname"
    SYSTEM_URL = "https://" + args.ip
    LOGIN_ACCOUNT = args.u
    LOGIN_PASSWORD = args.p

    CONFIG = open(args.c)
    PARSED_CONFIG = yaml.load(CONFIG, Loader=yaml.FullLoader)
    
    POST_STATE = ['Oem','Hpe','PostState']
    #BOOT_STATE = ['Status', 'State']
    bootstate_booting = "InPost"
    bootstate_booted = "FinishedPost"
    bootstate_booted_failsafe = "InPostDiscoveryComplete"
    logical_drive_count = 1
    messages = 1
    body_return = {}
    #boot_check(REDFISHOBJ,POST_STATE, bootstate_booting)

    #Getting System IP
    sleep_time_spp = int(900)
    minutes = lambda s: s / 60 
    #ip = netifaces.ifaddresses('eth0')[2][0]['addr']
    ip = "192.168.40.150"
    spp_url = "http://" + ip + "/" + PARSED_CONFIG["global"]["spp_iso"]
    spp_type = "DVD"
    os_url =  "http://" + ip + "/" + PARSED_CONFIG["global"]["os_iso"] 
    os_type = "DVD"
    #floppy_url = "http://" + ip + "/" + PARSED_CONFIG["global"]["floppy_img"]
    #floppy_type = "Floppy"

    # Must be a valid iLO License Key, put in variable file (yml)

    ILO_LICENSE_KEY = PARSED_CONFIG["ilo_settings"]["ilokey"]

    raid = PARSED_CONFIG["ilo_settings"]["disksetup"]["os_drive"]

    # flag to force disable resource directory. Resource directory and associated operations are
    # intended for HPE servers.
    DISABLE_RESOURCE_DIR = True


    REDFISHOBJ = ilo_login(SYSTEM_URL, LOGIN_ACCOUNT, LOGIN_PASSWORD)
    # try:
    #     # Create a Redfish client object
    #     REDFISHOBJ = ilo_login(SYSTEM_URL, LOGIN_ACCOUNT, LOGIN_PASSWORD)
    #     # Login with the Redfish client
    #     REDFISHOBJ.login()
    # except ServerDownOrUnreachableError as excp:
    #     sys.stderr.write(Fore.RED + "ERROR: server not reachable or does not support RedFish.\n" + Fore.RESET)
    #     sys.exit()
#    connect_console(args.ip, LOGIN_ACCOUNT, LOGIN_PASSWORD)
    print(Fore.GREEN + "[+]" + Fore.RESET + " Setting ILO License")
    set_license_key(REDFISHOBJ, ILO_LICENSE_KEY)
    #set_ilo_network(REDFISHOBJ) #implement later to set ilo network settings
    #Starting http server for ISOS
    print(Fore.GREEN + "[+]" + Fore.RESET + " Starting HTTP Server")
    #start_http()
    #Finding SSP name and build url

    #Mounting SPP ISO
    print(Fore.GREEN + "[+]" + Fore.RESET + " Mounting SPP")
    #media_type = current possible options: Floppy, USBStick, CD, DVD
    mount_virtual_media_iso(REDFISHOBJ, spp_url, PARSED_CONFIG["global"]["spp_format"] , True)
    print(Fore.GREEN + "[+]" + Fore.RESET + " Rebooting to Flash Firmware")
    reboot_server(REDFISHOBJ)
    boot_check(REDFISHOBJ,POST_STATE, bootstate_booted, True)
    print(Fore.GREEN + "[+]" + Fore.RESET + " Sleeping for " + str(minutes(sleep_time_spp))+" minutes")
    #print(Fore.GREEN + "[+]" + Fore.RESET + " Sleeping for " + str(minutes(sleep_time_spp))+" minutes")
    time.sleep(sleep_time_spp)
    print(Fore.GREEN + "[+]" + Fore.RESET + " Reconnecting in case of disconnect during SPP update")
    REDFISHOBJ = ilo_login(SYSTEM_URL, LOGIN_ACCOUNT, LOGIN_PASSWORD)
    print(Fore.GREEN + "[+]" + Fore.RESET + " Seeing if we are finished flashing")
    boot_check(REDFISHOBJ, POST_STATE, bootstate_booted_failsafe, False)


    for r in raid:
       print(Fore.GREEN + "[+]" + Fore.RESET + " Building RAID - " + r)
       raid_config = PARSED_CONFIG["ilo_settings"]["disksetup"]["os_drive"][r] 
       set_SmartArray_LogicalDrives(REDFISHOBJ, r, raid_config, logical_drive_count) 
       reboot_server(REDFISHOBJ)
       #time.sleep(180)
       print(Fore.GREEN + "[+]" + Fore.RESET + " Checking Boot Status")
       boot_check(REDFISHOBJ,POST_STATE, bootstate_booted_failsafe, False)
       reboot_server(REDFISHOBJ)
       logical_drive_count = logical_drive_count + 1

    print(Fore.GREEN + "[+]" + Fore.RESET + " Mounting OS ISO")
    mount_virtual_media_iso(REDFISHOBJ, os_url, PARSED_CONFIG["global"]["os_format"] , True)


    print(Fore.GREEN + "[+]" + Fore.RESET + " Rebooting to install the OS")
    reboot_server(REDFISHOBJ)
    print(Fore.GREEN + "[+]" + Fore.RESET + " Seeing if we made it into the install ISO")
    boot_check(REDFISHOBJ,POST_STATE, bootstate_booted, True)

    if args.ansible == True:
        print(Fore.GREEN + "[+]" + Fore.RESET + " Checking for Post install reboot.")
        boot_check(REDFISHOBJ, POST_STATE, bootstate_booting, False)
        print(Fore.GREEN + "[+]" + Fore.RESET + " Waiting for host callback... ")
        mount_virtual_media_iso(REDFISHOBJ, os_url, PARSED_CONFIG["global"]["os_format"], False)
        connection = pika.BlockingConnection(pika.ConnectionParameters('192.168.40.150'))
        channel = connection.channel()
        channel.queue_declare(queue='hostinfo')
        # channel.queue_declare(queue="hello", durable=True, exclusive=False, auto_delete=False)
                              #queue       #callback
        channel.basic_consume("hostinfo", _on_message)
        channel.start_consuming()

        #build inventory file
        print(Fore.GREEN + "[+]" + Fore.RESET + " Building inventory")
        host_info = json.loads(body_return)
        mac = host_info['MAC'].replace('-', '')
        inv_ip = host_info['ipaddress']
        inventoryname = "inventory." + mac

        f = open(inventoryname, "w")
        f.close()
        f = open(inventoryname, "a")
        f.write("[all]\n")
        f.write(inv_ip)
        f.close()
        REDFISHOBJ.logout()
        #launch ansible playbook
        print(Fore.GREEN + "[+]" + Fore.RESET + " Launching anisble")
        ansible_launch(inventoryname)
    else:
        print(Fore.GREEN + "[+]" + Fore.RESET + " OS should be up in a few minutes")
        REDFISHOBJ.logout()








