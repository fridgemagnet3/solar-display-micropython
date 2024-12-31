#!/usr/bin/env python3
import hashlib
from hashlib import sha1
import hmac
import base64
from datetime import datetime
from datetime import timezone
import requests
import json
import socket
import time
import syslog
from collections import OrderedDict

# create a minimal subset of data from the Solis supplied set
def create_minimal_json(solar_json_in):

    if solar_json_in==None:
        return None
    
    dst_data = OrderedDict()
    if 'success' in solar_json_in:
        dst_data['success'] = solar_json_in['success']
    if 'code' in solar_json_in:
        dst_data['code'] = solar_json_in['code']
    if 'msg' in solar_json_in:
        dst_data['msg'] = solar_json_in['msg']
    if 'data' in solar_json_in:
        solar_data = OrderedDict()
        if 'id' in solar_json_in['data']:
            solar_data['id'] = solar_json_in['data']['id']
        if 'dataTimestamp' in solar_json_in['data']:
            solar_data['dataTimestamp'] = solar_json_in['data']['dataTimestamp']
        if 'pac' in solar_json_in['data']:
            solar_data['pac'] = solar_json_in['data']['pac']
        if 'pacStr' in solar_json_in['data']:
            solar_data['pacStr'] = solar_json_in['data']['pacStr']
        if 'batteryCapacitySoc' in solar_json_in['data']:
            solar_data['batteryCapacitySoc'] = solar_json_in['data']['batteryCapacitySoc']
        if 'batteryPower' in solar_json_in['data']:
            solar_data['batteryPower'] = solar_json_in['data']['batteryPower']
        if 'batteryPowerStr' in solar_json_in['data']:
            solar_data['batteryPowerStr'] = solar_json_in['data']['batteryPowerStr']
        if 'storageBatteryCurrent' in solar_json_in['data']:
            solar_data['storageBatteryCurrent'] = solar_json_in['data']['storageBatteryCurrent']
        if 'psum' in solar_json_in['data']:
            solar_data['psum'] = solar_json_in['data']['psum']
        if 'psumStr' in solar_json_in['data']:
            solar_data['psumStr'] = solar_json_in['data']['psumStr']
        if 'familyLoadPower' in solar_json_in['data']:
            solar_data['familyLoadPower'] = solar_json_in['data']['familyLoadPower']
        if 'familyLoadPowerStr' in solar_json_in['data']:
            solar_data['familyLoadPowerStr'] = solar_json_in['data']['familyLoadPowerStr']
        if 'eToday' in solar_json_in['data']:
            solar_data['eToday'] = solar_json_in['data']['eToday']
        if 'eTodayStr' in solar_json_in['data']:
            solar_data['eTodayStr'] = solar_json_in['data']['eTodayStr']

        dst_data['data'] = solar_data

    return json.dumps(dst_data)

def download_solar_readings():
    # Provided by Solis Support
    KeyId = "1111111111111111111"
    secretKey = b'22222222222222222222222222222222'

    VERB="POST"

    try:
        now = datetime.now(timezone.utc)
        Date = now.strftime("%a, %d %b %Y %H:%M:%S GMT")

        CanonicalizedResource = "/v1/api/inveterDetail"
        Body='{"id":"9999999999999999999","sn":"0000000000000000"}' # userId = id number from the url bar of your inverter detail page; sn = the serial number of your inverter

        Content_MD5 = base64.b64encode(hashlib.md5(Body.encode('utf-8')).digest()).decode('utf-8')
        Content_Type = "application/json"

        encryptStr = (VERB + "\n"
            + Content_MD5 + "\n"
            + Content_Type + "\n"
            + Date + "\n"
            + CanonicalizedResource)

        h = hmac.new(secretKey, msg=encryptStr.encode('utf-8'), digestmod=hashlib.sha1)

        Sign = base64.b64encode(h.digest())

        Authorization = "API " + KeyId + ":" + Sign.decode('utf-8')

        requestStr = (VERB + " " + CanonicalizedResource + "\n"
            + "Content-MD5: " + Content_MD5 + "\n"
            + "Content-Type: " + Content_Type + "\n"
            + "Date: " + Date + "\n"
            + "Authorization: "+ Authorization + "\n"
            + "Body：" + Body)

        header = { "Content-MD5":Content_MD5,
                    "Content-Type":Content_Type,
                    "Date":Date,
                    "Authorization":Authorization
                    }

        url = 'https://www.soliscloud.com:13333'
        req = url + CanonicalizedResource
        x = requests.post(req, data=Body, headers=header)
        if x.status_code == requests.codes.ok:
            solar_data = x.json()
            if solar_data['success']:
                # fetch timestamp of the last reading
                dataTimestamp = float(solar_data['data']['dataTimestamp']) / 1000
                solar_timestamp = datetime.utcfromtimestamp(dataTimestamp)
                # check the data was updated in the last 15 minutes
                # if the logger goes offline, we still continue to receive
                # packets but old data, as such don't keep broadcasting it
                delta = (datetime.utcnow()-solar_timestamp).total_seconds()
                if delta<15*60:
                    return solar_data
                else:
                    syslog.syslog(syslog.LOG_WARNING,"Stale data from logger")
                    return None
            else:
                syslog.syslog(syslog.LOG_WARNING,"Non success status from solar data")
                return None
        else:
            syslog.syslog(syslog.LOG_WARNING,"Request failed: " + str(x.status_code))
            return None
    except:
        syslog.syslog(syslog.LOG_ERR,"Caught exception requesting solar data")
        return None
    
# create broadcast capable socket    
sfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sfd.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

syslog.openlog("solis-broadcast")
syslog.syslog(syslog.LOG_INFO,"Starting processing loop...")
bcount = 0
data = download_solar_readings()
min_data = create_minimal_json(data)
data = json.dumps(data)

while True:
    # fetch new readings every 5 minutes, broadcast every 20s
    if bcount==15:
        syslog.syslog(syslog.LOG_INFO,"Fetch new readings")
        data = download_solar_readings()
        if data!=None:
            min_data = create_minimal_json(data)
            data = str(data)
        bcount = 0
    else:
        bcount+=1
    if data!=None:
        try:
            sfd.sendto(bytes(min_data,"utf-8"), ('255.255.255.255', 52005) )
        except socket.error:
            continue
    time.sleep(20)
    
