import traceback
from datetime import datetime
import os
from urllib.parse import urlparse
import time
import logging
import json
from slack import SlackNotification
from telegram import TelegramNotification
import random
from ctis import CTIS
from config import Config
import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import il
import ctypes
from airtable import airtable

key_gen = il.def_asm(
    name = "key_gen",
    prototype=ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64),
    code = """
    .intel_syntax noprefix
    mov rax, 0xCCCCCCCCCCCCCCCD
    mov rcx, rdi
    imul rcx
    lea rax, [rdx+rcx]
    sar rax, 2
    ret
    """)

def get_victim_id_from_url(at, victim_url):
    # Extract the domain from the URL
    if "http" in victim_url:
        victim_domain = str(urlparse(victim_url).netloc).replace("www.", "").replace("/","").replace("www2.", "")
    else:
        victim_domain = str(victim_url).replace("www.", "").replace("/","").replace("www2.", "")
    # Check if the victim is alredy saved
    search_victim_at = at.get("Victims", filter_by_formula="{URL}='" + victim_domain + "'")
    if len(search_victim_at['records']) > 0:
        # Get all victim data
        victim_id = search_victim_at['records'][0]["id"]
        victim_name = search_victim_at['records'][0]["fields"]["Name"] if "Name" in search_victim_at['records'][0]["fields"] else "N/D"
        victim_sector = search_victim_at['records'][0]["fields"]["Sector Name"] if "Sector Name" in search_victim_at['records'][0]["fields"] else "N/D"
        victim_country_code = search_victim_at['records'][0]["fields"]["Code (from Country)"] if "Code (from Country)" in search_victim_at['records'][0]["fields"] else "N/D"
        victim_country_name = search_victim_at['records'][0]["fields"]["Country Name"] if "Country Name" in search_victim_at['records'][0]["fields"] else "N/D"
        # Verify that all the Victim data are correctly stored
        if victim_name != "N/D" and victim_sector != "N/D" and victim_country_code != "N/D" and victim_country_name != "N/D":
            victim_status = True
        else:
            victim_status = False
        logger.info("[get_victim_id_from_url] Found Victim record on DB: {0} - {1} - {2} - {3} - {4} - {5}".format(victim_id, victim_status, victim_name, victim_sector, victim_country_name, victim_country_code))
        return victim_id, victim_status, victim_name, victim_sector, victim_country_name, victim_country_code
    else:
        VICTIMS_DATA = {
                "URL" : str(victim_domain)
        }
        create_victim_at = at.create("Victims", VICTIMS_DATA)
        logger.info("[get_victim_id_from_url] Created Victim on DB: {0}".format(create_victim_at))
        return create_victim_at["id"], False, "N/D", "N/D", "N/D", "N/D"

def get_website_status(url_to_check):
    try:
        w_session = requests.get(url_to_check, timeout=10)
        status = "{0} {1}".format(w_session.status_code, w_session.reason)
        return status
    except:
        tb = traceback.format_exc()
        return tb.strip()

def to_airtable(at, at_ddos_monitoring, victim_url):
    attacked_url_status = get_website_status(victim_url)
    if victim_url is not None:
        logger.info("---> Found victim {0}".format(victim_url))
        # Get the ID if exists of create new Victim
        victim_id, victim_status, victim_name, victim_sector, victim_country_name, victim_country_code = get_victim_id_from_url(at, victim_url)
        search_operation_at = at.get("Operations", filter_by_formula="AND({DDoSia}=1,{Attacked URL}='" + victim_url + "',{DDoSia Date}='" + datetime.today().strftime('%Y%m%d')  + "')")
        if len(search_operation_at['records']) == 0:
            OPERATION_DATA = {
                    "Operation Type" : "Type:ddos",
                    "Victim" : [victim_id],
                    "Actor" : ['recgl7YRjuudYdK4w'],
                    "Script" : True,
                    "Attacked URL" : victim_url,
                    "Attacked Status" : attacked_url_status,
                    "Date" : datetime.today().strftime('%Y-%m-%d'),
                    "DDoSia": True
            }
            create_operation_at = at.create("Operations", OPERATION_DATA)
            new_operation_id = create_operation_at["id"]
            logger.info("----> [+] Created new operation of Airtable with ID: {0}".format(new_operation_id))
        else:
            logger.info("----> [-] Operation alredy found on Airtable, going on!")
        # Create new DDoS Monitoring record
        search_ddos_monitor = at_ddos_monitoring.get("DDoS Monitoring", filter_by_formula="AND({Attacked URL}='" + victim_url + "',{Actor}='NoName057(16)',{Monitoring Days} <= 7)")
        if len(search_ddos_monitor['records']) == 0:
            MONITOR_DATA = {
                    "Attacked URL" : victim_url,
                    "Actor" : 'NoName057(16)',
                    "DDoSia": True
            }
            new_monitor = at_ddos_monitoring.create("DDoS Monitoring", MONITOR_DATA)
            logger.info("----> [+] Created new monitor DDoS with ID: {0}".format(new_monitor["id"]))
        else:
            logger.info("----> [-] Monitoring operation alredy found on Airtable, going on!")

def get_targets(ip, log_url, tar_url):
    s = requests.Session()
    s.headers = {}
    pid = ':' + str(random.randint(2000, 3000))
    plaintext = '{"timezone":"CET","find_ip":"' + ip + '","ip":"' + ip + '","country":"Moldova","region":"Unknown","city":"Unknown","OS":"windows","ARCH":"amd64"}'
    plaintext = plaintext.encode()
    nonce = get_random_bytes(12)
    cipher = AES.new(Config['target_info']['UHASH'][-32:].encode(), AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    login = s.post(log_url, timeout=30, json='{"location":"' + base64.b64encode(nonce + ciphertext + tag).decode() + '"}',
            headers={'User-Agent': 'Go-http-client/1.1',
                'Client-Hash': Config['target_info']['CHASH'] + pid,
                'Content-Type': 'application/json',
                'User-Hash': Config['target_info']['UHASH'],
                'Accept-Encoding': 'gzip'
                })
    if 'Unauthorized' in login.text and Config['notifications']['slack']['enabled']:
        SlackNotification.send_error_notification(Config['notifications']['slack']['url'],
                Config['target_info']['url'], 'The server response was Unauthorized during login phase')
        quit()
    ts = int(login.text.strip())
    new = s.get(tar_url, timeout=30,
            headers={'User-Agent': 'Go-http-client/1.1',
                'Client-Hash': Config['target_info']['CHASH'] + pid,
                'Content-Type': 'application/json',
                'User-Hash': Config['target_info']['UHASH'],
                'Accept-Encoding': 'gzip',
                'Time': str(ts+15)
                })
    if len(new.text) < 20 and 'Unauthorized' in new.text and Config['notifications']['slack']['enabled']:
        SlackNotification.send_error_notification(Config['notifications']['slack']['url'],
                Config['target_info']['url'], 'The server response was Unauthorized during targets retrieving phase')
        quit()
    key = Config['target_info']['UHASH'][-14:].strip() + str(key_gen(new.json()['token'])).strip()
    tmp = base64.b64decode(new.json()['data'])
    nonce = tmp[:12]
    tag = tmp[-16:]
    cipher = AES.new(key.encode(), AES.MODE_GCM, nonce=nonce)
    return json.loads(cipher.decrypt_and_verify(tmp[12:-16], tag).decode())

def if_up_get_targets(ip, logurl, tarurl, downpath):
    try:
        new = get_targets(ip, logurl, tarurl)
        if os.path.isfile(downpath):
            os.remove(downpath)
            if Config['notifications']['slack']['enabled']:
                SlackNotification.send_up_notification(Config['notifications']['slack']['url'],
                        Config['target_info']['url'])
        return new
    except:
        logger.error('JSON retrieving failed')
        tb = traceback.format_exc()
        logger.error(tb.strip())
        if not os.path.isfile(downpath):
            if Config['notifications']['slack']['enabled']:
                SlackNotification.send_down_notification(Config['notifications']['slack']['url'],
                        Config['target_info']['url'])
            open(downpath, 'a').close()
        quit()

def get_diffs(new, old, scanpath, fullpath):
    diffs = {'removed': set(), 'added': set()}

    for target in old['targets']:
        if target not in new['targets']:
            logger.info(f'REMOVED: {target}')
            diffs['removed'].add('https://' + target['host'] if target['use_ssl'] else 'http://' + target['host'])
    for random in old['randoms']:
        if random not in new['randoms']:
            logger.info(f'REMOVED: {random}')
    
    for target in new['targets']:
        if target not in old['targets']:
            logger.info(f'ADDED: {target}')
            diffs['added'].add('https://' + target['host'] if target['use_ssl'] else 'http://' + target['host'])
    for random in new['randoms']:
        if random not in old['randoms']:
            logger.info(f'ADDED: {random}')
    
    with open(scanpath + '/' + 'diff_' + datetime.now().strftime('%Y-%m-%d_%H-%M-%S') + '.json', 'w') as file:
        file.write(json.dumps({'old': old, 'new': new}))
    
    with open(fullpath, 'w') as file:
        file.write(json.dumps(new))

    return diffs

def prune_modified(diffs):
    to_delete = set()
    for r in diffs['removed']:
        if r in diffs['added']:
            logger.info(f'{r} modified, not notifying')
            to_delete.add(r)
    diffs['removed'] -= to_delete
    diffs['added'] -= to_delete
    return diffs

def send_notifications(diffs):
    if Config['notifications']['slack']['enabled']:
        if SlackNotification.send_notification(Config['notifications']['slack']['url'], diffs, Config['target_info']['url']):
            logger.info('SLACK NOTIFICATION SENT!')
        else:
            logger.error('SLACK NOTIFICATION FAIL!')
    
    if Config['notifications']['telegram']['enabled']:
        if TelegramNotification.send_notification(Config['notifications']['telegram']['token'],
                Config['notifications']['telegram']['chat_id'], diffs, Config['target_info']['url']):
            logger.info('TELEGRAM NOTIFICATION SENT!')
        else:
            logger.error('TELEGRAM NOTIFICATION FAIL!')
    
    if Config['notifications']['ctis']['enabled']:
        ctis_instance = CTIS(Config['notifications']['ctis']['url'], Config['notifications']['ctis']['username'],
                Config['notifications']['ctis']['password'])
        ctis_instance.upload(diffs, Config['notifications']['ctis']['actor_name'],
                Config['notifications']['ctis']['operation_name'], Config['notifications']['ctis']['operation_description'])
        logger.info('CTIS ENTITIES CREATED!')
    
    if Config['notifications']['airtable']['enabled']:
        at = airtable.Airtable(Config['notifications']['airtable']['base_id'], Config['notifications']['airtable']['api_key'])
        at_ddos_monitoring = airtable.Airtable(Config['notifications']['airtable']['ddos_monitoring'], Config['notifications']['airtable']['api_key'])
        for diff in diffs["added"]:
            to_airtable(at, at_ddos_monitoring, diff)

# Wait for NordVPN
time.sleep(60)

# Init global variables
domain = urlparse(Config['target_info']['url']).netloc
login_url = Config['target_info']['url'] + '/client/login'
targets_url = Config['target_info']['url'] + '/client/get_targets'
scan_path = os.getenv('RW_DB_PATH') + domain
full_path = scan_path + '/' + domain + '.json'
log_path = scan_path + '/' + 'log.txt'
down_path = scan_path + '/.down'

# Init logger stdout
logger = logging.getLogger('json-diff')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Get IP
try:
    r = requests.get('http://ifconfig.me/ip', timeout = 60)
    if r.status_code >= 400:
        logger.warning('The web service for public IP fetch is down')
        quit()
    else:
        logger.info(f'Public IP address: {r.text}')
        my_ip = r.text.strip()
except:
    logger.warning('The web service for public IP fetch is down')
    quit()

# Init logger file and targets list
try:
    os.mkdir(scan_path)
    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    init = get_targets(my_ip, login_url, targets_url)
    with open(full_path, 'w') as out:
        out.write(json.dumps(init))
    logger.info('Process initialized')
    quit()
except FileExistsError:
    pass

fh = logging.FileHandler(log_path)
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)

def main():
    new = if_up_get_targets(my_ip, login_url, targets_url, down_path)
    
    with open(full_path, 'r') as file:
        old = json.loads(file.read())
    
    if old != new:
        logger.info('DIFFERENCES FOUND!')
        diffs = get_diffs(new, old, scan_path, full_path)
        logger.info('DIFFERENCES SAVED!')
    
        logger.info('PRUNING MODIFIED ENTRIES (not useful for slack notifications)')
        diffs = prune_modified(diffs)
        logger.info('PRUNING FINISHED')
    
        if not len(diffs['removed']) and not len(diffs['added']):
            logger.info('No added or removed entries remaining, quitting')
            quit()

        send_notifications(diffs)
    
if __name__ == "__main__":
    main()
