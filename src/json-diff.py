import requests
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
from datetime import date

def get_targets(ip, log_url, tar_url):
    s = requests.Session()
    s.headers = {}
    pid = ':' + str(random.randint(2000, 3000))
    login = s.post(log_url, timeout=30, json='{"location":{"timezone":"CET","find_ip":"' + ip + '","ip":"' + ip + '","country":"Moldova","region":"Unknown","city":"Unknown","OS":"windows","ARCH":"amd64"}}',
            headers={'User-Agent': 'Go-http-client/1.1',
                'Client-Hash': os.getenv('CHASH') + pid,
                'Content-Type': 'application/json',
                'User-Hash': os.getenv('UHASH'),
                'Accept-Encoding': 'gzip'
                })
    if 'Unauthorized' in login.text:
        SlackNotification.send_error_notification(os.getenv('SLACK'), os.getenv('MONITOR'), 'The server response was Unauthorized during login phase')
        quit()
    ts = int(login.text.strip())
    new = s.get(tar_url, timeout=30,
            headers={'User-Agent': 'Go-http-client/1.1',
                'Client-Hash': os.getenv('CHASH') + pid,
                'Content-Type': 'application/json',
                'User-Hash': os.getenv('UHASH'),
                'Accept-Encoding': 'gzip',
                'Time': str(ts+15)
                })
    if len(new.text) < 20 and 'Unauthorized' in new.text:
        SlackNotification.send_error_notification(os.getenv('SLACK'), os.getenv('MONITOR'), 'The server response was Unauthorized during targets retrieving phase')
        quit()
    return new.json()['data']

time.sleep(60)

domain = urlparse(os.getenv('MONITOR')).netloc
login_url = os.getenv('MONITOR') + '/login'
targets_url = os.getenv('MONITOR') + '/client/get_targets'
scan_path = os.getenv('RW_DB_PATH') + domain
full_path = scan_path + '/' + domain + '.json'
log_path = scan_path + '/' + 'log.txt'
down_path = scan_path + '/.down'

logger = logging.getLogger('json-diff')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

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

try:
    new = get_targets(my_ip, login_url, targets_url)
    if os.path.isfile(down_path):
        os.remove(down_path)
        SlackNotification.send_up_notification(os.getenv('SLACK'), os.getenv('MONITOR'))
except:
    logger.error('JSON retrieving failed')
    tb = traceback.format_exc()
    logger.error(tb.strip())
    if not os.path.isfile(down_path):
        SlackNotification.send_down_notification(os.getenv('SLACK'), os.getenv('MONITOR'))
        open(down_path, 'a').close()
    quit()

with open(full_path, 'r') as file:
    old = json.loads(file.read())

if old != new:
    logger.info('DIFFERENCES FOUND!')
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

    with open(scan_path + '/' + 'diff_' + datetime.now().strftime('%Y-%m-%d_%H-%M-%S') + '.json', 'w') as file:
        file.write(json.dumps({'old': old, 'new': new}))

    with open(full_path, 'w') as file:
        file.write(json.dumps(new))
    
    logger.info('DIFFERENCES SAVED!')

    logger.info('PRUNING MODIFIED ENTRIES (not useful for slack notifications)')
    to_delete = set()
    for r in diffs['removed']:
        if r in diffs['added']:
            logger.info(f'{r} modified, not notifying')
            to_delete.add(r)
    diffs['removed'] -= to_delete
    diffs['added'] -= to_delete
    logger.info('PRUNING FINISHED')

    if not len(diffs['removed']) and not len(diffs['added']):
        logger.info('No added or removed entries remaining, quitting')
        quit()

    if SlackNotification.send_notification(os.getenv('SLACK'), diffs, os.getenv('MONITOR')):
        logger.info('SLACK NOTIFICATION SENT!')
    else:
        logger.error('SLACK NOTIFICATION FAIL!')

    if TelegramNotification.send_notification(os.getenv('TG_TOKEN'), os.getenv('TG_CHAT'), diffs, os.getenv('MONITOR')):
        logger.info('TELEGRAM NOTIFICATION SENT!')
    else:
        logger.error('TELEGRAM NOTIFICATION FAIL!')

    ctis_instance = CTIS(os.getenv('CTIS_URL'), os.getenv('CTIS_USER'), os.getenv('CTIS_PASS'))
    ok, intrusion_set = ctis_instance.add_intrusion_set(os.getenv('ACTOR_NAME'))
    if not ok:
        raise Exception("Can't create intrusion set")
    ok, operation = ctis_instance.add_operation(date.today().strftime('%Y%m%d') + ' ' + os.getenv('OPERATION_NAME'),
            os.getenv('OPERATION_DESCRIPTION'))
    if not ok:
        raise Exception("Can't create operation")
    ok, rel = ctis_instance.add_relationship('attributed-to', operation, 'x-operations', intrusion_set, 'intrusion-sets')
    if not ok:
        raise Exception("Can't create operation - intrusion-set relationship")
    for url in diffs['added']:
        ok, url_id = ctis_instance.add_url(url)
        if not ok:
            raise Exception(f"Can't create url {url}")
        ok, rel = ctis_instance.add_relationship('related-to', operation, 'x-operations', url_id, 'urls')
        if not ok:
            raise Exception(f"Can't create operation - {url} relationship")
    logger.info('CTIS ENTITIES CREATED!')
