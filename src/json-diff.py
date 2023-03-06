import requests
import traceback
from datetime import datetime
import os
from urllib.parse import urlparse
import time
import logging
import json
from slack import SlackNotification

time.sleep(30)

domain = urlparse(os.getenv('RW_MONITOR')).netloc
scan_path = os.getenv('RW_DB_PATH') + domain
full_path = scan_path + '/' + domain + '.json'
log_path = scan_path + '/' + 'log.txt'

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
    else:
        logger.info(f'Public IP address: {r.text}')
except:
    logger.warning('The web service for public IP fetch is down')

try:
    os.mkdir(scan_path)
    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    init = requests.get(os.getenv('RW_MONITOR'), timeout=30).json()
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
    new = requests.get(os.getenv('RW_MONITOR'), timeout=30).json()
except:
    logger.error('JSON retrieving failed')
    tb = traceback.format_exc()
    SlackNotification.send_error_notification(os.getenv('RW_SLACK'), tb.strip(), os.getenv('RW_MONITOR'))
    logger.error(tb.strip())
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

    if SlackNotification.send_notification(os.getenv('RW_SLACK'), diffs, os.getenv('RW_MONITOR')):
        logger.info('SLACK NOTIFICATION SENT!')
    else:
        logger.error('SLACK NOTIFICATION FAIL!')
