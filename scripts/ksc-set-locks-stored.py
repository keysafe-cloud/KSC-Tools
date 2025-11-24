# Copyright 2018-2026 (c) KeySafe-Cloud, all rights reserved.

"""
Script to help setting locks from 'active' to 'stored' lock status.

It gets all locks of the tenant based on the KSC API Access Key provided,
filters this list for locks that have the 'active' lock status; then asks
the user for approval, before setting their lock status to 'stored'.

NOTE: It is recommended to provide the KSC API Access Key via command-line
      parameters (rather than changing 'SECRET' in a copy of this script).
      Please protect your API Key as described in the API documentation.

This script requires `requests` (see https://pypi.org/project/requests/)
to be installed, use `pip install -r requirements.txt` to install.
"""


import argparse
import json
import logging
import requests
import sys


# =============================================================================
# NOTE: instead of changing this in the script, it is strongly recommended
#       to use the command-line parameter `--api_key` to keep your API Key
#       indeed secret (it will override the TENANT_API_KEY constant here);
#       for different (sub-)tenants: use a different API Key in each run
TENANT_API_KEY = 'SECRET'
# =============================================================================

VERSION = '1.0.2'
BASE_URL = 'https://keysafe-cloud.appspot.com/api/v1'
CRITERIA_LOCK_STATUS = ['active']


def yn_choice(message, default='y'):
  '''
  Helper function to handle a command-line question to proceed.
  Returns boolean True when question is confirmed via user input.
  Based on https://stackoverflow.com/a/4741730/2315612
  combined with https://stackoverflow.com/a/54712937/2315612
  '''
  choices = 'Y/n' if default.lower() in ('y', 'yes') else 'y/N'
  try:
    if sys.version_info.major == 2:
      choice = raw_input("{} ({}) ".format(message, choices))
    else:
      choice = input("{} ({}) ".format(message, choices))
  except:
    logging.error('Problem handling command-line input...')
  values = ('y', 'yes', '') if choices == 'Y/n' else ('y', 'yes')
  return choice.strip().lower() in values


def get_locks_url(limit=0):
  '''
  Create query Uniform Resource Locator (URL) to obtain locks.
  Returns a string URL to be used when making API request for locks.
  '''
  url = BASE_URL.strip().rstrip('/') + '/locks'
  if limit:
    prefix = '&' if ('?' in url) else '?'
    url = '{0}{1}limit={2}'.format(url, prefix, limit)
  return url


def get_headers(api_key):
  '''
  Create headers to use when making requests to the KSC API.
  Returns a dictionary to be used as headers when making API requests.
  '''
  tenant_api_key = api_key.strip()
  if len(tenant_api_key) != 32:
    logging.warning('Unexpected length of API Key, please adjust !!!')
  # identify the script and the requests library used
  script_ver = 'locks2stored/{}'.format(VERSION)
  requests_ver = 'python-requests/{}'.format(requests.__version__)
  headers = {
    'X-Api-Key': tenant_api_key.strip(),
    'Accept-Encoding': 'gzip,deflate',
    'Content-Type': 'application/json',
    'User-Agent': '{}; {}; gzip'.format(script_ver, requests_ver),
  }
  return headers


def get_locks(url, headers):
  '''
  Request all locks for tenant inventory (associated with API key in headers),
  handling any batch processing as required via URL (see "List all locks").
  Returns number of requests executed and a list of all locks in the tenant
  inventory (if any).
  '''
  r_count = 0
  data = None
  lst = []
  while url:
    r_count += 1
    r = requests.get(url, headers=headers, json=data)
    try:
      r_data = r.json()
      # obtain url for next set of locks (if any)
      url = r_data.get('next_url', '')
      # get the lock(s) from result (if any)
      result = r_data.get('result', [])
      if isinstance(result, dict):
        lst.append(result)
      else:
        lst.extend(result)
    except:
      logging.warning(r.text)
      url = ''
  return r_count, lst


def filter_locks(locks, lock_status=[]):
  '''
  Filter a list of locks based on given lock_status criteria (as a list).
  Returns a list of locks having their status in the given lock_status list.
  '''
  lst = []
  if not isinstance(lock_status, list):
    logging.warning('Unexpected lock_status criteria')
    return []
  for lock in locks:
    if not isinstance(lock, dict):
      logging.warning('Unexpected entry in locks while filtering')
    # check for lock to match criteria
    if lock.get('lock_status', '') in lock_status:
      lst.append(lock)
  return lst


def set_lock_stored(lock_id, headers):
  '''
  Try to set the lock_status of the lock with lock_id to 'stored'.
  Errors/warnings are ignored (though verbose logging will show results)
  as it is possible that the lock_status was changed by another process.
  '''
  url = BASE_URL.strip().rstrip('/') + '/locks/{}/status'.format(lock_id)
  data = {
    'lock_status': 'stored',
  }
  r = requests.put(url, headers=headers, json=data)
  try:
    r_data = r.json()
  except:
    logging.warning(r.text)


def set_locks_stored(locks, headers):
  '''
  Process a list of locks by setting their lock_status to 'stored'.
  Returns number of requests executed.
  Errors/warnings are ignored (though verbose logging will show results)
  as it is possible that the lock_status was changed by another process.
  '''
  r_count = 0
  for lock in locks:
    if not isinstance(lock, dict):
      logging.warning('Unexpected entry in locks while processing')
    lock_id = lock.get('id', '')
    if lock_id:
      r_count += 1
      set_lock_stored(lock_id, headers)
  return r_count


if __name__ == '__main__':
  logging.getLogger().addHandler(logging.StreamHandler())
  logging.getLogger().setLevel(logging.INFO)

  # configure command-line parsing
  parser = argparse.ArgumentParser(
    description="Set locks from 'active' to 'stored' status.")
  parser.add_argument(
    '--api_key',
    default=TENANT_API_KEY,
    help='API Key for the tenant inventory '
         '(default: TENANT_API_KEY constant as specified in script)')
  parser.add_argument(
    '--limit',
    type=int, default=500,
    help='limit number of resulting records per request if needed '
         '(default=500; use 0 for server default, -1 for no-limit)')
  parser.add_argument(
    '--yes', '-y',
    action='store_true',
    help='proceed with processing automatically, no questions asked')
  parser.add_argument(
    '--verbose', '-v',
    action='store_true',
    help='verbose logging output')

  # parse command-line arguments
  args = parser.parse_args()
  if args.verbose:
    logging.getLogger().setLevel(logging.DEBUG)

  # prepare processing
  logging.info("Determine URL to be used for query.")
  url = get_locks_url(args.limit or 0)
  logging.info("Determine headers to be used for all requests.")
  headers = get_headers(args.api_key)
  logging.info("Get all locks for tenant based on API Key...")
  r_count_lst, all_locks = get_locks(url, headers)
  logging.info("# of all locks in tenant inventory: {}".format(len(all_locks)))
  logging.info("Filter locks to be processed...")
  lock_status = CRITERIA_LOCK_STATUS
  locks = filter_locks(all_locks, lock_status)
  logging.info("# of locks that are {}: {}".format(lock_status, len(locks)))

  # processing; if any, and only when (pre-)approved
  r_count_set = 0
  if locks:
    # set filtered locks to stored (but only when approved)
    msg = "Proceed with setting {} locks to 'stored'?".format(len(locks))
    if args.yes or yn_choice(msg, default='n'):
      logging.info('Approved, processing the filtered locks...')
      r_count_set = set_locks_stored(locks, headers)
    else:
      logging.warning('Aborted, no changes have been made.')
  else:
    logging.info('No changes (as no locks qualified for processing).')
  r_count_total = r_count_lst + r_count_set
  logging.info('Done, with {} non-eKey API requests.'.format(r_count_total))
