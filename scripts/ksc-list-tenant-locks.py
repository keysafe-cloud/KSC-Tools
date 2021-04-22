#!/usr/bin/env python
# coding=utf-8

"""
Script to help list all locks in the tenant inventory, with the output
either in JSON format or in CSV format (for specified fields).

It gets all locks of the tenant based on the KSC API Access Key provided.

NOTE: It is recommended to provide the KSC API Access Key via command-line
      parameters (rather than changing 'SECRET' in a copy of this script).
      Please protect your API Key as described in the API documentation.

This script requires `requests` (see https://pypi.org/project/requests/)
to be installed, use `pip install -r requirements.txt` to install.

Copyright 2019-2021 (c) KeySafe-Cloud, all rights reserved.
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

VERSION = '1.0.1'
BASE_URL = 'https://keysafe-cloud.appspot.com/api/v1'


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
    if '?' in url:
      url = url + '&limit={}'.format(args.limit)
    else:
      url = url + '?limit={}'.format(args.limit)
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
  script_ver = 'list-tenant-locks/{}'.format(VERSION)
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


if __name__ == '__main__':
  logging.getLogger().addHandler(logging.StreamHandler())
  logging.getLogger().setLevel(logging.INFO)

  # configure command-line parsing
  parser = argparse.ArgumentParser(
    description="List all locks in the tenant inventory.")
  parser.add_argument(
    '--verbose', '-v',
    action='store_true',
    help='verbose logging output')
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
    '--format', '--fmt',
    type=str, default='json',
    help='provide result in specified format (default "json" for JSON output); '
         'for example: "id,lock_uid,lock_status" would allow CSV output)')
  parser.add_argument(
    '--out',
    help='write result to specified filename')
  parser.add_argument(
    '--show',
    action='store_true',
    help='show result')

  # parse command-line arguments
  args = parser.parse_args()
  if args.verbose:
    logging.getLogger().setLevel(logging.DEBUG)

  # prepare API calls
  logging.info("Determine URL to be used for query.")
  url = get_locks_url(args.limit or 0)
  logging.info("Determine headers to be used for all requests.")
  headers = get_headers(args.api_key)

  # obtain tenant inventory using "List all locks"
  logging.info("Get all locks for tenant based on API Key...")
  r_count_lst, all_locks = get_locks(url, headers)
  logging.info("# of all locks in tenant inventory: {}".format(len(all_locks)))
  logging.info('Obtained with {} non-eKey API requests.'.format(r_count_lst))

  result = ''
  flds = []
  if args.format:
    if args.format.lower() == 'json':
      logging.info("Convert result into JSON format...")
      result = json.dumps(all_locks, indent=2, sort_keys=True)
    else:
      logging.info("Convert result into CSV format...")
      flds = args.format.lower().split(',')
      # provide names of fields as header on first line
      lines = [';'.join(['"{}"'.format(fld) for fld in flds])]
      for rec in all_locks:
        # for each record provide field values on one line
        line = ';'.join(['"{}"'.format(rec[fld]) for fld in flds])
        lines.append(line)
      # combine all lines with record details into CSV result
      result = '\n'.join(lines)

  if args.out:
    logging.info("Export/output result to: {}".format(args.out))
    with open(args.out, 'w') as out_file:
      out_file.write(result)

  # either use command-line parameter set to show, or ask user
  if args.out:
    show = args.show
  else:
    show = args.show or yn_choice("Show result?", default='n')
  if show:
    logging.info("Result:")
    print(result)
