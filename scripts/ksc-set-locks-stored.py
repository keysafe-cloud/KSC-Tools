#!/usr/bin/env python
# Copyright 2018-2026 (c) KeySafe-Cloud, all rights reserved.
# SPDX-License-Identifier: MIT

"""
Script to set tenant locks from 'active' to 'stored' lock status.

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
import datetime
import logging
import os
import sys

import requests
from dotenv import load_dotenv

from utils import obfuscate, yn_choice


VERSION = "1.2.2"
BASE_URL = "https://keysafe-cloud.appspot.com/api/v1"
CRITERIA_LOCK_STATUS = ["active"]
API_KEY_LENGTH = 32

# load environment variables from .env file
load_dotenv()
# =============================================================================
# NOTE: Instead of setting API Keys within scripts, it is strongly recommended
#       to keep the TENANT_API_KEY safe / secure within a local `.env` file.
#
#       Make sure the `.env` is excluded from source code control, for example
#       by using a `.gitignore` entry to exclude the `.env` file.
#
#       It is possible to override this `.env` value with on the command-line
#       using the `--api_key` parameter.
TENANT_API_KEY = os.environ.get("TENANT_API_KEY")
# =============================================================================

# configure logging
logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


def get_locks_url(limit: int = 0) -> str:
    """
    Create query Uniform Resource Locator (URL) to obtain locks.

    :param limit: maximum number of entries in one batch when requesting list
    :return: string URL to be used when making API request for locks
    """
    url = BASE_URL.strip().rstrip("/") + "/locks"
    if limit:
        prefix = "&" if ("?" in url) else "?"
        url = f"{url}{prefix}limit={limit}"
    return url


def get_headers(api_key: str) -> dict:
    """
    Create HTTP headers to use when making requests to the KSC API.

    :param api_key: the API Key to be included in the request
    :return: dictionary to be used as headers when making API requests
    """
    tenant_api_key = api_key.strip()
    if len(tenant_api_key) != API_KEY_LENGTH:
        logger.warning("Unexpected length of API Key, please adjust!")
        sys.exit(1)
    # identify the script and the requests library used
    script_ver = f"list-tenant-locks/{VERSION}"
    requests_ver = f"python-requests/{requests.__version__}"
    return {
        "X-Api-Key": tenant_api_key.strip(),
        "Accept-Encoding": "gzip,deflate",
        "Content-Type": "application/json",
        "User-Agent": f"{script_ver}; {requests_ver}; gzip",
    }


def get_locks(url: str, headers: dict) -> tuple[int, list[dict]]:
    """
    Request all locks for tenant inventory (associated with API key in headers).

    Handles any batch processing as required via URL (see "List all locks").

    :param url: the URL to be used in the HTTP request
    :param headers: headers to be used in HTTP request
    :return: number of requests executed and list of all locks in tenant inventory (if any)
    """
    r_count = 0
    data = None
    lst = []
    while url:
        r_count += 1
        try:
            logger.debug(f"HTTP Request URL: {url}")
            r = requests.get(url, headers=headers, json=data, timeout=10)
        except requests.exceptions.ConnectionError:
            logger.exception("Connection error.")
            sys.exit(1)
        try:
            r_data = r.json()
            # obtain url for next set of locks (if any)
            url = r_data.get("next_url", "")
            # get the lock(s) from result (if any)
            result = r_data.get("result", [])
            if isinstance(result, dict):
                lst.append(result)
            else:
                lst.extend(result)
        except requests.exceptions.RequestException:
            logger.exception("Request exception.")
            if r and r.text:
                logger.debug(r.text)
            sys.exit(1)
    return r_count, lst


def filter_locks(locks: list[dict], lock_status: list[str]) -> list[dict]:
    """
    Filter a list of locks based on given lock_status criteria (as a list).

    :param locks: list of dicts as lock records
    :param lock_status: list of lock_status strings to use as filter
    :return: list of locks having their status in the given lock_status list
    """
    lst = []
    if not isinstance(lock_status, list):
        logger.warning("Unexpected lock_status criteria.")
        return []
    for lock in locks:
        if not isinstance(lock, dict):
            logger.warning("Unexpected entry in locks while filtering.")
        # check for lock to match criteria
        if lock.get("lock_status", "") in lock_status:
            lst.append(lock)
    return lst


def set_lock_stored(lock_id: str, headers: dict) -> None:
    """
    Try to set the lock_status of the lock with lock_id to 'stored'.

    Errors/warnings are ignored (though verbose logging will show results)
    as it is possible that the lock_status was changed by another process.

    :param lock_id: identifier (as string) of the lock to be set to stored
    :param headers: headers to be used in HTTP request
    """
    url = BASE_URL.strip().rstrip("/") + f"/locks/{lock_id}/status"
    data = {
        "lock_status": "stored",
    }
    r = requests.put(url, headers=headers, json=data, timeout=10)
    try:
        r_data = r.json()
        logger.debug(r_data)
    except requests.exceptions.RequestException:
        logger.exception("Request exception.")
        if r and r.text:
            logger.warning(r.text)


def set_locks_stored(locks: list[dict], headers: dict) -> int:
    """
    Process a list of locks by setting their lock_status to 'stored'.

    Errors/warnings are ignored (though verbose logging will show results)
    as it is possible that the lock_status was changed by another process.

    :param locks: list of dicts as lock records
    :param headers: headers to be used in HTTP request
    :return: number of requests executed
    """
    r_count = 0
    for lock in locks:
        if not isinstance(lock, dict):
            logger.warning("Unexpected entry in locks while processing.")
        lock_id = str(lock.get("id", ""))
        if lock_id:
            r_count += 1
            set_lock_stored(lock_id, headers)
    return r_count


if __name__ == "__main__":
    dt_now = datetime.datetime.now(datetime.UTC).astimezone()
    # configure command-line parsing
    parser = argparse.ArgumentParser(description="Set locks from 'active' to 'stored' status.")
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose output")
    parser.add_argument(
        "--api_key",
        default=TENANT_API_KEY,
        help="API Key for the tenant inventory "
        "(default: TENANT_API_KEY constant as specified in .env file)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500,
        help="limit number of resulting records per request if needed "
        "(default=500; use 0 for server default, -1 for no-limit)",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="proceed with processing automatically, no questions asked",
    )

    # parse command-line arguments
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # prepare API calls
    logger.info("Determine initial URL to be used for query.")
    url = get_locks_url(args.limit or 0)
    logger.info("Determine headers to be used for all requests.")
    if args.api_key:
        logger.debug(f"Using the API Key: {obfuscate(args.api_key)}")
    else:
        logger.error("No TENANT_API_KEY set in .env file or provided via arguments!")
        sys.exit(1)
    headers = get_headers(args.api_key)
    _headers = headers.copy()
    if _headers:
        # protect the TENANT_API_KEY by obfuscating it in the logs
        _headers["X-Api-Key"] = obfuscate(args.api_key)
        logger.debug(f"HTTP Request Headers: {_headers}")

    # obtain tenant inventory using "List all locks"
    logger.info("-" * 60)
    logger.info("Get all locks for tenant based on API Key...")
    r_count_lst, all_locks = get_locks(url, headers)
    logger.info(f"# of all locks in tenant inventory: {len(all_locks)}")
    logger.info(f"Obtained with {r_count_lst} non-eKey API requests.")
    logger.info("-" * 60)
    logger.debug(all_locks)

    logger.info("Filter locks to be processed...")
    lock_status = CRITERIA_LOCK_STATUS
    locks = filter_locks(all_locks, lock_status)
    logger.info(f"# of locks that are {lock_status}: {len(locks)}")

    # processing; if any, and only when (pre-)approved
    r_count_set = 0
    if locks:
        # set filtered locks to stored (but only when approved)
        msg = f"Proceed with setting {len(locks)} locks to 'stored'?"
        if args.yes or yn_choice(msg, default="n"):
            logger.info("Approved, processing the filtered locks...")
            r_count_set = set_locks_stored(locks, headers)
        else:
            logger.warning("Aborted, no changes have been made.")
    else:
        logger.info("No changes (as no locks qualified for processing).")
    r_count_total = r_count_lst + r_count_set
    logger.info(f"Done, with {r_count_total} non-eKey API requests.")
