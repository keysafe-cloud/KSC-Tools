# Copyright 2025-2026 (c) KeySafe-Cloud, all rights reserved.
# SPDX-License-Identifier: MIT

"""
Helper module for interacting with the KeySafe-Cloud (KSC) API.
"""

import logging
import sys

import requests


# constants
BASE_URL = "https://keysafe-cloud.appspot.com/api/v1"
API_KEY_LENGTH = 32


# configure logging
logger = logging.getLogger(__name__)


def get_headers(api_key: str, script_version: str) -> dict:
    """
    Create HTTP headers to use when making requests to the KSC API.

    :param api_key: the API Key to be included in the request
    :param script_version: the name/version of the calling script
    :return: dictionary to be used as headers when making API requests
    """
    tenant_api_key = api_key.strip()
    if len(tenant_api_key) != API_KEY_LENGTH:
        logger.warning("Unexpected length of API Key, please adjust!")
        sys.exit(1)
    # identify the script and the requests library used
    requests_version = f"python-requests/{requests.__version__}"
    return {
        "X-Api-Key": tenant_api_key.strip(),
        "Accept-Encoding": "gzip,deflate",
        "Content-Type": "application/json",
        "User-Agent": f"{script_version}; {requests_version}; gzip",
    }


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
