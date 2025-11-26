#!/usr/bin/env python
# Copyright 2019-2026 (c) KeySafe-Cloud, all rights reserved.
# SPDX-License-Identifier: MIT

"""
Script to list all locks in the KSC tenant inventory.

It gets all locks in the tenant inventory based on the KSC API Access Key (aka API Key) provided.
When the amount of locks exceeds a certain limit, this script will use the next URL approach
to obtain all locks in one list. The number of HTTP requests required to do so will be shown.

Result can be exported to a file in "csv", "json", or "xlsx" format; for a CSV (comma-separated
values), JavaScript Object Notation (JSON), or Excel .xslx spreadsheet file.

The fields to include in the export can be specified, allowing easier to read output. By default,
the fields will be limited to "id,lock_uid,lock_status,reference" for a quick useful overview.

Use `pip install -r requirements.txt` to install `python-dotenv`, `requests`, and `xlsxwriter`
required libraries. Then use `python ksc-list-tenant-locks.py --help` for usage instructions.

For example, use `python ksc-list-tenant-locks.py --format=xlsx` to generate an Excel file
with all the locks and their "id,lock_uid,lock_status,reference" fields in a table. The file
created will follow a `list-locks-YYYY-mm-dd-HHMM.xlsx` snapshot at date/time pattern.

NOTE: It is recommended to set the KSC API Access Key (aka API Key) in a `.env` file or via
      command-line arguments; rather than hard-coding any 'SECRET' in a copy of this script.
      Please protect your API Key as described in the API documentation.
"""

import argparse
import copy
import datetime
import json
import logging
import os
import sys
from pathlib import Path

import requests
import xlsxwriter
from dotenv import load_dotenv
from xlsxwriter.utility import xl_col_to_name

from utils import (
    ensure_file_extension,
    obfuscate,
    unique_ordered_list,
    yn_choice,
)


VERSION = "1.2.2"
BASE_URL = "https://keysafe-cloud.appspot.com/api/v1"
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

# mapping of known fields to initial Excel .xlsx column widths
FIELD_WIDTHS = {
    "batch_code": 14,
    "bootloader_modified": 26,
    "bootloader_version": 8,
    "created": 26,  # deprecated, use batch_code
    "firmware_modified": 26,
    "firmware_version": 8,
    "hardware_model": 9,
    "hardware_version": 8,
    "id": 17,
    "key": 20,  # deprecated, use id (=lock_id)
    "lock_model": 12,
    "lock_status": 12,
    "lock_version": 5,
    "lock_uid": 21,
    "mac_address": 17,
    "modified": 26,
    "nr_of_slots": 5,
    "reference": 18,
    "software_modified": 26,
    "software_version": 8,
}
FIELDS_ARGS_DEFAULT = "id,lock_uid,lock_status,reference"
FIELDS_ARGS_VERBOSE = (
    "id,lock_uid,mac_address,lock_status,reference,lock_model,lock_version,batch_code,"
    "modified,nr_of_slots,hardware_model,hardware_version,software_version,software_modified,"
    "firmware_version,firmware_modified"
)

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
                logger.warning(r.text)
            sys.exit(1)
    return r_count, lst


def export_xlsx(fname: str, flds: list[str], data: list[dict]) -> None:
    """
    Export the result into Excel .xlsx spreadsheet format.

    :param fname: filename requested, already adjusted to format
    :param flds: list of fields requested
    :param data: list of records, already reduced to fields requested
    """
    try:
        logger.debug("Create a workbook and add 3 worksheets.")
        wb = xlsxwriter.Workbook(fname)
        ws = wb.add_worksheet()
        _ws = wb.add_worksheet()
        _ws = wb.add_worksheet()
        logger.debug("Apply text format to the whole worksheet.")
        text_format = wb.add_format({"num_format": "@"})
        ws.set_column("A:XFD", None, text_format)
        logger.debug("Set column widths for the data fields.")
        for col_nr, fld in enumerate(flds):
            col_width = FIELD_WIDTHS.get(fld, 12)
            ws.set_column(col_nr, col_nr, col_width)
        logger.debug("Prepare headers and data for the table.")
        col_headers = [{"header": fld} for fld in flds]
        data_rows = [[f"{rec.get(fld, '')}" for fld in flds] for rec in data]
        # sort lexicographically by comparing corresponding elements from left to right
        data_rows = sorted(data_rows)
        logger.debug("Add table with data to the worksheet.")
        rng_col = xl_col_to_name(len(flds) - 1)
        rng_row = len(data_rows) + 1
        xl_range = f"$A$1:${rng_col}${rng_row}"
        ws.add_table(xl_range, {"data": data_rows, "columns": col_headers})
        logger.debug("Add defined name for the data table.")
        wb.define_name("AllData", f"={ws.name}!{xl_range}")
        logger.debug("Close the workbook and save the file.")
        wb.close()
        logger.info(f"Successfully created Excel spreadsheet file: {fname}")
    except Exception:
        logger.exception("Error writing Excel .xlsx file.")


def export_data(fname: str, fmt: str, flds: list[str], data: list[dict]) -> str:
    """
    Provide output of data in the format requested, also written to fname output file if specified.

    :param fname: filename requested, already adjusted to format
    :param fmt: format requested (one of "csv", "json", or "xlsx")
    :param flds: list of fields requested
    :param data: list of records, already reduced to fields requested
    :return: string result, either data (for "csv" and "json") or a message (for "xlsx")
    """
    result = ""
    if fmt in ["csv", "json"]:
        if fmt == "csv":
            logger.info("Converting result into CSV format...")
            # provide names of fields as header on first line
            lines = [";".join([f'"{fld}"' for fld in flds])]
            for rec in data:
                # for each record provide field values on one line
                line = ";".join([f'"{rec[fld]}"' for fld in flds])
                lines.append(line)
            # combine all lines with record details into CSV result
            result = "\n".join(lines)
        if fmt == "json":
            logger.info("Converting result into JSON format...")
            result = json.dumps(data, indent=2, sort_keys=True)
        if fname:
            logger.info(f"Export/output result to: {fname}")
            with Path(fname).open("w") as out_file:
                out_file.write(result)
    if fmt == "xlsx":
        export_xlsx(fname=fname, flds=flds, data=data)
        result = f'Open the "{fname}" for the Excel spreadsheet output.'
    return result


def reduce_data(data: list[dict], flds: list[str]) -> tuple[list[dict], list[str]]:
    """
    Reduce given input data, filtering records to specified list of fields.

    :param data: input data as list of dict records
    :param flds: list of fields to keep in the return data
    :return: list of records reduced to list of fields, and effective list of fields
    """
    if not flds:
        # special case, first build flds from data itself;
        # to include all fields of all records in order encountered
        flds = []
        for rec in data:
            new_flds = [fld for fld in unique_ordered_list(list(rec.keys())) if fld not in flds]
            flds.extend(new_flds)
    # make a copy of the input data
    result = copy.deepcopy(data)
    for rec in result:
        # get hold of list of unique fields in the record
        rec_flds = set(rec.keys())
        for rec_fld in rec_flds:
            if rec_fld not in flds:
                del rec[rec_fld]
    return result, flds


if __name__ == "__main__":
    dt_now = datetime.datetime.now(datetime.UTC).astimezone()
    # configure command-line parsing
    parser = argparse.ArgumentParser(description="List all locks in the tenant inventory.")
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
        "--fields",
        "--fld",
        type=str,
        default=FIELDS_ARGS_DEFAULT,
        help="determine the fields to include in the output "
        '(default "id,lock_uid,lock_status,reference" provides a quick overview; '
        'use "-" for a verbose set of fields, use "" for all fields)',
    )
    parser.add_argument(
        "--format",
        "--fmt",
        choices=["csv", "json", "xlsx"],
        default="json",
        help='provide result in specified format (default "json" for JSON output; '
        'use "csv" for CSV output, and "xlsx" for Excel spreadsheet output)',
    )
    parser.add_argument(
        "--out",
        type=str,
        default=f"list-locks-{dt_now:%Y-%m-%d-%H%M}.json",
        help='write result to specified filename (default "list-locks-YYYY-mm-dd-HHMM" '
        "with format extension)",
    )
    parser.add_argument("--show", action="store_true", help="show data obtained")

    # parse command-line arguments
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # determine fields to be extracted
    if args.fields.strip() in ["-"]:
        args.fields = FIELDS_ARGS_VERBOSE
    # reduce fields to a unique set, while maintaining order
    flds = unique_ordered_list(list(args.fields.lower().split(",")))
    if args.fields.strip() in ["*", ""]:
        flds = []
        logger.debug("Requested fields: all")
    else:
        logger.debug(f"Requested fields: {flds}")

    # determine output format
    fmt = args.format
    logger.debug(f"Requested format: {fmt}")

    # determine output filename to be used, taking format into account
    fname = ""
    if args.out:
        fname = ensure_file_extension(args.out, args.format)
    if fname:
        logger.debug(f'Requested output file: "{fname}"')
    else:
        logger.info("No output file specified.")

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

    # reduce the data (in all_locks list) to the requested fields
    data, flds = reduce_data(data=all_locks, flds=flds)
    # export the data
    if fname:
        export_data(fname=fname, fmt=fmt, flds=flds, data=data)

    # when requested, show the data; or ask user first
    if not args.show and not fname:
        args.show = yn_choice("Show data?", default="n")
    if args.show:
        logger.info(json.dumps(data, indent=2, sort_keys=True))
