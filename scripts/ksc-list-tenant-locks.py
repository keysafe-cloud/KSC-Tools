# Copyright 2019-2026 (c) KeySafe-Cloud, all rights reserved.

"""
Script to help list all locks in the tenant inventory, with the output
either in JSON format or in CSV format (for specified fields).

It gets all locks of the tenant based on the KSC API Access Key provided.

NOTE: It is recommended to provide the KSC API Access Key via command-line
      parameters (rather than changing 'SECRET' in a copy of this script).
      Please protect your API Key as described in the API documentation.

This script requires `requests` (see https://pypi.org/project/requests/)
to be installed, use `pip install -r requirements.txt` to install.
"""

import argparse
import datetime
import json
import logging
import os
import requests
import sys

from dotenv import load_dotenv

VERSION = "1.2.1"
BASE_URL = "https://keysafe-cloud.appspot.com/api/v1"

# load environment variables from .env file
load_dotenv()
# =============================================================================
# NOTE: For different (sub-)tenants: use a different API Key in each run.
#
#       Instead of changing this in the script, it is strongly recommended
#       to keep the TENANT_API_KEY safe / secure within a local `.env` file.
#
#       Make sure the `.env` is excluded from source code control, for example
#       by using `.gitignore` to exclude the `.env` file.
#
#       It is possible to override the `.env` value with on the command-line
#       using the `--api_key` parameter.
#
#       For different (sub-)tenants: use a different API Key in each run.
TENANT_API_KEY = os.environ.get("TENANT_API_KEY")
# =============================================================================

OUTPUT_FORMATS = ["csv", "json"]
try:
    import xlsxwriter
    from xlsxwriter.utility import xl_col_to_name

    OUTPUT_FORMATS.append("xlsx")
except ImportError:
    xslxwriter = None


FIELD_WIDTHS = {
    "batch_code": 14,
    "bootloader_modified": 25,
    "bootloader_version": 8,
    "created": 25,  # deprecated, use batch_code
    "firmware_modified": 25,
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
    "modified": 25,
    "nr_of_slots": 5,
    "reference": 18,
    "software_modified": 25,
    "software_version": 8,
}
FIELDS_ARGS_DEFAULT = "id,lock_uid,lock_status,reference"
FIELDS_ARGS_ALL = (
    "id,lock_uid,mac_address,lock_status,reference,lock_model,lock_version,batch_code,"
    "modified,nr_of_slots,hardware_model,hardware_version,software_version,software_modified,"
    "firmware_version,firmware_modified"
)

# configure the logging
logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


def yn_choice(message: str, default: str = "y") -> bool:
    """
    Handle an interactive response to the given message/question.
    Returns boolean True when question is confirmed via user input.
    Based on https://stackoverflow.com/a/4741730/2315612
    combined with https://stackoverflow.com/a/54712937/2315612
    """
    choices = "Y/n" if default.lower() in ("y", "yes") else "y/N"
    try:
        choice = input("{} ({}) ".format(message, choices))
    except KeyboardInterrupt:
        logger.error("Received keyboard interrupt, exit script.")
        sys.exit(1)
    except EOFError:
        logger.error("Unexpected EOF, exit script.")
        sys.exit(1)
    values = ("y", "yes", "") if choices == "Y/n" else ("y", "yes")
    return choice.strip().lower() in values


def obfuscate(s: str, show: int = 6) -> str:
    """
    Obfuscate a string, showing only the last `show` characters.

    :param s: string to obfuscate
    :param show: number of characters to show at the end
    :return: obfuscated string
    """
    return f"OBFUSCATED:{s[-show:]}" if s else "OBFUSCATED:None"


def unique_ordered_list(items) -> list[str]:
    """
    Reduce items to a unique set, while maintaining order.

    :param items: list of string items
    :return: unique ordered list of items
    """
    if not items:
        return []
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result


def ensure_file_extension(fname: str, fmt: str) -> str:
    """
    Ensure that the given filename ends with the specified format extension.

    :param fname: original filename (e.g., "report.txt", "data.json")
    :param fmt: target format extension (e.g., "csv", "json", "xlsx")
    :return: corrected filename (e.g., "report.csv")
    """
    # normalize the format extension requested
    target_ext = f".{fmt.lower()}"
    # check if fname already ends with the target extension
    if fname.strip().lower().endswith(target_ext):
        return fname
    # change/add extension of the fname
    parts = fname.rsplit(".", 1)
    base_name = parts[0]
    return f"{base_name}{target_ext}"


def get_locks_url(limit: int = 0) -> str:
    """
    Create query Uniform Resource Locator (URL) to obtain locks.
    Returns a string URL to be used when making API request for locks.
    """
    url = BASE_URL.strip().rstrip("/") + "/locks"
    if limit:
        prefix = "&" if ("?" in url) else "?"
        url = "{0}{1}limit={2}".format(url, prefix, limit)
    return url


def get_headers(api_key: str) -> dict:
    """
    Create headers to use when making requests to the KSC API.
    Returns a dictionary to be used as headers when making API requests.
    """
    tenant_api_key = api_key.strip()
    if len(tenant_api_key) != 32:
        logger.warning("WARNING: Unexpected length of API Key, please adjust!")
    # identify the script and the requests library used
    script_ver = "list-tenant-locks/{}".format(VERSION)
    requests_ver = "python-requests/{}".format(requests.__version__)
    headers = {
        "X-Api-Key": tenant_api_key.strip(),
        "Accept-Encoding": "gzip,deflate",
        "Content-Type": "application/json",
        "User-Agent": "{}; {}; gzip".format(script_ver, requests_ver),
    }
    return headers


def get_locks(url: str, headers: dict) -> tuple[int, list[dict]]:
    """
    Request all locks for tenant inventory (associated with API key in headers),
    handling any batch processing as required via URL (see "List all locks").
    Returns number of requests executed and a list of all locks in the tenant
    inventory (if any).
    """
    r_count = 0
    data = None
    lst = []
    while url:
        r_count += 1
        try:
            r = requests.get(url, headers=headers, json=data)
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
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
        except requests.exceptions.RequestException as e:
            logger.error(f"Request exception: {e}")
            # logger.debug(r.text)
            sys.exit(1)
    return r_count, lst


def export_xlsx(fname: str, flds: list[str], data: list[dict]):
    """
    Export the result into Excel (.xlsx) format.

    :param fname: filename requested, already adjusted to format
    :param flds: list of fields requested
    :param data: list of records, already reduced to fields requested
    """
    if not xlsxwriter:
        logger.warning("Warning: XLSX format requested, but xlsxwriter not available.")
        return
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
        data_rows = []
        for rec in data:
            data_rows.append([f"{rec.get(fld, '')}" for fld in flds])
        # sort lexicographically by comparing corresponding elements from left to right
        data_rows = sorted(data_rows)
        logger.debug("Add table with data to the worksheet.")
        rng_column = xl_col_to_name(len(flds) - 1)
        rng_rows = len(data_rows) + 1
        xl_range = f"$A$1:${rng_column}${rng_rows}"
        logger.debug(xl_range)
        ws.add_table(xl_range, {"data": data_rows, "columns": col_headers})
        logger.debug("Add defined name for the data table.")
        ws_xl_range = f"={ws.name}!{xl_range}"
        wb.define_name("AllData", ws_xl_range)
        logger.debug("Close the workbook and save the file.")
        wb.close()
        logger.info(f"Successfully created XLSX file: {fname}")
    except Exception as e:
        logger.error(f"Error writing XLSX file: {e}")


def provide_output(fname: str, fmt: str, flds: list[str], data: list[dict]) -> str:
    """
    Provide output of data in the format requested, also written to fname output file if specified.

    :param fname: filename requested, already adjusted to format
    :param fmt: format requested (one of "csv", "json", or "xlsx")
    :param flds: list of fields requested
    :param data: list of records, already reduced to fields requested
    :return: string result (for XLSX just file written or not)
    """
    result = ""
    if fmt in ["csv", "json"]:
        if fmt == "csv":
            logger.info("Convert result into CSV format...")
            # provide names of fields as header on first line
            lines = [";".join(['"{}"'.format(fld) for fld in flds])]
            for rec in data:
                # for each record provide field values on one line
                line = ";".join(['"{}"'.format(rec[fld]) for fld in flds])
                lines.append(line)
            # combine all lines with record details into CSV result
            result = "\n".join(lines)
        if fmt == "json":
            logger.info("Convert result into JSON format...")
            result = json.dumps(data, indent=2, sort_keys=True)
        if fname:
            logger.info("Export/output result to: {}".format(fname))
            with open(fname, "w") as out_file:
                out_file.write(result)
    if fmt == "xlsx":
        export_xlsx(fname=fname, flds=flds, data=data)
        result = f'Open the "{fname}" for the XLSX output.'
    return result


if __name__ == "__main__":
    dt_now = datetime.datetime.now(datetime.timezone.utc)
    # configure command-line parsing
    parser = argparse.ArgumentParser(
        description="List all locks in the tenant inventory."
    )
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
        'use "all" for all fields)',
    )
    parser.add_argument(
        "--format",
        "--fmt",
        choices=["csv", "json", "xlsx"],
        default="json",
        help='provide result in specified format (default "json" for JSON output; '
        'use "csv" for CSV output, and "xlsx" for XLSX spreadsheet output)',
    )
    parser.add_argument(
        "--out",
        type=str,
        default=f"list-locks-{dt_now:%Y-%m-%d}.json",
        help='write result to specified filename (default "list-locks-YYYY-MM-DD")',
    )
    parser.add_argument("--show", action="store_true", help="show result")

    # parse command-line arguments
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # determine fields to be extracted
    if args.fields.strip() in ["*", "all"]:
        args.fields = FIELDS_ARGS_ALL
    # reduce fields to a unique set, while maintaining order
    flds = unique_ordered_list(args.fields.lower().split(","))
    logger.debug(f"Requested fields: {flds}")

    # determine output format
    if (args.format in ["xlsx"]) and (not xlsxwriter):
        # library required when XLSX requested
        logger.error(
            'ERROR: format "xlsx" requested without Python xlsxwriter installed.'
        )
        sys.exit(1)
    logger.debug(f"Requested format: {args.format}")

    # determine output filename to be used, taking format into account
    fname_out = ""
    if args.out:
        fname_out = ensure_file_extension(args.out, args.format)
        logger.debug(f"Requested output file: {fname_out}")
    else:
        logger.debug("No output file requested.")

    # prepare API calls
    logger.info("Determine URL to be used for query.")
    url = get_locks_url(args.limit or 0)
    logger.debug(f"HTTP Request URL: {url}")
    logger.info("Determine headers to be used for all requests.")
    if args.api_key:
        logger.debug("Using the API Key: {}".format(obfuscate(args.api_key)))
    else:
        logger.error(
            "ERROR: No TENANT_API_KEY set in .env file or provided via arguments!"
        )
        sys.exit(1)
    headers = get_headers(args.api_key)
    _headers = dict(headers)
    if _headers:
        # protect the TENANT_API_KEY by obfuscating it in the logs
        _headers["X-Api-Key"] = obfuscate(args.api_key)
        logger.debug(f"HTTP Request Headers: {_headers}")

    # obtain tenant inventory using "List all locks"
    logger.info("Get all locks for tenant based on API Key...")
    r_count_lst, all_locks = get_locks(url, headers)
    logger.info("# of all locks in tenant inventory: {}".format(len(all_locks)))
    logger.info("Obtained with {} non-eKey API requests.".format(r_count_lst))
    logger.debug(all_locks)

    # reduce result (in all_locks list) to requested fields
    for rec in all_locks:
        # get hold of list of unique fields in the record
        _rec_flds = set(rec.keys())
        for rec_fld in _rec_flds:
            if rec_fld not in flds:
                del rec[rec_fld]

    # provide the result output, for XLSX expected to file only
    result = provide_output(fname=fname_out, fmt=args.format, flds=flds, data=all_locks)

    # either use command-line parameter set to show, or ask user
    if args.out:
        show = args.show
    else:
        show = args.show or yn_choice("Show result?", default="n")
    if show:
        logger.info("Result:")
        logger.info(result)
