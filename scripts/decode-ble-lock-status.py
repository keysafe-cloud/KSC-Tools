#!/usr/bin/env python
# Copyright 2019-2026 (c) KeySafe-Cloud, all rights reserved.
# SPDX-License-Identifier: MIT
# ruff: noqa: C901, PLR0912, PLR2004

"""
Decode KeySafe-Cloud (KSC) compatible lock status values.

Script to decode KeySafe-Cloud (KSC) compatible lock status values as obtained
from the Bluetooth Low Energy (BLE) interface using the Status Characteristic
of the Lock Service. Depending on the lock model, the BLE lock status value
can be either one (for example the AXA eRL1 BLE), two bytes (e.g. the eRL2),
or even more bytes (reserved for future enhancements).

Note that this is about the BLE interface of the lock rather than the KSC API
(Application Programming Interface) for the cloud.

While this script will not connect to the lock itself over BLE, it can
help to decode and understand the value obtained with another tool from
the Status Characteristic of the Lock Service via the BLE interface.

You can for example use the nRF Connect tool (from Nordic Semiconductor)
on either Android or iOS mobile devices to obtain this value:
  * Using the nRF Connect App, scan for locks nearby.
  * On the Scanner tab, filtering for 'AXA:' will trim the result.
  * Connect with your selected lock.
  * Expand the 'Unknown Service' / '00001523-e513-11e5-9260-0002a5d5c51b'
    (this is the Lock Service of the lock, aka 0x1523).
  * Locate the Status Characteristic '00001524-e513-11e5-9260-0002a5d5c51b'
    which will be one of the 'Unknown Characteristic' entries (note that
    this is unknown to nRF Connect, as it is not a well-known standard).
  * Click the single arrow down icon to read the lock status value once.
  * Click the multiple arrows down icon to subscribe to notifications,
    which will show any lock status value changes (press for example the
    button on the eRL2 to see the lock status value changing).

IMPORTANT: While the lock is connected via nRF Connect, it can't be found
           by other BLE tools (including your own App) and vice-versa:
           the nRF Connect App might not find your lock when another App
           or tool is connected with the lock. Therefore, disconnect the
           device in the nRF Connect tool afterwards.

When developing an App, logging the observed BLE lock status value will
of course help you understand the lock behavior (note: use Notifications).
This script can then help to decode such observed values and compare it
with the logic and understanding in your App code.

Examples of script usage and results:
  $ python decode-ble-lock-status.py 01
  0x01 : closed
  $ python decode-ble-lock-status.py 0x0080
  0x0080 : open, button-pressed
  $ python decode-ble-lock-status.py '(0x) 08-80'
  0x0880 : open, child-safety, button-pressed
  $ python decode-ble-lock-status.py 01-00
  0x0100 : closed
"""

import argparse
import logging


# configure the logging
logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


def get_lock_status_flags(lock_status_value: str) -> list[str]:
    """
    Decode a lock status value provided as a hex string (like '0880').

    Returning an array of strings representing the parsed bits into
    textual described flags.

    :param lock_status_value: normalized lock status value as hex string
    :return: list of flags as strings describing the lock status
    """
    flags = []
    try:
        status_value = bytearray.fromhex(lock_status_value)
        if not status_value:
            return ["NO-INPUT-ERROR"]
    except ValueError as e:
        logger.warning(f"Encountered parsing error: {e}")
        return ["BAD-INPUT-ERROR"]
    # check first status byte
    if len(status_value) >= 1:
        if status_value[0] == 0xFF:
            flags.append("unknown-status")
        else:
            if status_value[0] & 0x01:
                # matches 0b00000001
                flags.append("closed")
            else:
                flags.append("open")
            if status_value[0] & 0x08:
                # matches 0b00001000
                flags.append("child-safety")
            if status_value[0] & 0x10:
                # matches 0b00010000 (available for eRL2-2019+)
                flags.append("secured-plugin")
            if status_value[0] & 0x80:
                # matches 0b10000000 (available for eRL2-2019+)
                flags.append("unsecured-plugin")
        # check second status byte (available for eRL2-2019+)
        if len(status_value) >= 2:
            if status_value[1] == 0xFF:
                flags.append("unknown-extended")
            else:
                if status_value[1] & 0x01:
                    # matches 0b00000001
                    flags.append("smart-plugin")
                if status_value[1] & 0x80:
                    # matches 0b10000000
                    flags.append("button-pressed")
    else:
        flags.append("missing-status-value")
    return flags


def normalize(lock_status_value_input: str) -> str:
    """
    Normalize the command-line input of lock status value.

    :param lock_status_value_input: command-line input
    :return: normalized lock status value
    """
    lock_status_value = lock_status_value_input.lower()
    for c in "()-_ :;,":
        lock_status_value = lock_status_value.replace(c, "")
    return lock_status_value.removeprefix("0x")


if __name__ == "__main__":
    # configure command-line parsing
    parser = argparse.ArgumentParser(
        description="Decode the lock status value as obtained via BLE.",
        epilog="Provide the status_value as a hex string representation of bytes, "
        "different formats are supported (e.g. '0x0880', '0880', or '08-80').",
    )
    parser.add_argument(
        "status_value",
        nargs="+",
        help="the status value seen (as a hex string, like: 01 or 08-80)",
    )

    # parse command-line arguments
    args = parser.parse_args()
    # normalize the lock status value input
    lock_status_value = normalize("".join(args.status_value))

    # decode the input into an array describing the state bits
    flags = get_lock_status_flags(lock_status_value)
    # merge the flags into one string for output
    str_flags = ", ".join(flags)
    logger.info(f"0x{lock_status_value} : {str_flags}")
