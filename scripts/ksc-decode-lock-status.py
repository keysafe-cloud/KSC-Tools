#!/usr/bin/env python
# coding=utf-8

"""
Script to decode the AXA Electronic Ring Lock (AXA eRL) lock status value
as provided over Bluetooth Low Energy (BLE) to a connected device. It is
compatible with both the eRL1 (1 byte) and the eRL2 (2 byte) format.

Note that this explains the BLE interface value; rather than the KSC API.

While this script will not connect to the lock itself over BLE, it can
help to decode and understand the value obtained with another tool from
the Status characteristic of the Lock service via the BLE interface.

You can for example use the nRF Connect tool (from Nordic Semiconductor)
on either Android of iOS mobile devices to obtain this value:
- Using the nRF Connect App, scan for locks nearby
- On the Scanner tab, filtering for 'AXA:' will trim the result
- Connect with your selected lock
- Expand the 'Unknown Service' / '00001523-e513-11e5-9260-0002a5d5c51b'
  (this is the Lock Service of the AXA eRL lock, aka 0x1523)
- Locate the Status characteristic '00001524-e513-11e5-9260-0002a5d5c51b'
  which will be one of the 'Unknown Characteristic' entries (note that
  this is unknown to nRF Connect, as it is not a well-known standard)
- Click the single arrow down icon to read the lock status value once
- Click the multiple arrows down icon to subscribe to notifications,
  which will show any lock status value changes (press for example the
  button on the eRL2 to see the lock status value changing)

IMPORTANT: While the lock is connected via nRF Connect, it can't be found
           by other BLE tools (including your own App) and vice-versa:
           the nRF Connect App might not find your lock when another App
           or tool is connected with the AXA eRL lock.

When developing an App, logging the observed BLE lock status value will
of course help you understand the lock behavior (note: use notifications).
This script can then help to decode such observed values and compare it
with the logic and understanding in your App code.

Copyright 2019-2020 (c) KeySafe-Cloud, all rights reserved.
"""

import argparse
import binascii


def get_lock_status_flags(lock_status_value):
  flags = []
  try:
    status_value = binascii.unhexlify(lock_status_value)
    if not status_value:
      return ['NO-INPUT-ERROR']
  except:
    return ['BAD-INPUT-ERROR']
  # check first status byte
  if len(status_value) >= 1:
    if hex(status_value[0]) == '0xff':
      flags.append('unknown-status')
    else:
      if (status_value[0] & 0x01):
        # matches 0b00000001
        flags.append('closed')
      else:
        flags.append('open')
      if status_value[0] & 0x08:
        # matches 0b00001000
        flags.append('child-safety')
      if status_value[0] & 0x10:
        # matches 0b00010000 (available for eRL2-2019+)
        flags.append('secured-plugin')
      if status_value[0] & 0x80:
        # matches 0b10000000 (available for eRL2-2019+)
        flags.append('unsecured-plugin')
    # check second status byte (available for eRL2-2019+)
    if len(status_value) >= 2:
      if hex(status_value[1]) == '0xff':
        flags.append('unknown-extended')
      else:
        if status_value[1] & 0x01:
          # matches 0b00000001
          flags.append('smart-plugin')
        if status_value[1] & 0x80:
          # matches 0b10000000
          flags.append('button-pressed')
  else:
    flags.append('missing-status-value')
  return flags


def normalize(lock_status_value_input):
  """Helper routine to normalize command-line input"""
  lock_status_value = lock_status_value_input.lower()
  for c in '()-_ ':
    lock_status_value = lock_status_value.replace(c, '')
  if lock_status_value.startswith('0x'):
    lock_status_value = lock_status_value[2:]
  return lock_status_value


if __name__ == '__main__':
  # configure command-line parsing
  parser = argparse.ArgumentParser(
    description="Decode the AXA eRL lock status value.")
  parser.add_argument(
    'status_value',
    help='the status value seen (as a hex string, like: 01)')

  # parse command-line arguments
  args = parser.parse_args()
  # normalize the lock status value input
  lock_status_value = normalize(args.status_value)

  # decode the input into an array describing the state bits
  flags = get_lock_status_flags(lock_status_value)
  # merge the flags into one string for output
  str_flags = ', '.join(flags)
  print('0x{} : {}'.format(lock_status_value, str_flags))
