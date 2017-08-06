__author__ = 'anson'
# !/usr/bin/env python

# For call ipmitool_cmd
Sensors = [
    "temperature",
    "\"power supply\"",
    "voltage",
    "fan"
]

# Store log and return sensor type
Sensors_return = [
    "temperature",
    "power_supply",
    "voltage",
    "fan"
]

ipmitool_cmd = "sudo ipmitool -I open sdr type "

# ipmitool return state
sdr_state_list = [
    'ok',  # the sensor is present and operating correctly
    'ns',  # no sensor (corresponding reading will say disabled or Not Readable)
    'nc',  # non-critical error regarding the sensor
    'cr',  # critical error regarding the sensor
    'nr'   # non-recoverable error regarding the sensor
]

# ipmitool state > nagios state number
sdr_state_num = {
    'ok': 0,
    'ns': 1,
    'nc': 1,
    'cr': 2,
    'nr': 2
}
