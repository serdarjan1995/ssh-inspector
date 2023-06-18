#!/usr/bin/env python3
"""
Usage:
python ssh_guard.py -t 15/s

@author: Sardor Hazratov
"""

import argparse
import logging
import os
import re
import subprocess
from datetime import datetime, timedelta
from subprocess import Popen, PIPE
from logger import Logger


logger = Logger.get_logger('ssh_guard')
logger.setLevel(logging.INFO)
DEFAULT_THRESHOLD = '10/s'

IPTABLES_ADD_RULE = "iptables -A INPUT -s %s -p tcp --dport 22 -j DROP"

re_attack_lookup = r'.*(failed|incorrect)\spassword[\w\s]+((invalid|illegal)\suser)[\w\s]+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[\s\w]+$'
re_ip_lookup = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'


def valid_threshold_values(value: str):
    """Custom argparse type for checking threshold value"""
    try:
        threshold, time_interval = value.split('/')
        if not threshold.isnumeric() or time_interval not in ['s', 'm']:
            raise ValueError
        return int(threshold), time_interval
    except ValueError:
        msg = f"Given threshold value ({value}) not valid! " \
              f"Expected format, '%d/%s' where 'd' is a number and s is a char. " \
              f"Ex: 15/s -> 15 per second, 80/m -> 80 per minute"
        raise argparse.ArgumentTypeError(msg)


def add_iptables_rule(ip):
    """ Adds iptables rule to drop incoming packets from `ip` to ssh port """
    cmd = IPTABLES_ADD_RULE % ip
    result = subprocess.run(cmd.split(' '), capture_output=True, text=True)
    if result.stderr:
        raise Exception(result.stderr)


def filter_potential_attack_lines(lines):
    """ Returns list of potential attack log lines matched to regex """
    return list(filter(lambda line: re.match(re_attack_lookup, line, re.IGNORECASE), lines))


def main(args):
    threshold, time_interval = args.threshold
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    ban_set = set()
    logger.debug(f'Script started')
    while True:
        since_time = datetime.now()
        if time_interval == 'm':
            since_time -= timedelta(minutes=1, seconds=1)  # 1 minute (+1 seconds for finetuning)
        elif time_interval == 's':
            since_time -= timedelta(seconds=2)  # 1 second (+1 seconds for finetuning)
        else:
            raise NotImplementedError(f'Time interval "{time_interval}"')
        jrn_cmd = ['journalctl', '-u', 'ssh', '--since', since_time.strftime('%Y-%m-%d %H:%M:%S')]
        with Popen(jrn_cmd, stdout=PIPE) as p:
            text = p.stdout.read().decode('utf-8')
            lines = text.split('\n')
            p_lines = filter_potential_attack_lines(lines)
            if p_lines:
                filtered_text = '\n'.join(p_lines)
                ips = re.findall(re_ip_lookup, filtered_text)
                ip_set = set(ips)
                for ip in ip_set:
                    if ips.count(ip) > threshold and ip not in ban_set:
                        add_iptables_rule(ip)
                        ban_set.add(ip)
                        logger.info(f'Banned {ip}')
                        logger.debug(f'IP addr: {ip} has {ips.count(ip)} failed login attempts')


if __name__ == '__main__':
    SCRIPT_DESC = "Python script that checks ssh auth logs and adds iptables rule to mitigate against bruteforce " \
                  "attack\n" \
                  "Should run with root privileges"
    parser = argparse.ArgumentParser(prog='ssh_guard', description=SCRIPT_DESC,
                                     epilog='By Sardor Hazratov')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose')
    parser.add_argument('-t', '--threshold', type=valid_threshold_values, required=False, default=DEFAULT_THRESHOLD,
                        help='SSH auth threshold. If the some ip address hits this value new iptables rule will be '
                             "added to the system. Expected format, '[d]/[s]' where 'd' is a number and s is a char."
                             f"Ex: 15/s -> 15 per second, 80/m -> 80 per minute.  Default: {DEFAULT_THRESHOLD}")

    arguments = parser.parse_args()

    if os.geteuid() != 0:
        parser.error("Requires root privileges")

    main(arguments)
