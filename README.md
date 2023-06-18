# ssh-inspector
Attack ssh service with bruteforce wordlist attack &amp;&amp; Guard ssh service against wordlist attack


### Features:
- Making a dictionary attack on the SSH service running on the target server
  - Multithreaded
  - number of threads can be adjusted
- 2 different modes
  - Single user – multiple password modes
  - Many users – many password modes
- Dictionary attack detection and prevention on running SSH service
  - The `journalctl` command is used for detection. This command has service and time filtering features in itself.
  Also, filtering with the `journalctl` command is preferred rather than reading the entire var/log/auth.log file.


Lab environment:
It is preferred to use virtual machine as a lab environment. 2 different machines are installed on VirtualBox
- Ubuntu Server (target machine)
- Kali Linux (attack machine, new IP address request was made from DHCP service to attack from different IP addresses)

* SSH service is installed on Ubuntu Server machine.

Dictionaries used:
- Most common username list  
https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt
- Most used password list  
https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/top-passwords-shortlist.txt
                                                          
----

### Help

```
python3 ssh_bruteforce.py -h
```

```
python3 ssh_gurad.py -h
```

----

### RUN:

#### Attack machine:  

Required packages must be installed before running.

```
pip install paramiko
```

or with the `requirements.txt` file that comes with the source codes:
```
pip install -r requirements.txt
```

Run attack  
```
python3 ssh_bruteforce.py --host 192.168.56.107 --port 22 -U ubuntu -p wordlists/passwords.txt --threads 7 --auth-timeout 0.1 --timeout 1
```


#### Server machine:  

Run ssh guard (threshold is 30 invalid login attempts in 1 second)  
```
python3 ssh_guard.py -t 30/s
```
