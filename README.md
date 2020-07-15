# pythodan.py

## Intro
Script(s) that utilises Shodan's API to help automate OSINT wonders that can be done by Shodan. I plan to add to this as the need arises. That said, at the moment it automates the ```host``` command, which queries information about the host(s) such as where it's located, what ports are open and which organisation owns the IP.

## Prerequisites
### requirements.txt
Self-explanatory, init?
```
pip install -r requirements.txt
```

### Shodan API Key
You can get your API key from your Shodan account page located at [here](https://account.shodan.io/).

## Use Cases
As aforementioned, at the moment, the script ```pythodan_host.py``` is capable of querying information about the host such as where it is located, what ports are open and which organization owns the IP. It will be useful especially during the OSINT phase of your red teaming where you most definitely will not want to actively send scanning traffic to the target.

## Usage
The script ```pythodan_host.py``` can take one IP, multiple IPs (as how you would do in Nmap), or a text file (IPs/IP range per line) as input. It will then spit out the captured info to the terminal plus save to a useful CSV file in your current working directory, for your offline analysis pleasure.
```
> python pythodan_host.py -h
usage: pythodan_host.py [-h] [-v] -k API_KEY (-t TARGET_IPs | -f FILE)

██████╗ ██╗   ██╗████████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝    ██║   ███████║██║   ██║██║  ██║███████║██╔██╗ ██║
██╔═══╝   ╚██╔╝     ██║   ██╔══██║██║   ██║██║  ██║██╔══██║██║╚██╗██║
██║        ██║      ██║   ██║  ██║╚██████╔╝██████╔╝██║  ██║██║ ╚████║
╚═╝        ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

A script that, given a valid Shodan API key, queries Shodan for info
    such as open ports and banners about Internet facing host(s)
          without actively sending traffic from yourself.
      A CSV file will also be generated for ease of analysis.

optional arguments:
  -h, --help     show this help message and exit
  -v, --version  show program's version number and exit
  -k API_KEY     Shodan API key
  -t TARGET_IPs  Target IPs: can be a single IP address, a network range like 192.168.1.1-10 (as with Nmap), or in CIDR notation
  -f FILE        List of target IPs in a file
  ```

## Disclaimers
The tool is purely for research and educational purposes only. Usage of any of these scripts for attacking targets without prior explicit written consent is illegal and unethical. The owner of this repository cannot be held responsible for any damages caused.
