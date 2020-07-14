#!/usr/bin/env python3

import os
import sys
import requests
import argparse
import shodan
import netaddr
from pathlib import Path
from datetime import datetime
import csv
import time
from termcolor import colored
import colorama


# make ANSI colors works on Windows terminal
colorama.init()

SLEEP_TIME = 1


def create_parser():
    desc = """
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
"""
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--version", action="version", version="%(prog)s v1.0")
    parser.add_argument("-k", metavar="API_KEY", help="Shodan API key", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", metavar="TARGET_IPs", help="Target IPs: can be a single IP address, a network range like 192.168.1.1-10 (as with Nmap), or in CIDR notation")
    group.add_argument("-f", metavar="FILE", help="List of target IPs in a file")
    return parser


def validate_file(file):
    """ Validate that the supplied file does exist and is readable """
    if not Path(file).is_file():
        raise argparse.ArgumentTypeError(colored(f"[-] File does not exist", "red"))
    elif os.access(file, os.R_OK):
        return file
    else:
        raise argparse.ArgumentTypeError(colored(f"[-] File is not readable", "red"))


def eval_list(list_):
    """ Evaluate if list is empty or not - if empty, insert Unknown """
    if not list_:
        list_ = "Unknown"
    elif list_:
        # Check if the object type of the given list is a list
        if isinstance(list_, list):
            list_ = list_[0]
    return list_


def get_ip_country():
    """ Queries myip.com to return our external IP and country """
    api_url = "https://api.myip.com"
    with requests.Session() as s:
        data = s.get(api_url).json()
    return data["ip"], data["country"]


def prompt(question, default="no"):
    """ Prompts users whether to carry on """
    valid = {
        "yes": True, "ye": True, "y": True,
        "no": False, "n": False
    }

    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError(colored(f"[-] Invalid default answer: {default}", "red"))

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == "":
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Proceed? Please respond with 'yes' (Y) or 'no' (N) \n")


def shodan_host(api, target_ip):
    """ Retrieves results from Shodan, display the output and returns the 
    result as a list """
    try:
        results = api.host(str(target_ip))
        ip = results["ip_str"]
        hostname = results.get("hostnames")
        hostname = eval_list(hostname)
        country = results.get("country_name", "n/a")
        country = eval_list(country)
        org = results.get("org", "n/a")
        org = eval_list(org)
        os = results.get("os", "n/a")
        os = eval_list(os)
        print(colored(f"\n[+] Results found for: {ip}", "green"))
        print(f"Hostname: {hostname}")
        print(f"Country: {country}")
        print(f"Organisation: {org}")
        print(f"Operating System: {os}")
        ports = []
        transports = []
        banners = []
        for item in results["data"]:
            port = item.get("port")
            transport = item.get("transport")
            banner = item.get("data")
            banner = eval_list(banner)
            print(f"\nOpen Port: {port}/{transport}")
            print(f"Banner: {banner}")
            ports.append(port)
            transports.append(transport)
            banners.append(banner)
        row_list = []
        for index in range(len(ports)):
            row = {
                "IP": ip, 
                "Hostname": hostname, 
                "Country": country, 
                "Organisation": org, 
                "Operating System": os, 
                "Port": ports[index], 
                "Transport": transports[index], 
                "Banner": banners[index]
            }
            row_list.append(row)
        return row_list

    except shodan.APIError as e:
        print(colored(f"\n[-] Error: {e} - {target_ip}", "red"))


def gen_csv(results):
    """ Generate a CSV output based on Shodan host results """
    # filename based on timestamp
    suffix = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = "pythodan-" + suffix + ".csv"
    csv_output = Path.cwd() / filename
    with csv_output.open(mode="w", encoding="utf-8", newline="") as fout:
        writer = csv.DictWriter(fout, fieldnames=["IP", "Hostname", "Country", "Organisation", "Operating System", "Port", "Protocol", "Banner"])
        writer.writeheader()
        for item in results:
            for index in range(len(item)):
                for res in item[index]:
                    row = {
                        "IP": res["IP"], 
                        "Hostname": res["Hostname"], 
                        "Country": res["Country"], 
                        "Organisation": res["Organisation"], 
                        "Operating System": res["Operating System"], 
                        "Port": res["Port"], 
                        "Protocol": res["Transport"],
                        "Banner": res["Banner"]
                    }
                    writer.writerow(row)
    print(colored(f"\n[+] CSV outfile saved at: {csv_output}", "green"))


def process_targets(api_key, targets):
    """ Take api_key and targets from main and perform the majority of the functions """
    try:
        api = shodan.Shodan(api_key)
        results = []
        for ip in netaddr.iter_nmap_range(targets):
            result = shodan_host(api, ip)
            # To get around request rate limit (1 request/second)
            time.sleep(SLEEP_TIME)
            if result:
                results.append(result)
        return results

    except netaddr.AddrFormatError as e:
        print(colored(f"\n[-] Error: {e}", "red"))
        create_parser().print_help()


def main():
    args = create_parser().parse_args()
    key, target, target_file = args.k, args.t, args.f
    ip, country = get_ip_country()
    print(f"[*] Your external IP is {ip}, which is from {country}")
    question = "[*] Do you want to continue?"
    answer = prompt(question)
    if answer == True:
        results = []
        if key and target:
            results = [process_targets(key, target)]
        elif key and target_file:
            if validate_file(target_file):
                targets = Path(target_file)
                with targets.open(mode="r") as fin:
                    content = fin.readlines()
                    # results = []
                    for ips in content:
                        results.append(process_targets(key, ips))
        if any(results):
            gen_csv(results)

        api_info = shodan.Shodan(key).info()
        scan_credits = api_info["scan_credits"]
        print(f"\n[*] FYI - You have {scan_credits} scan credits left.")
    
    else:
        raise SystemExit


if __name__ == '__main__':
    main()