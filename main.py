import os
from dotenv import load_dotenv
import xml.etree.ElementTree as ET
import requests
from time import sleep
import sys

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

HOST_NAME = os.getenv('HOST_NAME')
USERNAME = os.getenv('USERNAME')
PASSWORD = os.getenv('PASSWORD')
OBJECT_GROUP = 'blacklist-ips'

base_url = f"https://{HOST_NAME}/api/"

def get_api_key(hostname, username, password): 
    url = f"https://{hostname}/api/" 
    data = f'user={username}&password={password}'
    payload = { 'type': 'keygen'} 
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    }
    response = requests.post(url, params=payload, verify=False, data=data, headers=headers) 
    if response.status_code == 200: 
        root = ET.fromstring(response.content) 
        return root.find('./result/key').text 
    else:
        raise Exception('Failed to retrieve API key')

    
def create_object(api_key, object_name, object_value): 
    url = f"{base_url}?type=config&action=set&key={api_key}&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address&element=<entry name='{object_name}'><ip-netmask>{object_value}</ip-netmask></entry>" 
    response = requests.get(url, verify=False) 
    if response.status_code == 200: 
        return "Object created successfully" 
    else: 
        return f"Failed to create object: {response.text}" 

def add_object_to_group(api_key, group_name, object_name): 
    url = f"{base_url}?type=config&action=set&key={api_key}&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='{group_name}']/static&element=<member>{object_name}</member>" 
    response = requests.get(url, verify=False) 
    if response.status_code == 200: 
        return "Object added to group successfully" 
        #return response.text
    else: 
        return f"Failed to add object to group: {response.text}"

def get_abuse_ip_list():
    headers = {
    'Key': os.getenv('ABUSE_API_KEY', ''),
    'Accept': 'text/plain',
    }

    params = {
    'confidenceMinimum': '90',
    }
    response = requests.get('https://api.abuseipdb.com/api/v2/blacklist', params=params, headers=headers)
    with open('abuse_ip_list.txt','w') as f:
        f.write(response.text)

    print("File saved successfully")


def blacklist_from_file(api_key, filename):
    with open(filename, 'r') as file:
        for ip in file.read().splitlines():
            object_name = f'bl_{ip}'
            result = create_object(api_key, object_name, ip)
            if "successfully" in result.lower():
                add_object_to_group(api_key,OBJECT_GROUP,object_name)
                print('IP addresses added to malicious group successfully')


def fprint(line):

    for x in line:
        print(x, end='', flush=True)
        sleep(0.1)


def init():
    fprint('Hi Welcome!\n')
    fprint('Please choose option \n')
    print(' [1] Fetch IP list from AbuseIPDB\n [2] Blacklist IP from file')

    choice = input('Enter your choice: ')
    print(choice)

    try:
        api_key = get_api_key(HOST_NAME,USERNAME,PASSWORD)
    except Exception as e:
        print(e)


    if choice == '1':
        try: 
            get_abuse_ip_list()
            blacklist_from_file(api_key, 'abuse_ip_list.txt')
        except Exception as e: 
            print(e)

    elif choice == '2':
        input_file = input('Enter input file name')
        blacklist_from_file(api_key, input_file)

    else:
        fprint('Wrong input')



    

if __name__ == "__main__":

    init()
