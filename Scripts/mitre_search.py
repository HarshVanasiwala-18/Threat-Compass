
import requests
import json
from bs4 import BeautifulSoup
import os
import sys
import csv

try:
    with open("CTI DB/MITRE/mitre.json", "r") as file:
        mitre = json.load(file)

except FileNotFoundError:
    print("File not found")
    print("Aborting...")
    sys.exit(1)

def miter_additional_info(group_id):
    print(group_id)
    url = f'https://attack.mitre.org/groups/{group_id}/'
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        h2 = soup.find_all("h2")
        for i in h2:
            try:
                table = i.next_sibling.next_sibling
                tr = table.find_all("tr")
                for i in tr:
                    td = i.find_all("td")
                    for i in td:
                        print(i.text.strip())
            except:
                pass

def group_id_search(input):
    for i in mitre:
        if input.lower() == i["Name"].lower():
            print(i["ID"])
            miter_additional_info(i["ID"])
            break
        else:
            pass


if __name__ == "__main__":
    user_input = input("Enter Malware name or Threat actor: ")
    group_id_search(user_input)