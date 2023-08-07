import requests
from bs4 import BeautifulSoup
import json
import sys
import csv
import os

try:
    with open("CTI DB/Threat Actors/threat_actors.json", "r") as file:
        threat_data = json.load(file)

    with open("CTI DB/Malware/malware_families.json", "r") as file:
        malware_data = json.load(file)

except FileNotFoundError:
    print("File not found")
    print("Aborting...")
    sys.exit(1)


def scarpe_indicators(Threat_Actor):
    j = 1
    while True:
        try:
            Threat_Actor = Threat_Actor.replace(" ", "%20")
            response = requests.get(
                f"https://otx.alienvault.com/otxapi/indicators/?include_inactive=0&sort=indicator&q={Threat_Actor}&page={j}&limit=10000"
            )
            soup = BeautifulSoup(response.content, "html.parser")
            j += 1
            if response.status_code == 200:
                json_data = json.loads(soup.prettify())
                if json_data["results"] != []:
                    for i in range(len(json_data["results"])):
                        print(
                            json_data["results"][i]["indicator"],
                            json_data["results"][i]["type"],
                        )
                elif json_data["results"] == []:
                    break
            elif response.status_code == 429:
                print("Too many requests")
                break
            elif response.status_code == 400:
                print("Bad Request")
                break
            else:
                break
        except Exception as e:
            print("Exception: ", e)
            break


def scarpe_pulses(Threat_Actor):
    pulses = []
    j = 1
    while True:
        try:
            Threat_Actor = Threat_Actor.replace(" ", "%20")
            response = requests.get(
                f"https://otx.alienvault.com/otxapi/pulses/?limit=10000&page={j}&sort=pulse_id&q={Threat_Actor}"
            )
            soup = BeautifulSoup(response.content, "html.parser")
            j += 1
            if response.status_code == 200:
                json_data = json.loads(soup.prettify())
                if json_data["results"] != []:
                    for i in range(len(json_data["results"])):
                        pulses.append(json_data["results"][i]["id"])
                elif json_data["results"] == []:
                    break
                elif response.status_code == 429:
                    print("Too many requests")
                    break
                elif response.status_code == 400:
                    print("Bad Request")
                    break
                else:
                    break
        except Exception as e:
            print("Exception: ", e)
            break
    return pulses


def scrape_ioc_pulses(Threat_Actor, pulses):
    reader = pulses
    for row in reader:
        print(row, " - ", str(Threat_Actor).title(), "Scraping...")
        j = 1
        while True:
            try:
                response = requests.get(
                    f"https://otx.alienvault.com/otxapi/pulses/{row}/indicators/?sort=indicator&limit=10000&page={j}"
                )
                soup = BeautifulSoup(response.content, "html.parser")
                json_data = json.loads(soup.prettify())
                print("Page: ", j, " - ", len(json_data["results"]))
                j += 1
                if response.status_code == 200:
                    json_data = json.loads(soup.prettify())
                    if json_data["results"] != []:
                        for i in range(len(json_data["results"])):
                            count = json_data["results"][i]["observations"]
                            if count >= 10:
                                indicator = json_data["results"][i]["indicator"]
                                ioc_type = json_data["results"][i]["type"]
                                print(indicator, ioc_type)
                    elif json_data["results"] == []:
                        break
                elif response.status_code == 429:
                    print("Too many requests")
                    break
                elif response.status_code == 400:
                    print("Bad Request")
                    break
                else:
                    break
            except Exception as e:
                print("Exception: ", e)
                break


def find_threat_actor(input):
    try:
        data = []
        for malware in malware_data:
            malware_family = malware["Malware Family"]
            if "(" in malware_family:
                malware_family = malware_family.split("(")[0].strip()
            malware_family = str(malware_family).lower()
            malware_alias = malware["Aliases"]
            if malware_family == input:
                data.append(malware_family)
                break
            elif malware_alias != None:
                malware_alias = str(malware_alias).lower()
                if input in malware_alias:
                    data.append(malware_alias)
                    break

        for threat_actor in threat_data:
            threat_actor_name = threat_actor["Threat Actor"]
            threat_actor_name = str(threat_actor_name).lower()
            threat_actor_alias = threat_actor["Aliases"]
            if threat_actor_name == input:
                data.append(threat_actor_name)
                break
            elif threat_actor_alias != None:
                threat_actor_alias = str(threat_actor_alias).lower()
                if input in threat_actor_alias:
                    data.append(threat_actor_alias)
                    break
        if data[0] != None:
            scarpe_indicators(data[0])
    except Exception as e:
        print("Exception: ", e)
        print("Threat Actor or Malware not found in CTI DB")
        print("Aborting...")
        sys.exit(1)


def main():
    try:
        user_input = input("Enter Threat Actor or Malware: ").lower()
        find_threat_actor(user_input)
        scrape_ioc_pulses(user_input, scarpe_pulses(user_input))
    except Exception as e:
        print("Exception:", e)


