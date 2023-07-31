import requests
import json
from bs4 import BeautifulSoup
import os
import sys
import csv

try:
    with open("CTI DB/Threat Actors/threat_actors.json", "r") as file:
        threat_data = json.load(file)

    with open("CTI DB/Malware/malware_families.json", "r") as file:
        malware_data = json.load(file)

    with open("CTI DB/Malpedia Library/threat_article.json", "r") as file:
        malpedia_data = json.load(file)

    with open("CTI DB/MITRE/group.json", "r") as file:
        groups = json.load(file)

    with open("CTI DB/MITRE/mitre.json", "r") as file:
        mitre = json.load(file)

    with open("CTI DB/MITRE/software.json", "r") as file:
        software = json.load(file)

except FileNotFoundError:
    print("File not found")
    print("Aborting...")
    sys.exit(1)

malware_name = []
malware_alias = []
data = []


def miter_additional_info(group_id):
    group_id = str(group_id).lower()
    for group in groups:
        id = str(group["Group ID"]).lower()
        if group_id in id:
            print("Group Name: ", group["Name"])
            print("Mitre TTP: ", group["Technique ID"])
            print("Comment: ", group["Comment"])

    for soft in software:
        id = str(soft["Group ID"]).lower()
        if group_id in id:
            print("Software Name: ", soft["Name"])
            print("Technique: ", soft["Techniques"])
            print("Software ID: ", soft["Software ID"])


def mitre_framework(input):
    i = 0
    while True:
        try:
            mitre_attack = mitre[i]["Name"]
            mitre_attack = str(mitre_attack).lower()
            for malware in data:
                malware = str(malware).lower()
                if input in mitre_attack:
                    print(mitre[i]["ID"])
                    print(mitre[i]["Name"])
                    print(mitre[i]["Description"])
                    print(mitre[i]["Aliases"])
                    print("\n")
                    miter_additional_info(mitre[i]["ID"])
                    break
                elif malware in mitre_attack:
                    print(mitre[i]["ID"])
                    print(mitre[i]["Name"])
                    print(mitre[i]["Description"])
                    print(mitre[i]["Aliases"])
                    print("\n")
                    miter_additional_info(mitre[i]["ID"])
                    break
            i += 1
        except Exception as e:
            break


def threat_actor_article(input):
    for news in malpedia_data:
        malware_family = str(news["Malware Family"]).lower()
        if input in malware_family:
            print("Article: ", news["Title"])
            print("Link: ", news["URL"])
            print("Date: ", news["Date"])
            print("Author: ", news["Author"])
            print("Organization: ", news["Author"])
            print("Malware Family: ", news["Malware Family"])
            print("\n")


def threat_to_malware():
    for malware in set(malware_name):
        malware = str(malware).lower()
        if "(" in malware:
            malware = malware.split("(")[0]
            data.append(malware)
            threat_actor_article(malware)
        else:
            malware = malware
            data.append(malware)
            threat_actor_article(malware)

    for alias in set(malware_alias):
        alias = str(alias).lower()
        if "," in alias:
            alias = alias.split(",")
            for i in alias:
                i = i.strip()
                data.append(i)
                threat_actor_article(i)
        else:
            data.append(alias)
            threat_actor_article(alias)


def threat_actor_profile_2(input, alias):
    try:
        alias = alias.split(",")
    except:
        alias = alias

    i = 0
    while True:
        try:
            malware = malware_data[i]["Threat Actor"]
            malware = str(malware).lower()
            if input == malware:
                malware_name.append(malware_data[i]["Malware Family"])
                aliases = malware_data[i]["Aliases"]
                if aliases:
                    malware_alias.append(malware_data[i]["Aliases"])
                i += 1
            elif malware in alias:
                malware_name.append(malware_data[i]["Malware Family"])
                aliases = malware_data[i]["Aliases"]
                if aliases:
                    malware_alias.append(malware_data[i]["Aliases"])
                i += 1
            else:
                i += 1
        except Exception as e:
            break

    threat_to_malware()


def threat_actor_profile(input, alias):
    i = 0
    while True:
        try:
            malware = malware_data[i]["Threat Actor"]
            malware = str(malware).lower()
            if input == malware:
                malware_name.append(malware_data[i]["Malware Family"])
                aliases = malware_data[i]["Aliases"]
                if aliases:
                    malware_alias.append(malware_data[i]["Aliases"])
                i += 1
            elif malware in alias:
                malware_name.append(malware_data[i]["Malware Family"])
                aliases = malware_data[i]["Aliases"]
                if aliases:
                    malware_alias.append(malware_data[i]["Aliases"])
                i += 1
            else:
                i += 1
        except Exception as e:
            break

    threat_actor_profile_2(input, alias)


def threat_description(input, threat_type):
    url = f"https://malpedia.caad.fkie.fraunhofer.de/{threat_type}/{input}"
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        threat_description = soup.find("p")
        print(threat_description.text)


def threat_actor_country(input):
    url = "https://malpedia.caad.fkie.fraunhofer.de/actors"
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        find_table = soup.find(
            "table", {"class": "table enumerated table-dark table-sm"}
        )
        element = find_table.find("tr", {"data-href": f"/actor/{input}"})
        if element:
            span_element = element.find("span", {"class": "flag-icon"})
            if span_element:
                country_code = span_element["title"]
                with open("Scripts\country.csv") as file:
                    reader = csv.reader(file)
                    for row in reader:
                        if country_code in row[1].lower():
                            print(row[0])
                            break


def find_threat_actor(input):
    for malware in malware_data:
        malware_family = malware["Malware Family"]
        if malware_family:
            malware_family = malware_family.split("(")[0].strip()
        malware_alias = malware["Aliases"]
        malware_family = str(malware_family).lower()
        if malware_family == input:
            malware_d = malware["Name"]
            threat_description(malware_d, "details")
            break
        elif malware_alias != None:
            malware_alias = str(malware_alias).lower()
            if input in malware_alias:
                malware_d = malware["Name"]
                threat_description(malware_d, "details")
                break

    for threat in threat_data:
        threat_actor = threat["Threat Actor"]
        threat_actor_alias = threat["Aliases"]
        threat_actor = str(threat_actor).lower()
        if threat_actor == input:
            threat_actor = threat_actor.replace(" ", "_")
            threat_description(threat_actor, "actor")
            threat_actor_country(threat_actor)
            threat_actor_profile(input, threat_actor_alias)
            break
        elif threat_actor_alias != None:
            threat_actor_alias = str(threat_actor_alias).lower()
            if input in threat_actor_alias:
                threat_actor = threat_actor.replace(" ", "_")
                threat_description(threat_actor, "actor")
                threat_actor_country(threat_actor)
                threat_actor_profile(input, threat_actor_alias)
                break


if __name__ == "__main__":
    user_input = input("Enter Threat Actor or Malware: ").lower()
    find_threat_actor(user_input)
    print("Malware Family: ", set(malware_name))
    print("Aliases: ", set(malware_alias))
    mitre_framework(user_input)
