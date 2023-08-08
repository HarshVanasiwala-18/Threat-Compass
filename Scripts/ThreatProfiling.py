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

    with open("CTI DB/MITRE/mitre.json", "r") as file:
        mitre = json.load(file)
except FileNotFoundError:
    print("File not found")
    print("Aborting...")
    sys.exit(1)

try:
    os.makedirs("CTI DB/Indicators")
except FileExistsError:
    pass


malware_name = []
malware_alias = []
assosiated_group = []
campaigns_data = {}
techniques_data = {}
software_data = {}
t_description = []
threat_country = {}

def miter_additional_info(group_id):
    url = f'https://attack.mitre.org/groups/{group_id}/'
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        h2 = soup.find_all("h2")
        for i in h2:
            if "Associated Group Descriptions" in i.text.strip():
                table = i.find_next("table")
                rows = table.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    for col in cols:
                        groups = cols[0].text.strip()
                        if groups not in assosiated_group:
                            assosiated_group.append(groups)
            elif "Campaigns" in i.text.strip():
                table = i.find_next("table")
                rows = table.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    for col in cols:
                        camp_ID = cols[0].text.strip()
                        Name = cols[1].text.strip()
                        First_Seen = cols[2].text.strip().split("[")[0]
                        Last_Seen = cols[3].text.strip().split("[")[0]
                        techniques_column = cols[5]
                        techniques = [technique.strip() for technique in techniques_column.text.split(",")]
                        if camp_ID not in campaigns_data:
                            campaigns_data[camp_ID] = {'Name': Name, 'First_Seen': First_Seen, 'Last_Seen': Last_Seen, 'Techniques': techniques}
            elif "Techniques Used" in i.text.strip():
                table = i.find_next("table")
                rows = table.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    for col in cols:
                        Domain = cols[0].text.strip()
                        tech_ID = cols[1].text.strip()
                        if "." in cols[2].text.strip():
                            sub_tech_ID = cols[2].text.strip()
                            Name = cols[3].text.strip()
                            Use = cols[4].text.strip()
                        else:
                            sub_tech_ID = ""
                            Name = cols[2].text.strip()
                            Use = cols[3].text.strip()
                        if tech_ID not in techniques_data:
                            techniques_data[tech_ID] = {'Domain': Domain, 'Name': Name, 'Use': Use, 'Sub_Techniques': [sub_tech_ID]}
            elif "Software" in i.text.strip():
                table = i.find_next("table")
                rows = table.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    for col in cols:
                        soft_id = cols[0].text.strip()
                        soft_name = cols[1].text.strip()
                        tech = cols[3].text.strip()
                        if soft_id not in software_data:
                            software_data[soft_id] = {'Name': soft_name, 'Techniques': [tech]}
            else:
                pass

def mitre_framework(input):
    try:
       for i in mitre:
            if input == i["Name"].lower():
               miter_additional_info(i["ID"])
            else:
                for j in malware_name:
                    try:
                        j = j.split("(")[0].strip()
                    except:
                        try:
                            j = j.split(",")
                        except:
                            j = j
                    for l in j:
                        l = str(l).lower()
                        if i["Name"].lower() in l:
                            miter_additional_info(i["ID"])
                    else:
                        for k in malware_alias:
                            try: 
                                k = k.split("(")[0].strip()
                            except:
                                try:
                                    k = k.split(",")
                                except:
                                    k = k
                            for m in k:
                                m = str(m).lower()
                                if i["Name"].lower() in m:
                                    miter_additional_info(i["ID"])
            
    except Exception as e:
        print(e)


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
        description = soup.find("p")
        if description:
            t_description.append(description.text.strip())

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
                            threat_country["Country"] = row[0]
                            threat_country["Country Code"] = row[1]
                            break


def find_threat_actor(input):
    for malware in malware_data:
        malware_family = malware["Malware Family"]
        if malware_family:
            malware_family = malware_family.split("(")[0].strip()
        malware_aliases = malware["Aliases"]
        if malware_aliases:
            malware_aliases = malware_aliases.split(",")
            for alias in malware_aliases:
                alias = alias.strip()
                if alias:
                    malware_alias.append(alias)
        malware_family = str(malware_family).lower()
        if malware_family == input:
            malware_d = malware["Name"]
            threat_description(malware_d, "details")
            break
        elif malware_aliases != None:
            malware_aliases = str(malware_alias).lower()
            if input in malware_aliases:
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

def main():
    user_input = input("Enter Threat Actor or Malware: ").lower()
    print("-" * 50)
    find_threat_actor(user_input)
    mitre_framework(user_input)
    print("-" * 50)
    name  = user_input.replace(" ", "_")
    if os.path.exists(f"CTI DB\Indicators\{name}_threat_profiling.txt"):
        print("File already exists")
        print("Please Rename the file or delete the existing file")
    else:
        with open(f"CTI DB\Indicators\{name}_threat_profiling.txt", "w") as file:
            file.write(f"Threat Actor/Malware: {user_input}\n")
            file.write(f"Description: {t_description[0]}\n")
            file.write(f"Country: {threat_country['Country']}\n")
            file.write(f"Country Code: {threat_country['Country Code']}\n")
            for group in assosiated_group:
                file.write(f"{group}\n")
            print("Writing Group Data")
            print()
            print("-" * 50)
                

            for camp_ID, data in campaigns_data.items():
                file.write(f"Camp_ID: {camp_ID}\n")
                file.write(f"Name: {data['Name']}\n")
                file.write(f"First Seen: {data['First_Seen']}\n")
                file.write(f"Last Seen: {data['Last_Seen']}\n")
                file.write("Techniques:\n")
                for technique in data['Techniques']:
                    file.write(f"  - {technique}\n")
                print("Writing Campaigns Data")
                print()
                print("-" * 50)

            for tech_ID, data in techniques_data.items():
                file.write(f"Tech ID: {tech_ID}\n")
                file.write(f"Domain: {data['Domain']}\n")
                file.write(f"Name: {data['Name']}\n")
                file.write(f"Use: {data['Use']}\n")
                if data['Sub_Techniques']:
                    file.write("Sub Techniques:\n")
                    for sub_tech_ID in data['Sub_Techniques']:
                        file.write(f"  - {sub_tech_ID}\n")
                print("Writing Techniques Data")
                print()
                print("-" * 50)

            for soft_id, data in software_data.items():
                print(f"Software ID: {soft_id}")
                print(f"Name: {data['Name']}")
                print("Techniques:")
                file.write("Techniques:\n")
                file.write(f"  - {data['Name']}\n")
                file.write("Techniques:\n")
                for tech in data['Techniques']:
                    file.write(f"  - {tech}\n")
                print("Writing Software Data")
                print()
                print("-" * 50)
            
            if malware_name:
                for name in set(malware_name):
                    file.write(f"Name: {name}\n")
                print("Writing Malware Data")
                print("-" * 50)
                
            if malware_alias:
                for alias in set(malware_alias):
                    file.write(f"Alias: {alias}\n")
                print("Writing Malware Alias Data")
                print("-" * 50)