import requests
from bs4 import BeautifulSoup
import json
import sys
import csv
import os

directory = "CTI DB"
try:
    os.makedirs(directory)
except FileExistsError:
    pass

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
    new_folder_name = f"IOCs/{Threat_Actor}"
    new_folder_path = os.path.join(directory, new_folder_name)
    try:
        os.makedirs(new_folder_path)
    except FileExistsError:
        pass

    with open(os.path.join(new_folder_path, "indicators.csv"), "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Indicator", "Type"])

        j = 1
        while True:
            try:
                Threat_Actor = Threat_Actor.replace(" ", "%20")
                response = requests.get(
                    f"https://otx.alienvault.com/otxapi/indicators/?include_inactive=0&sort=-modified&q={Threat_Actor}&page={j}&limit=10000"
                )
                soup = BeautifulSoup(response.content, "html.parser")
                j += 1
                if response.status_code == 200:
                    json_data = json.loads(soup.prettify())
                    if json_data["results"] != []:
                        for i in range(len(json_data["results"])):
                            writer.writerow(
                                [
                                    json_data["results"][i]["indicator"],
                                    json_data["results"][i]["type"],
                                ]
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
    new_folder_name = f"IOCs/{Threat_Actor}"
    new_folder_path = os.path.join(directory, new_folder_name)
    try:
        os.makedirs(new_folder_path)
    except FileExistsError:
        pass

    with open(os.path.join(new_folder_path, "pulses_id.csv"), "w", newline="") as file:
        writer = csv.writer(file)
        j = 1
        while True:
            try:
                Threat_Actor = Threat_Actor.replace(" ", "%20")
                response = requests.get(
                    f"https://otx.alienvault.com/otxapi/pulses/?limit=10000&page={j}&sort=-modified&q={Threat_Actor}"
                )
                soup = BeautifulSoup(response.content, "html.parser")
                j += 1
                if response.status_code == 200:
                    json_data = json.loads(soup.prettify())
                    if json_data["results"] != []:
                        for i in range(len(json_data["results"])):
                            writer.writerow([json_data["results"][i]["id"]])
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


def scrape_ioc_pulses(Threat_Actor):
    new_folder_name = f"IOCs/{Threat_Actor}"
    new_folder_path = os.path.join(directory, new_folder_name)
    try:
        os.makedirs(new_folder_path)
    except FileExistsError:
        pass

    with open(os.path.join(new_folder_path, "pulses_id.csv"), "r") as file:
        reader = csv.reader(file)
        with open(
            os.path.join(new_folder_path, "pulses_ioc.csv"), "w", newline=""
        ) as file:
            writer = csv.writer(file)
            writer.writerow(["Indicator", "Type"])
            for row in reader:
                print(row[0], " - ", str(Threat_Actor).title(), "Scraping...")
                j = 1
                while True:
                    try:
                        response = requests.get(
                            f"https://otx.alienvault.com/otxapi/pulses/{row[0]}/indicators/?sort=-created&limit=10000&page={j}"
                        )
                        soup = BeautifulSoup(response.content, "html.parser")
                        json_data = json.loads(soup.prettify())
                        print("Page: ", j, " - ", len(json_data["results"]))
                        j += 1
                        if response.status_code == 200:
                            json_data = json.loads(soup.prettify())
                            if json_data["results"] != []:
                                for i in range(len(json_data["results"])):
                                    indicator = json_data["results"][i]["indicator"]
                                    ioc_type = json_data["results"][i]["type"]
                                    writer.writerow([indicator, ioc_type])
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
    data = []
    i = 0
    while True:
        try:
            threat_actor = threat_data[i]["Threat Actor"]
            threat_actor = str(threat_actor).lower()
            if threat_actor == input:
                # threat_actor = threat_actor.replace(' ', '%20')
                data.append(threat_actor)
                break
            else:
                malware = malware_data[i]["Malware Family"]
                malware = str(malware).lower()
                if malware == input:
                    # malware = malware.replace(' ', '%20')
                    data.append(malware)
                    break
            i += 1
        except Exception as e:
            print("Exception: ", e)
            break

    if data[0] != None:
        scarpe_indicators(data[0])


def main():
    try:
        user_input = input("Enter Threat Actor or Malware: ").lower()
        path = os.path.join("CTI DB", "IOCs", user_input)
        if os.path.exists(path):
            print("IOCs already exist")
            sys.exit()
        find_threat_actor(user_input)
        scarpe_pulses(user_input)
        scrape_ioc_pulses(user_input)
    except Exception as e:
        print("Exception:", e)


if __name__ == "__main__":
    main()
