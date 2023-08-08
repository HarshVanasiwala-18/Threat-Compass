import requests
from bs4 import BeautifulSoup
import json
import os
import sys

try:
    with open("CTI DB/Threat Actors/threat_actors.json", "r") as file:
        threat_data = json.load(file)

    with open("CTI DB/Malware/malware_families.json", "r") as file:
        malware_data = json.load(file)

except FileNotFoundError:
    print("File not found")
    print("Aborting...")
    sys.exit(1)

try:
    os.makedirs("CTI DB/Indicators")
except FileExistsError:
    pass

def scrape_malpedia_malware(malware):
    name = malware.replace(" ", "_")
    if os.path.exists(f"CTI DB/Indicators/{name}" + "_threat_article.json"):
        print("File already exists")
        print("Please rename or delete the file")
    else:
        with open(f"CTI DB/Indicators/{name}" + "_threat_article.json", "w", newline="") as file:
            response = requests.get(
                f"https://malpedia.caad.fkie.fraunhofer.de/details/{malware}"
            )
            try:
                soup = BeautifulSoup(response.content, "html.parser")
                if response.status_code == 200:
                    for row in soup.find_all("tr", class_="clickable-row clickable-row-newtab"):
                        title = row.find("span", class_="title mono-font")
                        url = row["data-href"]
                        date = row.find("span", class_="date mono-font")
                        organization = row.find("span", class_="organization mono-font")
                        author = row.find("span", class_="authors mono-font")
                        malware_family = row.find("a", attrs={"data-family_name": True})

                        title_text = title.text if title else None
                        date_text = date.text if date else None
                        organization_text = organization.text if organization else None
                        author_text = author.text if author else None
                        malware_family_text = (
                            malware_family.text.strip() if malware_family else None
                        )

                        entry = {
                            "Title": title_text,
                            "URL": url,
                            "Date": date_text,
                            "Organization": organization_text,
                            "Author": author_text,
                            "Malware Family": malware_family_text,
                        }
                        json.dump(entry, file, indent=4)
                        print("Scraping: ", title_text, end="", flush=True)
            except Exception as e:
                print("Exception: ", e)


    try:
        if os.path.exists(f"CTI DB/Indicators/{name}" + "_yara.txt"):
            print("File already exists")
            print("Please rename or delete the file")
        else:
            with open(f"CTI DB/Indicators/{name}" + "_yara.txt", "w") as file:
                soup = BeautifulSoup(response.content, "html.parser")
                table = soup.find("table", {"class": "table table-dark table-sm"})
                try:
                    table.next_sibling
                    for row in soup.find_all("pre"):
                        yara = row.text
                        if yara:
                            file.write(yara)
                            file.write("\n")
                            print("Yara rule Saved...")
                except:
                    pass
    except Exception as e:
        print("Exception: ", e)


def scrape_malpedia_threat_actor(threat_actor):
    name = threat_actor.replace(" ", "_")
    if os.path.exists(f"CTI DB/Indicators/{name}" + "_threat_article.json"):
        print("File already exists")
        print("Please rename or delete the file")
    else:
        with open(f"CTI DB/Indicators/{name}" + "_threat_article.json", "w", newline="") as file:
            response = requests.get(
                f"https://malpedia.caad.fkie.fraunhofer.de/actor/{threat_actor}"
            )
            try:
                soup = BeautifulSoup(response.content, "html.parser")
                if response.status_code == 200:
                    for row in soup.find_all("tr", class_="clickable-row clickable-row-newtab"):
                        title = row.find("span", class_="title mono-font")
                        url = row["data-href"]
                        date = row.find("span", class_="date mono-font")
                        organization = row.find("span", class_="organization mono-font")
                        author = row.find("span", class_="authors mono-font")
                        malware_family = row.find("a", attrs={"data-family_name": True})

                        title_text = title.text if title else None
                        date_text = date.text if date else None
                        organization_text = organization.text if organization else None
                        author_text = author.text if author else None
                        malware_family_text = (
                            malware_family.text.strip() if malware_family else None
                        )

                        entry = {
                            "Title": title_text,
                            "URL": url,
                            "Date": date_text,
                            "Organization": organization_text,
                            "Author": author_text,
                            "Malware Family": malware_family_text,
                        }

                        json.dump(entry, file, indent=4)
                        print("Scraping: ", title_text, end="", flush=True)
            except Exception as e:
                print("Exception: ", e)

def find_threat_actor(input):
    i = 0
    while True:
        try:
            threat_actor = threat_data[i]["Threat Actor"]
            threat_actor = str(threat_actor).lower()
            if threat_actor == input:
                scrape_malpedia_threat_actor(threat_actor.replace(" ", "_"))
                break
            else:
                malware = malware_data[i]["Malware Family"]
                malware = str(malware).lower()
                if malware == input:
                    scrape_malpedia_malware(malware_data[i]["Name"])
                    break
            i += 1
        except Exception as e:
            print("Exception: ", e)
            break


def main():
    try:
        user_input = input("Enter Threat Actor or Malware: ").lower()
        find_threat_actor(user_input)
    except Exception as e:
        print("Exception:", e)
