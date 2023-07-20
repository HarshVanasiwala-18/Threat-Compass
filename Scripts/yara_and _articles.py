import requests
from bs4 import BeautifulSoup
import json
import os
import sys

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

def scrape_malpedia_malware(malware, directory_name):
    data = []
    response = requests.get(f'https://malpedia.caad.fkie.fraunhofer.de/details/{malware}')
    try:
        soup = BeautifulSoup(response.content, 'html.parser')
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
            
                data.append(entry)
    except Exception as e:
        print("Exception: ", e)
    
    new_folder_name = f"IOCs/{directory_name}"
    new_folder_path = os.path.join(directory, new_folder_name)
    try:
        os.makedirs(new_folder_path)
    except FileExistsError:
        pass

    with open(os.path.join(new_folder_path, f"{directory_name}_articles.json"), "w") as file:
            json.dump(data, file, indent=4)

    try:
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table", {"class": "table table-dark table-sm"})
        try:
            table.next_sibling
            for row in soup.find_all("pre"):
                yara = row.text
                if yara:
                    with open(os.path.join(new_folder_path, f"{directory_name}_yara.txt"), "w") as file:
                        file.write(yara)
        except:
            pass
    except Exception as e:
        print("Exception: ", e)        

def scrape_malpedia_threat_actor(threat_actor):
    data = [] 
    response = requests.get(f'https://malpedia.caad.fkie.fraunhofer.de/actor/{threat_actor}')
    try:
        soup = BeautifulSoup(response.content, 'html.parser')
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

                data.append(entry)         
    except Exception as e:
        print("Exception: ", e)

    new_folder_name = f"IOCs/{threat_actor}"
    new_folder_path = os.path.join(directory, new_folder_name)
    try:
        os.makedirs(new_folder_path)
    except FileExistsError:
        pass

    with open(os.path.join(new_folder_path, f"{threat_actor}_articles.json"), "w") as file:
            json.dump(data, file, indent=4)

def find_threat_actor(input):
    i  = 0
    while True:
        try:
            threat_actor = threat_data[i]['Threat Actor']
            threat_actor = str(threat_actor).lower()
            if threat_actor == input:
                # threat_actor = threat_actor.replace(' ', '%20')
                scrape_malpedia_threat_actor(threat_actor.replace(' ', '_'))
                break
            else:
                malware = malware_data[i]['Malware Family']
                malware = str(malware).lower()
                if malware == input:
                    # malware = malware.replace(' ', '%20')
                    scrape_malpedia_malware(malware_data[i]['Name'], malware)
                    break
            i += 1
        except Exception as e:
            print("Exception: ", e)
            break


def main():
    try:
        user_input = input('Enter Threat Actor or Malware: ').lower()
        find_threat_actor(user_input)
    except Exception as e:
        print("Exception:", e)

if __name__ == "__main__":
    main()