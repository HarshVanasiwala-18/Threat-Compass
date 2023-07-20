import requests
import json
from bs4 import BeautifulSoup
import os

directory = "CTI DB"
try:
    os.makedirs(directory)
except FileExistsError:
    pass

def scrape_malware_family():
    try:
        response = requests.get("https://malpedia.caad.fkie.fraunhofer.de/families")
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")

            find_table = soup.find(
                "table", {"class": "table enumerated table-dark table-sm"}
            )

            data = []

            for row in find_table.find_all("tr"):
                malware_family = row.find("td", class_="common_name")
                threat_actor = row.find("td", class_="actors")
                alt_names = row.find("td", class_="alt_names")
                name = row.find("td", class_="name")

                malware_family_text = (
                    malware_family.text
                    if malware_family and malware_family.text
                    else None
                )
                
                threat_actor_text = (
                    threat_actor.text if threat_actor and threat_actor.text else None
                )
                alt_names_text = (
                    alt_names.text if alt_names and alt_names.text else None
                )
                name_text = name.text if name and name.text else None

                if malware_family_text == "[]":
                    malware_family_text = None

                if threat_actor_text and threat_actor_text != "[]":
                    threat_actor_text = (
                        threat_actor_text.replace("[", "")
                        .replace("]", "")
                        .replace("'", "")
                    )
                else:
                    threat_actor_text = None

                if alt_names_text and alt_names_text != "[]":
                    alt_names_text = (
                        alt_names_text.replace("[", "")
                        .replace("]", "")
                        .replace("'", "")
                    )
                else:
                    alt_names_text = None

                if name_text == "[]":
                    name_text = None

                entry = {
                    "Malware Family": str(malware_family_text).strip(),
                    "Threat Actor": threat_actor_text,
                    "Aliases": alt_names_text,
                    "Name": name_text,
                }

                data.append(entry)

        directory_path = "CTI DB"
        new_folder_name = "Malware"
        new_folder_path = os.path.join(directory_path, new_folder_name)
        try:
            os.makedirs(new_folder_path)
        except FileExistsError:
            pass

        with open(os.path.join(new_folder_path, "malware_families.json"), "w") as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print("Exception:", e)

def scrape_threat_actor():
    try:
        response = requests.get("https://malpedia.caad.fkie.fraunhofer.de/actors")
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")

            find_table = soup.find(
                "table", {"class": "table enumerated table-dark table-sm"}
            )

            data = []

            for row in find_table.find_all("tr"):
                threat_actor = row.find("td", class_="common_name")
                aliases = row.find("td", class_="synonyms")

                threat_actor_text = (
                    threat_actor.text if threat_actor and threat_actor.text else None
                )
                aliases_text = aliases.text if aliases and aliases.text else None

                entry = {"Threat Actor": threat_actor_text, "Aliases": aliases_text}

                data.append(entry)

        directory_path = "CTI DB"
        new_folder_name = "Threat Actors"
        new_folder_path = os.path.join(directory_path, new_folder_name)
        try:
            os.makedirs(new_folder_path)
        except FileExistsError:
            pass

        with open(os.path.join(new_folder_path, "threat_actors.json"), "w") as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print("Exception:", e)

def scrape_lib():
    i = 1
    data = []

    while True:
        malpedia_lib = f"https://malpedia.caad.fkie.fraunhofer.de/library/{i}"
        try:
            response = requests.get(malpedia_lib)
            soup = BeautifulSoup(response.text, "html.parser")
            if response.status_code == 200:
                find_table = soup.find("table", {"class": "table table-dark table-sm"})
                for row in find_table.find_all("tr"):
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
                
                print(
                    f"\rPage {i} Scraping completed\r",
                    flush=True, end="\r",
                )
                i += 1
            else:
                if response.status_code == 404:
                    if "Page not Found" in soup.text:
                        print(f"\rScraping completed")
                        break
        except Exception as e:
            print("Exception:", e)
            break

    directory_path = "CTI DB"
    new_folder_name = "Malpedia Library"
    new_folder_path = os.path.join(directory_path, new_folder_name)
    try:
        os.makedirs(new_folder_path)
    except FileExistsError:
        pass

    with open(os.path.join(new_folder_path, "threat_article.json"), "w") as file:
        json.dump(data, file, indent=4)

if __name__ == "__main__":
    scrape_malware_family()
    scrape_threat_actor()
    scrape_lib()
