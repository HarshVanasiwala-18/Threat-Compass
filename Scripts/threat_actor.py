import requests
import json
from bs4 import BeautifulSoup
import os

def scrape_threat_actor():
    try:
        response = requests.get("https://malpedia.caad.fkie.fraunhofer.de/actors")
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")

            find_table = soup.find("table", {"class": "table enumerated table-dark table-sm"})

            data = []

            for row in find_table.find_all("tr"):
                threat_actor = row.find('td', class_='common_name')
                aliases = row.find('td', class_='synonyms')

                threat_actor_text = threat_actor.text if threat_actor and threat_actor.text else None
                aliases_text = aliases.text if aliases and aliases.text else None

                entry = {
                    "Threat Actor": threat_actor_text,
                    "Aliases": aliases_text
                }
                
                data.append(entry)
        
        directory = "Threat Actor Json Files"
        try:
            os.makedirs(directory)
        except FileExistsError:
            pass

        with open(os.path.join(directory, "threat_actors.json"), "w") as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print("Exception:", e)

if __name__ == "__main__":
    scrape_threat_actor()