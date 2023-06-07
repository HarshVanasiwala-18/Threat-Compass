import requests
from bs4 import BeautifulSoup
import json
import os

def mitre_scrape():
    try: 
        response = requests.get("https://attack.mitre.org/groups/")

        data = []

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            table = soup.find("table", {"class": "table table-bordered table-alternate mt-2"})
            for row in table.find("tbody").find_all("tr"):
                cells = [cell.text.strip() for cell in row.find_all("td")]
                if len(cells) >= 3:
                    if cells[2] == "":
                        cells[2] = None

                    result = {
                        "id": cells[0],
                        "name": cells[1],
                        "aliases": cells[2],
                        "description": cells[3]
                    }

                    data.append(result)

        directory = "Mitre Group Json Files"
        try:
            os.makedirs(directory)
        except FileExistsError:
            pass

        with open(os.path.join(directory, "mitre.json"), "w") as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print("Exception:", e)