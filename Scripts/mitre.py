import requests
import json
import os
from bs4 import BeautifulSoup

directory = "CTI DB"
try:
    os.makedirs(directory)
except FileExistsError:
    pass


def scrape_group():
    with open("CTI DB\MITRE\mitre.json", "r") as file:
        mitre = json.load(file)

    output_data = []

    try:
        for row in mitre:
            group_id = row["ID"]
            response = requests.get(
                f"https://attack.mitre.org/groups/{group_id}/{group_id}-enterprise-layer.json"
            )
            if response.status_code == 200:
                data = json.loads(response.text)
                techniques = data["techniques"]
                for technique in techniques:
                    technique_id = technique["techniqueID"]
                    comment = technique.get("comment", "")
                    output_data.append(
                        {
                            "Name": data["name"],
                            "Group ID": group_id,
                            "Technique ID": technique_id,
                            "Comment": comment if comment else None,
                        }
                    )
    except Exception as e:
        print("Exception:", e)

    directory_path = "CTI DB"
    new_folder_name = "MiTRE"
    new_folder_path = os.path.join(directory_path, new_folder_name)
    try:
        os.makedirs(new_folder_path)
    except FileExistsError:
        pass

    with open(os.path.join(new_folder_path, "group.json"), "w") as output_file:
        json.dump(output_data, output_file, indent=4)


def scrape_software():
    with open("CTI DB\MITRE\mitre.json", "r") as file:
        mitre = json.load(file)

    data = []
    try:
        for row in mitre:
            group_id = row["ID"]
            response = requests.get(f"https://attack.mitre.org/groups/{group_id}/")
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                try:
                    table = soup.find(
                        "table", {"class": "table table-bordered table-alternate mt-2"}
                    )

                    for row in table.find("tbody").find_all("tr"):
                        cells = [cell.text.strip() for cell in row.find_all("td")]
                        if len(cells) >= 3:
                            if cells[2] == "":
                                cells[2] = None

                            techniques = [
                                technique.strip() for technique in cells[3].split(",")
                            ]

                            result = {
                                "Group ID": group_id,
                                "Software ID": cells[0],
                                "Name": cells[1] if cells[1] else None,
                                "Techniques": techniques if techniques else None,
                            }

                            data.append(result)

                except Exception as e:
                    result = {
                        "Group ID": group_id,
                        "Software ID": None,
                        "Name": None,
                        "Techniques": None,
                    }
                    data.append(result)
                    pass

                directory_path = "CTI DB"
                new_folder_name = "MITRE"
                new_folder_path = os.path.join(directory_path, new_folder_name)
                try:
                    os.makedirs(new_folder_path)
                except FileExistsError:
                    pass

                with open(os.path.join(new_folder_path, "software.json"), "w") as file:
                    json.dump(data, file, indent=4)
    except Exception as e:
        print("Exception:", e)


def scrape_mitre():
    try:
        response = requests.get("https://attack.mitre.org/groups/")

        data = []

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            table = soup.find(
                "table", {"class": "table table-bordered table-alternate mt-2"}
            )
            for row in table.find("tbody").find_all("tr"):
                cells = [cell.text.strip() for cell in row.find_all("td")]
                if len(cells) >= 3:
                    if cells[2] == "":
                        cells[2] = None

                    result = {
                        "ID": cells[0],
                        "Name": cells[1],
                        "Aliases": cells[2],
                        "Description": cells[3],
                    }

                    data.append(result)

        directory_path = "CTI DB"
        new_folder_name = "MITRE"
        new_folder_path = os.path.join(directory_path, new_folder_name)
        try:
            os.makedirs(new_folder_path)
        except FileExistsError:
            pass

        with open(os.path.join(new_folder_path, "mitre.json"), "w") as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print("Exception:", e)


if __name__ == "__main__":
    scrape_mitre()
    scrape_software()
    scrape_group()
