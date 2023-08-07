import requests
from bs4 import BeautifulSoup

def main():
    url = "https://www.enigmasoftware.com/threat-database/"

    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        find_table = soup.find("table", {"class": "top_table"})
        if find_table:
            rows = find_table.find_all("tr")
            for row in rows:
                column = row.find_all("td")
                if column:
                    try:
                        index = column[0].text.strip()
                    except:
                        index = None

                    try:
                        threat_name = column[1].text.strip()
                    except:
                        threat_name = None

                    try:
                        severity = column[2].text.strip()
                    except:
                        severity = None

                    try:
                        alias = column[3].text.strip()
                    except:
                        alias = None

                    try:
                        detection_count = column[4].text.strip()
                    except:
                        detection_count = None

                    print(f"Index: {index}")
                    print(f"Threat Name: {threat_name}")
                    print(f"Severity: {severity}")
                    print(f"Alias: {alias}")
                    print(f"Detection Count: {detection_count}")
                    print("-------------------------------------------------")
        else:
            print("Table not found.")

