import requests
import json
from bs4 import BeautifulSoup
import os

def scrape_lib():
    i = 1
    data = []

    while True:
        malpedia_lib = f"https://malpedia.caad.fkie.fraunhofer.de/library/{i}"
        try:
            response = requests.get(malpedia_lib)
            soup = BeautifulSoup(response.text, "html.parser")
            if response.status_code == 200:
                print(f"Malpedia library page {i} found", end="\r", flush=True)
                find_table = soup.find("table", {"class": "table table-dark table-sm"})
                for row in find_table.find_all("tr"):
                    title = row.find('span', class_='title mono-font')
                    url = row['data-href']
                    date = row.find('span', class_='date mono-font')
                    organization = row.find('span', class_='organization mono-font')
                    author = row.find('span', class_='authors mono-font')
                    malware_family = row.find('a', attrs={'data-family_name': True})

                    title_text = title.text if title else "N/A"
                    date_text = date.text if date else "N/A"
                    organization_text = organization.text if organization else "N/A"
                    author_text = author.text if author else "N/A"
                    malware_family_text = malware_family.text.strip() if malware_family else "N/A"

                    entry = {
                        "Title": title_text,
                        "URL": url,
                        "Date": date_text,
                        "Organization": organization_text,
                        "Author": author_text,
                        "Malware Family Group": malware_family_text
                    }

                    data.append(entry)

                i += 1
            else:
                if response.status_code == 404:
                    if "Page not Found" in soup.text:
                        print(f"Completed scraping Malpedia library pages.......")
                        break
        except Exception as e:
            print("Exception:", e)
            break

    directory = "Threat Articles Json Files"
    try:
        os.makedirs(directory)
    except FileExistsError:
        pass

    with open(os.path.join(directory, "threat_article.json"), "w") as file:
        json.dump(data, file, indent=4)



