import json
import requests
from bs4 import BeautifulSoup

def scarpe_ioc_pulses():
    with open("CTI DB\IOCs\pulses_id.txt", 'r') as file:
        lines = file.read().splitlines() 
        for line in lines:
            j = 1
            while True:
                try:
                    response = requests.get(f'https://otx.alienvault.com/otxapi/pulses/{line}/indicators/?sort=-created&limit=100000000&page={j}')
                    soup = BeautifulSoup(response.content, 'html.parser')
                    json_data = json.loads(soup.prettify())
                    j += 1
                    if json_data['results'] != []:
                        for i in range(len(json_data['results'])):
                            print(json_data['results'][i]['indicator'], json_data['results'][i]['type'])
                    elif json_data['results'] == []:
                        break
                except Exception as e:
                    print("Exception: ", e)
                    break


if __name__ == "__main__":
    scarpe_ioc_pulses()