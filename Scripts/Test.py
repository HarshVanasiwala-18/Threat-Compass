import requests
from bs4 import BeautifulSoup

resp = requests.get("https://malpedia.caad.fkie.fraunhofer.de/details/win.404keylogger")
soup = BeautifulSoup(resp.text, "html.parser")

yara_signature_found = False

for row in soup.find_all("pre"):
    text = row.text
    if not text:
        print("No Yara Signature Found")
        yara_signature_found = True
        break

if not yara_signature_found:
    print("Yara Signature Found")
