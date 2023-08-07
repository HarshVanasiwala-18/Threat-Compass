import pandas as pd
import feedparser
from bs4 import BeautifulSoup
import requests
from datetime import datetime
import json
import os

directory = "CTI DB"
try:
    os.makedirs(directory)
except FileExistsError:
    pass


news_provider = {
    "https://www.securityweek.com/feed/": "Security Week",
    "https://www.darkreading.com/rss.xml": "Dark Reading",
    "https://threatpost.com/feed/": "Threat Post",
    "https://krebsonsecurity.com/feed/": "Krebs on Security",
    "https://feeds.feedburner.com/TheHackersNews": "The Hacker News",
    "https://nakedsecurity.sophos.com/feed/": "Naked Security",
}

news_data = []
cve_data = []


def news_scraper(news):
    try:
        feed = feedparser.parse(news)
        entries = feed.entries
        for post in entries:
            try:
                soup = BeautifulSoup(post.summary, "html.parser")
                summary_text = soup.get_text()
                timestamp = post.published.split("+")[0].strip()
                date_obj = datetime.strptime(timestamp, "%a, %d %b %Y %H:%M:%S")
                date_str = date_obj.strftime("%Y-%m-%d")
                time_str = date_obj.strftime("%H:%M:%S")
                entry = {
                    "Title": post.title,
                    "Link": post.link,
                    "Date": date_str,
                    "Time": time_str,
                    "Summary": summary_text,
                }
                news_data.append(entry)
            except:
                try:
                    timestamp = post.published.split("+")[0].strip()
                    date_obj = datetime.strptime(timestamp, "%a, %d %b %Y %H:%M:%S")
                    date_str = date_obj.strftime("%Y-%m-%d")
                    time_str = date_obj.strftime("%H:%M:%S")
                    entry = {
                        "Title": post.title,
                        "Link": post.link,
                        "Date": date_str,
                        "Time": time_str,
                        "Summary": post.summary,
                    }
                    news_data.append(entry)
                except Exception as e:
                    print("Exception:", e)
    except:
        try:
            feed = feedparser.parse(news)
            entries = feed.entries
            for post in entries:
                try:
                    timestamp = post.published.split("+")[0].strip()
                    date_obj = datetime.strptime(timestamp, "%a, %d %b %Y %H:%M:%S")
                    date_str = date_obj.strftime("%Y-%m-%d")
                    time_str = date_obj.strftime("%H:%M:%S")
                    entry = {
                        "Title": post.title,
                        "Link": post.link,
                        "Date": date_str,
                        "Time": time_str,
                        "Summary": post.summary,
                    }
                    news_data.append(entry)
                except:
                    try:
                        timestamp = post.published.split("+")[0].strip()
                        date_obj = datetime.strptime(timestamp, "%a, %d %b %Y %H:%M:%S")
                        date_str = date_obj.strftime("%Y-%m-%d")
                        time_str = date_obj.strftime("%H:%M:%S")
                        entry = {
                            "Title": post.title,
                            "Link": post.link,
                            "Date": date_str,
                            "Time": time_str,
                            "Summary": post.summary,
                        }
                        news_data.append(entry)
                    except Exception as e:
                        print("Exception:", e)
        except Exception as e:
            print("Exception: ", e)


def cve_scraper():
    try:
        content = requests.get("https://cve.circl.lu/api/last")
        if content.status_code == 200:
            json_data = content.json()
    except Exception as e:
        print("Exception: ", e)

    try:
        for cve_details in json_data:
            cve_id = cve_details["id"]
            cve_score = cve_details["cvss"] if cve_details["cvss"] else None
            cve_published = cve_details["Published"].split("T")[0]
            cve_published_time = cve_details["Published"].split("T")[1]
            cve_modified = cve_details["Modified"].split("T")[0]
            cve_modified_time = cve_details["Modified"].split("T")[1]
            cve_description = cve_details["summary"].replace("\n", "")
            cve_references_str = ",".join(cve_details["references"])
            entry = {
                "CVE ID": cve_id,
                "CVSS Score": cve_score,
                "Published Date": cve_published,
                "Published Time": cve_published_time,
                "Modified Date": cve_modified,
                "Modified Time": cve_modified_time,
                "Description": cve_description,
                "References": cve_references_str,
            }
            cve_data.append(entry)
    except Exception as e:
        print("Exception: ", e)


def main():
    try:
        print("Scraping Cyber news...")
        for news in news_provider:
            news_scraper(news)
        try:
            print("Scraping CVEs...")
            cve_scraper()
            print("Scraping completed.")
        except Exception as e:
            print("Exception: ", e)
    except Exception as e:
        print("Exception: ", e)

    directory_path = "CTI DB"
    new_folder_name = "News and CVEs"
    new_folder_path = os.path.join(directory_path, new_folder_name)
    try:
        os.makedirs(new_folder_path)
    except FileExistsError:
        pass

    with open(os.path.join(new_folder_path, "news.json"), "w") as file:
        json.dump(news_data, file, indent=4)

    with open(os.path.join(new_folder_path, "cve.json"), "w") as file:
        json.dump(cve_data, file, indent=4)


