import latest_cyber_news
import threat_article
import threat_actor
import malware

if __name__ == "__main__":
    latest_cyber_news.main()
    threat_article.scrape_lib()
    threat_actor.scrape_threat_actor()
    malware.scrape_malware()