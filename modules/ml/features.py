import re
import ipaddress
import requests
import whois
import time
import datetime

from bs4 import BeautifulSoup
from datetime import time


class Features:

    PHISHING = -1
    NOT_PHISHING = 1
    SUSPICIOUS = 0

    def __init__(self, url):
        self.url = url
        self.domain = self._get_domain()
        self.url_response = self._get_url_response()
        self.whois_response = self._get_whois_response()
        self.rank_check_response = self._get_rank_check_response()
        self.global_rank = self._get_global_rank()

    def get_features(self):
        features = []
        features.append(self._check_url_is_ip())

        return features

    def _get_domain(self):
        domain = re.findall(r"://([^/]+)/?", self.url)[0]
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
        return domain

    def _get_whois_response(self):
        return whois.query(self.domain)

    def _get_rank_check_response(self):
        return requests.post("https://www.checkpagerank.net/index.php", {
            "name": self.domain
        })

    def _get_global_rank(self):
        try:
            return int(re.findall(r"Global Rank: ([0-9]+)", self.rank_check_response.text)[0])
        except:
            return -1

    def _get_url_response(self):
        response = requests.get(self.url)
        soup = BeautifulSoup(response.text, 'html.parser')
        self.url_response = soup

    def _check_url_is_ip(self):
        try:
            ipaddress.ip_address(self.url)
            ip = self.PHISHING
        except ValueError:
            ip = self.NOT_PHISHING
        return ip

    def _check_url_length(self):
        return self.PHISHING if len(self.url) > 54 else self.NOT_PHISHING

    def _check_shortning(self):
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                              r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                              r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                              r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                              r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                              r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                              r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                              r"tr\.im|link\.zip\.net"
        match = re.search(shortening_services, self.url)
        return self.PHISHING if match else self.NOT_PHISHING

    def _check_at_symbol(self):
        return self.PHISHING if '@' in self.url else self.NOT_PHISHING

    def _check_double_slashing(self):
        list = [x.start(0) for x in re.finditer('//', self.url)]
        return self.PHISHING if list[len(list) - 1] > 6 else self.NOT_PHISHING

    def _check_prefix_suffix(self):
        return self.PHISHING if re.findall(r"https?://[^\-]+-[^\-]+/", self.url) else self.NOT_PHISHING

    def _check_sub_domain(self):
        if len(re.findall("\.", self.url)) == 1:
            return self.NOT_PHISHING
        elif len(re.findall("\.", self.url)) == 2:
            return self.SUSPICIOUS
        else:
            return self.PHISHING

    def _check_ssl(self):
        return self.NOT_PHISHING if 'https' in self.url and self.url_response.text != '' else self.PHISHING

    def _check_reg_len(self):
        expiration_date = self.whois_response.expiration_date
        try:
            expiration_date = min(expiration_date)
            today = time.strftime('%Y-%m-%d')
            today = datetime.strptime(today, '%Y-%m-%d')
            registration_length = abs((expiration_date - today).days)

            if registration_length / 365 <= 1:
                return self.PHISHING
            else:
                return self.NOT_PHISHING
        except:
            return self.NOT_PHISHING

    def _check_favicon(self):
        favicon_url = self.url_response.find('link', rel='shortcut icon')
        favicon_response = requests.get(favicon_url)
        return self.NOT_PHISHING if favicon_response.content else self.PHISHING

    def _check_port(self):
        port = self.domain.split(':')[1]
        return self.PHISHING if port else self.NOT_PHISHING

    def _check_https_token(self):
        return self.NOT_PHISHING if re.findall(r"^https://", self.url) else self.PHISHING

        def _check_links_pointing_to_page(self):
        if response == "":
            return self.SUSPICIOUS
        else:
            number_of_links = len(re.findall(r"<a href=", response.text))
            if number_of_links == 0:
                return self.NOT_PHISHING
            elif number_of_links <= 2:
                return self.PHISHING
            else:
                return self.PHISHING

    #suka
    def _check_google_indexing(self):
        site=search(url, 5)
        if site:
            return self.PHISHING
        else:
            return self.NOT_PHISHING

    #suka
    def _check_global_rank(self):
        try:
            if self.global_rank > 0 and self.global_rank < 100000:
                return self.NOT_PHISHING
            else:
                return self.PHISHING
        except:
            return self.PHISHING

    #suka
    def _check_web_traffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
            rank= int(rank)
            if (rank < 100000):
                return self.PHISHING
            else:
                return self.SUSPICIOUS
        except TypeError:
            return self.NOT_PHISHING

    def _check_dns_record(self):
        dns = 1
        try:
            _ = whois.whois(domain)
        except:
            dns = -1
        
        if dns == -1:
            return self.NOT_PHISHING
        else:
            if registration_length / 365 <= 1:
                return self.NOT_PHISHING
            else:
                return self.PHISHING

    def _check_popUpWidnow(self):
        if response == "":
            return self.NOT_PHISHING
        else:
            if re.findall(r"alert\(", response.text):
                return self.PHISHING
            else:
                return self.PHISHING

    def _check_RightClick(self):
        if self.response == "":
            return self.NOT_PHISHING
        else:
            if re.findall(r"event.button ?== ?2", response.text):
                return self.PHISHING
            else:
                return self.NOT_PHISHING

    def _check_on_mouseover(self):
        if response == "" :
            return self.NOT_PHISHING
        else:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                return self.PHISHING
            else:
                return self.NOT_PHISHING

    def _check_redirect(self):
        if response == "":
            return self.NOT_PHISHING
        else:
            if len(response.history) <= 1:
                return self.NOT_PHISHING
            elif len(response.history) <= 4:
                return self.SUSPICIOUS
            else:
                return self.PHISHING

    def _check_abnormal_URL(self):
        if response == "":
            return self.NOT_PHISHING
        else:
            if response.text == "":
                return self.PHISHING
            else:
                return self.NOT_PHISHING

    def _check_email_submiting(self):
        if response == "":
            return self.NOT_PHISHING
        else:
            if re.findall(r"[mail\(\)|mailto:?]", response.text):
                return self.PHISHING
            else:
                return self.NOT_PHISHING

    def _check_sfh(self):
        for form in soup.find_all('form', action= True):
           if form['action'] =="" or form['action'] == "about:blank" :
              return self.NOT_PHISHIN
           elif url not in form['action'] and domain not in form['action']:
               return self.SUSPICIOUS
           else:
                 return self.PHISHING

    def _checl_links_in_tags(self):
        i=0
        success =0
        if soup == -999:
            data_set.append(-1)
        else:
            for link in soup.find_all('link', href= True):
               dots=[x.start(0) for x in re.finditer('\.',link['href'])]
               if url in link['href'] or domain in link['href'] or len(dots)==1:
                  success = success + 1
               i=i+1

            for script in soup.find_all('script', src= True):
               dots=[x.start(0) for x in re.finditer('\.',script['src'])]
               if url in script['src'] or domain in script['src'] or len(dots)==1 :
                  success = success + 1
               i=i+1
            try:
                percentage = success / float(i) * 100
            except:
                return self.PHISHING

            if percentage < 17.0 :
               return self.PHISHING
            elif((percentage >= 17.0) and (percentage < 81.0)) :
               return self.SUSPICIOUS
            else :
               return self.NOT_PHISHING

    def _check_anchors(self):
        percentage = 0
        i = 0
        unsafe=0
        if soup == -999:
            data_set.append(-1)
        else:
            for a in soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1


            try:
                percentage = unsafe / float(i) * 100
            except:
                return self.PHISHING

            if percentage < 31.0:
                return self.PHISHING
            elif ((percentage >= 31.0) and (percentage < 67.0)):
                return self.SUSPICIOUS
            else:
                return self.NOT_PHISHING

    def _check_request_url(self):
        i = 0
        success = 0
        if soup == -999:
            return self.NOT_PHISHING
        else:
            for img in soup.find_all('img', src= True):
               dots= [x.start(0) for x in re.finditer('\.', img['src'])]
               if url in img['src'] or domain in img['src'] or len(dots)==1:
                  success = success + 1
               i=i+1

            for audio in soup.find_all('audio', src= True):
               dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
               if url in audio['src'] or domain in audio['src'] or len(dots)==1:
                  success = success + 1
               i=i+1

            for embed in soup.find_all('embed', src= True):
               dots=[x.start(0) for x in re.finditer('\.',embed['src'])]
               if url in embed['src'] or domain in embed['src'] or len(dots)==1:
                  success = success + 1
               i=i+1

            for iframe in soup.find_all('iframe', src= True):
               dots=[x.start(0) for x in re.finditer('\.',iframe['src'])]
               if url in iframe['src'] or domain in iframe['src'] or len(dots)==1:
                  success = success + 1
               i=i+1

            try:
               percentage = success/float(i) * 100
               if percentage < 22.0 :
                  return self.PHISHING
               elif((percentage >= 22.0) and (percentage < 61.0)) :
                  return self.SUSPICIOUS
               else :
                  return self.NOT_PHISHING
            except:
                return self.PHISHING
