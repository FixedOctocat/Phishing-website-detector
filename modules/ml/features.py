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




#
#     def
#     #12. HTTPS_token
#     if :
#         data_set.append(1)
#     else:
#         data_set.append(-1)
#
#     #13. Request_URL
#     i = 0
#     success = 0
#     if soup == -999:
#         data_set.append(-1)
#     else:
#         for img in soup.find_all('img', src= True):
#            dots= [x.start(0) for x in re.finditer('\.', img['src'])]
#            if url in img['src'] or domain in img['src'] or len(dots)==1:
#               success = success + 1
#            i=i+1
#
#         for audio in soup.find_all('audio', src= True):
#            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
#            if url in audio['src'] or domain in audio['src'] or len(dots)==1:
#               success = success + 1
#            i=i+1
#
#         for embed in soup.find_all('embed', src= True):
#            dots=[x.start(0) for x in re.finditer('\.',embed['src'])]
#            if url in embed['src'] or domain in embed['src'] or len(dots)==1:
#               success = success + 1
#            i=i+1
#
#         for iframe in soup.find_all('iframe', src= True):
#            dots=[x.start(0) for x in re.finditer('\.',iframe['src'])]
#            if url in iframe['src'] or domain in iframe['src'] or len(dots)==1:
#               success = success + 1
#            i=i+1
#
#         try:
#            percentage = success/float(i) * 100
#            if percentage < 22.0 :
#               dataset.append(1)
#            elif((percentage >= 22.0) and (percentage < 61.0)) :
#               data_set.append(0)
#            else :
#               data_set.append(-1)
#         except:
#             data_set.append(1)
#
#
#
#     #14. URL_of_Anchor
#     percentage = 0
#     i = 0
#     unsafe=0
#     if soup == -999:
#         data_set.append(-1)
#     else:
#         for a in soup.find_all('a', href=True):
#         # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and :: might not be
#                 # there in the actual a['href']
#             if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
#                 unsafe = unsafe + 1
#             i = i + 1
#
#
#         try:
#             percentage = unsafe / float(i) * 100
#         except:
#             data_set.append(1)
#
#         if percentage < 31.0:
#             data_set.append(1)
#         elif ((percentage >= 31.0) and (percentage < 67.0)):
#             data_set.append(0)
#         else:
#             data_set.append(-1)
#
#     #15. Links_in_tags
#     i=0
#     success =0
#     if soup == -999:
#         data_set.append(-1)
#     else:
#         for link in soup.find_all('link', href= True):
#            dots=[x.start(0) for x in re.finditer('\.',link['href'])]
#            if url in link['href'] or domain in link['href'] or len(dots)==1:
#               success = success + 1
#            i=i+1
#
#         for script in soup.find_all('script', src= True):
#            dots=[x.start(0) for x in re.finditer('\.',script['src'])]
#            if url in script['src'] or domain in script['src'] or len(dots)==1 :
#               success = success + 1
#            i=i+1
#         try:
#             percentage = success / float(i) * 100
#         except:
#             data_set.append(1)
#
#         if percentage < 17.0 :
#            data_set.append(1)
#         elif((percentage >= 17.0) and (percentage < 81.0)) :
#            data_set.append(0)
#         else :
#            data_set.append(-1)
#
#         #16. SFH
#         for form in soup.find_all('form', action= True):
#            if form['action'] =="" or form['action'] == "about:blank" :
#               data_set.append(-1)
#               break
#            elif url not in form['action'] and domain not in form['action']:
#                data_set.append(0)
#                break
#            else:
#                  data_set.append(1)
#                  break
#
#     #17. Submitting_to_email
#     if response == "":
#         data_set.append(-1)
#     else:
#         if re.findall(r"[mail\(\)|mailto:?]", response.text):
#             data_set.append(1)
#         else:
#             data_set.append(-1)
#
#     #18. Abnormal_URL
#     if response == "":
#         data_set.append(-1)
#     else:
#         if response.text == "":
#             data_set.append(1)
#         else:
#             data_set.append(-1)
#
#     #19. Redirect
#     if response == "":
#         data_set.append(-1)
#     else:
#         if len(response.history) <= 1:
#             data_set.append(-1)
#         elif len(response.history) <= 4:
#             data_set.append(0)
#         else:
#             data_set.append(1)
#
#     #20. on_mouseover
#     if response == "" :
#         data_set.append(-1)
#     else:
#         if re.findall("<script>.+onmouseover.+</script>", response.text):
#             data_set.append(1)
#         else:
#             data_set.append(-1)
#
#     #21. RightClick
#     if response == "":
#         data_set.append(-1)
#     else:
#         if re.findall(r"event.button ?== ?2", response.text):
#             data_set.append(1)
#         else:
#             data_set.append(-1)
#
#     #22. popUpWidnow
#     if response == "":
#         data_set.append(-1)
#     else:
#         if re.findall(r"alert\(", response.text):
#             data_set.append(1)
#         else:
#             data_set.append(-1)
#
# def _check_for_iframe(url):
#     response = _get_url_response(url)
#
#     if response == '':
#         return 0
#
#     return int(re.findall(r"[<iframe>|<frameBorder>]", response.text))
#
#     #24. age_of_domain
#     if response == "":
#         data_set.append(-1)
#     else:
#         try:
#             registration_date = re.findall(r'Registration Date:</div><div class="df-value">([^<]+)</div>', whois_response.text)[0]
#             if diff_month(date.today(), date_parse(registration_date)) >= 6:
#                 data_set.append(-1)
#             else:
#                 data_set.append(1)
#         except:
#             data_set.append(1)
#
#     #25. DNSRecord
#     dns = 1
#     try:
#         d = whois.whois(domain)
#     except:
#         dns=-1
#     if dns == -1:
#         data_set.append(-1)
#     else:
#         if registration_length / 365 <= 1:
#             data_set.append(-1)
#         else:
#             data_set.append(1)
#
#     #26. web_traffic
#     try:
#         rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
#         rank= int(rank)
#         if (rank<100000):
#             data_set.append(1)
#         else:
#             data_set.append(0)
#     except TypeError:
#         data_set.append(-1)
#
#     #27. Page_Rank
#     try:
#         if global_rank > 0 and global_rank < 100000:
#             data_set.append(-1)
#         else:
#             data_set.append(1)
#     except:
#         data_set.append(1)
#
#     #28. Google_Index
#     site=search(url, 5)
#     if site:
#         data_set.append(1)
#     else:
#         data_set.append(-1)
#
#     #29. Links_pointing_to_page
#     if response == "":
#         data_set.append(-1)
#     else:
#         number_of_links = len(re.findall(r"<a href=", response.text))
#         if number_of_links == 0:
#             data_set.append(1)
#         elif number_of_links <= 2:
#             data_set.append(0)
#         else:
#             data_set.append(-1)
#
#     #30. Statistical_report
#     url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
#     try:
#         ip_address=socket.gethostbyname(domain)
#         ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
#                            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
#                            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
#                            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
#                            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
#                            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)
#         if url_match:
#             data_set.append(-1)
#         elif ip_match:
#             data_set.append(-1)
#         else:
#             data_set.append(1)
#     except:
#         print ('Connection problem. Please check your internet connection!')
