import re
import ipaddress
import socket

import requests
import whois
import time
import datetime

from bs4 import BeautifulSoup
from googlesearch import search


class Features:

    PHISHING = 1
    NOT_PHISHING = -1
    SUSPICIOUS = 0

    THRESHOLDS = {
        'rank': 100000,
        'google_index': 9,
        'external_links': 5,
    }

    def __init__(self, url):
        self.url = url
        self.domain = self._get_domain()
        self.url_response, self.url_response_bs = self._get_url_response()
        self.whois_response = self._get_whois_response()
        self.rank_check_response = self._get_rank_check_response()
        self.global_rank = self._get_global_rank()
        self.ip_blacklist = self._get_ip_blacklist()

    def get_features(self, with_labels=False):
        if with_labels:
            return {
                'ip': self._check_url_is_ip(),
                'url len': self._check_url_length(),
                'shorting': self._check_shortning(),
                'at symbol': self._check_at_symbol(),
                'double slashing': self._check_double_slashing(),
                'prerfix suffix': self._check_prefix_suffix(),
                'subdomain': self._check_sub_domain(),
                'ssl': self._check_ssl(),
                'reg_len': self._check_reg_len(),
                'favicon': self._check_favicon(),
                'port': self._check_port(),
                'https': self._check_https_token(),
                'internal links': self._check_internal_links(),
                'url anchr': self._check_url_of_anchor(),
                'links in tags': self._checks_links_in_tags(),
                'sfh': self._check_sfh(),
                'mailing': self._check_for_mailing(),
                'abnormal': self._check_abnormal_url(),
                'forwading': self._check_website_forwarding(),
                'status bar': self._check_status_bar_customization(),
                'disable_right': self._check_disable_right_click(),
                'popup': self._check_popup_window(),
                'iframe': self._check_iframe_redirection(),
                'domain age': self._check_domain_age(),
                'dns_record': self._check_dns_record(),
                'traffic': self._check_website_traffic(),
                'pagerank': self._check_pagerank(),
                'index': self._check_google_index(),
                'links': self._check_links_to_page(),
                'stat report': self._check_statistical_report(),
            }

        return [
            self._check_url_is_ip(),
            self._check_url_length(),
            self._check_shortning(),
            self._check_at_symbol(),
            self._check_double_slashing(),
            self._check_prefix_suffix(),
            self._check_sub_domain(),
            self._check_ssl(),
            self._check_reg_len(),
            self._check_favicon(),
            self._check_port(),
            self._check_https_token(),
            # self._check_internal_links(),
            # self._check_url_of_anchor(),
            # self._checks_links_in_tags(),
            # self._check_sfh(),
            self._check_for_mailing(),
            # self._check_abnormal_url(),
            self._check_website_forwarding(),
            self._check_status_bar_customization(),
            self._check_disable_right_click(),
            self._check_popup_window(),
            self._check_iframe_redirection(),
            self._check_domain_age(),
            self._check_dns_record(),
            self._check_website_traffic(),
            self._check_pagerank(),
            self._check_google_index(),
            self._check_links_to_page(),
            self._check_statistical_report(),
        ]

    def _get_domain(self):
        domain = re.findall(r"://([^/]+)/?", self.url)[0]
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
        return domain

    def _get_whois_response(self):
        return whois.query(self.domain)

    def _get_rank_check_response(self):
        return requests.post("https://checkpagerank.net/check-page-rank.php", {
            "name": self.domain
        })

    def _get_global_rank(self):
        try:
            return float(re.findall(r"Global Rank: ([0-9]+)", self.rank_check_response.text)[0])
        except:
            return -1

    def _get_url_response(self):
        response = requests.get(self.url)
        soup = BeautifulSoup(response.text, 'html.parser')
        return response, soup

    def _get_ip_blacklist(self):
        try:
            with open('modules/ml/data/cleantalk_30d.ipset', 'r') as blacklist:
                return blacklist.read()
        except:
            return []

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
        return self.NOT_PHISHING if 'https' in self.url and self.url_response_bs.text != '' else self.PHISHING

    def _check_reg_len(self):
        expiration_date = self.whois_response.expiration_date
        today = datetime.datetime.today()

        expire_in = abs(today - expiration_date)
        return self.PHISHING if expire_in.days / 365 <= 365 else self.NOT_PHISHING

    def _check_favicon(self):
        try:
            return self.NOT_PHISHING if requests.get(f"{self.url}/favicon.ico").content else self.PHISHING
        except:
            return self.PHISHING

    def _check_port(self):
        allowed_ports = ['80', '8080']
        port = self.domain.split(':')

        if len(port) < 2:
            return self.NOT_PHISHING

        return self.PHISHING if port[1] not in allowed_ports else self.NOT_PHISHING

    def _check_https_token(self):
        return self.PHISHING if re.findall(r"^https://", self.domain) or re.findall(r"^http://", self.domain) \
            else self.NOT_PHISHING

    def _check_internal_links(self):
        # Fuck
        return self.PHISHING

    def _check_url_of_anchor(self):
        return self.NOT_PHISHING

    def _checks_links_in_tags(self):
        return self.NOT_PHISHING

    def _check_sfh(self):
        # Fuck
        return self.PHISHING

    def _check_for_mailing(self):
        if not self.url_response.content:
            return self.NOT_PHISHING

        return self.PHISHING if re.findall(r"[mail\(\)|mailto:?]", self.url_response_bs.text) else self.NOT_PHISHING

    def _check_abnormal_url(self):
        # FUCK
        return self.PHISHING

    def _check_website_forwarding(self):
        if not self.url_response_bs:
            return self.NOT_PHISHING

        redirect_count = len(self.url_response.history)

        if redirect_count <= 1:
            return self.NOT_PHISHING
        elif redirect_count > 1 and redirect_count <= 4:
            return self.SUSPICIOUS
        else:
            return self.PHISHING

    def _check_status_bar_customization(self):
        if not self.url_response_bs:
            return self.NOT_PHISHING

        return self.PHISHING if re.findall("<script>.+onmouseover.+</script>", str(self.url_response_bs.text)) else self.NOT_PHISHING

    def _check_disable_right_click(self):
        if not self.url_response_bs:
            return self.NOT_PHISHING

        return self.PHISHING if re.findall(r"event.button ?== ?2", str(self.url_response_bs.text)) else self.NOT_PHISHING

    def _check_popup_window(self):
        if not self.url_response_bs:
            return self.NOT_PHISHING

        return self.PHISHING if re.findall(r"alert\(", str(self.url_response_bs.text)) else self.NOT_PHISHING

    def _check_iframe_redirection(self):
        if not self.url_response_bs:
            return self.NOT_PHISHING

        return self.PHISHING if len(self.url_response_bs.findAll('iframe')) else self.NOT_PHISHING

    def _check_domain_age(self):
        domain = whois.query(self.domain)

        today = datetime.datetime.today()
        created = domain.creation_date

        delta = abs(today - created)

        return self.NOT_PHISHING if delta.days >= 180 else self.PHISHING

    def _check_dns_record(self):
        dns = whois.query(self.domain)
        return self.NOT_PHISHING if dns.last_updated is not None else self.PHISHING

    def _check_website_traffic(self):
        try:
            rank = BeautifulSoup(str(requests.get("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).content),
                                 "lxml").find('reach').attrs['rank']
            return self.NOT_PHISHING if rank < self.THRESHOLDS['rank'] else self.SUSPICIOUS
        except:
            return self.PHISHING

    def _check_pagerank(self):
        return self.PHISHING if self.global_rank < 0.2 else self.NOT_PHISHING

    def _check_google_index(self):
        try:
            site = search(f'{self.url}', 10)
            return self.NOT_PHISHING if len(site) > self.THRESHOLDS['google_index'] else self.PHISHING
        except:
            return self.NOT_PHISHING

    def _check_links_to_page(self):
        try:
            site = search(f'href="{self.url}"', 10)
            return self.NOT_PHISHING if len(site) > self.THRESHOLDS['external_links'] else self.PHISHING
        except:
            return self.NOT_PHISHING

    def _check_statistical_report(self):
        try:
            ip_address = socket.gethostbyname(self.domain)
            return self.PHISHING if ip_address in self.ip_blacklist else self.NOT_PHISHING
        except:
            return self.NOT_PHISHING
