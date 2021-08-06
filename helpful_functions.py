import requests
from IPy import IP
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import urllib.request as urllib2
from socket import gethostbyname
from urllib.parse import urlparse
from urllib.parse import urlencode

def check_at_symbol(url):
    # Function which allows you
    # to find At symbol at URL

    for smb in url:
        if smb == '@':
            return False

    return True

def check_urloip(url):
    # Function which allows you to
    # check if the string is URL or IP

    check = urlparse(url)
    check = check.netloc
    check = check[0:check.find(':')]

    try:
        IP(check)

        return False
    except:
        return True

def check_cert(url):
    # Function which allows you
    # to check certificate
    
    url = urlparse(url)
    url = url.scheme + '://' + url.netloc

    req = urllib2.Request(url, headers={'User-Agent':'Mozilla/5.0'})

    try:
        urllib2.urlopen(req)
    except Exception as e:
        if 'certificate' in str(e):
            return False

        print("Error while checking cert: ", e)
        return None
    
    return True

def check_indexing(url):
    # Function which allows you to
    # check if Google indexes URL

    url = urlparse(url).netloc

    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = {'User-Agent': user_agent}
    query = {'q': 'info:' + url}
    google = "https://www.google.com/search?" + urlencode(query)
    
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    
    soup = BeautifulSoup(str(data.content), "html.parser")
    hrefs = soup.find_all("div", class_="BNeawe UPmit AP7Wnd")[0:4]

    for href in hrefs:
        if url in href.contents[0]:
            return True

    return False

def check_redirecting(url):
    # Function which allows you to
    # check if this URL redirects
    # to another site or not and if
    # it does shows path of redirect

    responses = requests.get(url)
    res = []

    urlparse_1 = urlparse(url)

    for response in responses.history:
        res.append(response.url)

    if len(res) != 0:
        urlparse_2 = urlparse(res[len(res) - 1])

        if urlparse_1.netloc != urlparse_2.netloc:
            return False, res

        if urlparse_1.scheme == urlparse_2.scheme:
            return False, res

    return True, []

def check_favicon(url):
    # Function which allows you to
    # check if there is a favicon.ico

    url = urlparse(url)
    url = url.scheme + '://' + url.netloc

    res = requests.get(url+'/favicon.ico').status_code

    if res == 200:
        return True
    else:
        return False

def get_ip_from_url(url):
    # Function which allows you
    # to get IP from URL

    url = urlparse(url).netloc
    ip = gethostbyname(url)
    
    return ip

def whois(ip):
    # Function which allows you to
    # find out domain's registration date

    obj = IPWhois(ip)
    res=obj.lookup_whois()

    return res['nets'][0]['created'][0:10]

def ping(url):
    # Function which allows you
    # to find out if host is up or down

    try:
        requests.get(url)
    except requests.exceptions.ConnectionError:
        return False

    return True

def check_leet(url):
    # Function which allows you
    # to find out if URL contains
    # leet alphabet 

    url = urlparse(url).netloc
    leet_alph = {0: ['o'], 1: ['i', 'l'], 3: ['e'], 4: ['a'], 5: ['s'], 6: ['g'], 7: ['t'], 8: ['b'], 9: ['g']}

    posible_links = ['']
    flag = True
    leet_count = 0
    for i in url:
        if i.isdigit():
            flag = False

            posible_links_ = []
            for link in posible_links:
                for let in leet_alph[int(i)]:
                    posible_links_.append(link + let)
            
            posible_links = posible_links_
        else:
            for link_id in range(0, len(posible_links)):
                posible_links[link_id] += i

    if len(posible_links) < 2:
        return True, []

    return False, posible_links

def check_sub_domain(url):
    # Function which allows you to
    # find out if URL contains subdomain

    c = 0

    for i in url:
        if i == '.':
            c += 1

    if c == 1:
        return True
    else:
        return False

def check_url_length(url):
    # This function allows you
    # to check the length of an URL

    url = urlparse(url).netloc

    if len(url) < 25:
        return True
    else:
        return False

def check_https(url):
    # This function allows you to
    # check if URL redirects you
    # from http to https

    res = []

    urlparse_1 = urlparse(url)
    url = 'http://'+urlparse_1.netloc
    responses = requests.get(url)

    for response in responses.history:
        res.append(response.url)

    if len(res) != 0:
        urlparse_2 = urlparse(res[len(res) - 1])

        if urlparse_1.netloc == urlparse_2.netloc:
            if urlparse_2.scheme != urlparse_1.scheme:
                return True

    return False


if __name__ == "__main__":
    print(check_redirecting('https://bit.ly/2TXjRWB'))
