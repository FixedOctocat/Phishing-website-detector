from IPy import IP
from datetime import datetime
from urllib.parse import urlparse
from flask import Blueprint, request
from json import dumps
from helpful_functions import *


api = Blueprint('api', __name__)

@api.route('/check_url', methods=['POST'], strict_slashes=False)
def route_check_url():
    # API function which checks
    # URL by every check function
    # available at the moment

    if request.method == 'POST':
        res = {}
        url = request.form.get('url')
        
        if url != '':
            check = urlparse(url)

            if check.scheme != '' and check.netloc != '':
                s = 0

                ping_status = ping(url)

                if ping_status:
                    res['ping'] = 'host up'
                    
                    create_date = whois(get_ip_from_url(url))
                    res['Created'] = create_date

                    converted_date = datetime.strptime(create_date, '%Y-%m-%d')
                    datetime_sub = datetime.now() - converted_date
                    time_compare = datetime.strptime('2021-02-15', '%Y-%m-%d') - datetime.strptime('2021-01-01', '%Y-%m-%d')
                    
                    if time_compare < datetime_sub:
                        s += 1

                    cert = check_cert(url)
                    if cert == True:
                        s += 1
                        res['check_cert'] = 'ok'
                    elif cert == False:
                        res['check_cert'] = 'error'
                    elif cert == None:
                        res['check_cert'] = 'server side problem'

                    if check_favicon(url):
                        s += 1
                        res['check_favicon'] = 'ok'
                    else:
                        res['check_favicon'] = 'error'

                    if check_indexing(url):
                        s += 1
                        res['check_indexing'] = 'ok'
                    else:
                        res['check_indexing'] = 'error'

                    ans, redirects = check_redirecting(url)
                    if ans:
                        s += 1
                        res['check_redirecting'] = 'ok'
                    else:
                        res['check_redirecting'] = [{'ans': 'error'}, {'redirects': redirects}]

                    ans, possible_links = check_leet(url)
                    if ans:
                        s += 1
                        res['check_leet'] = 'ok'
                    else:
                        res['check_leet'] = [{'ans': 'error'}, {'possible_links': possible_links}]

                    ans = check_urloip(url)
                    if ans:
                        s += 1
                        res['check_urloip'] = 'ok'
                    else:
                        res['check_urloip'] = 'error'

                    ans = check_at_symbol(url)
                    print('At symbol checking: ', end="")
                    if ans:
                        s += 1
                        print('ok')
                    else:
                        print('error')

                    ans = check_sub_domain(url)
                    print('Sub domains in URL: ', end="")
                    if ans:
                        s += 1
                        print('ok')
                    else:
                        print('error')

                    ans = check_url_length(url)
                    print('URL length: ', end="")
                    if ans:
                        s += 1
                        print('ok')
                    else:
                        print('error')

                    ans = check_https(url)
                    print('Redirect to https from http: ', end="")
                    if ans:
                        s += 1
                        print('ok')
                    else:
                        print('error')


                    res['final_score'] = '{}/11'.format(s)
                else:
                    res['ping'] = 'host down'
            else:
                res['error'] = 'invalid url'
        else:
            res['error'] = 'invalid url'

    print(res)
    return dumps(res)

@api.route('/check_cert', methods=['POST'], strict_slashes=False)
def route_check_cert():
    # API function which
    # checks URL for certificate

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)
        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}

        ans = check_cert(url)

        if ans == True:
            return {'check_cert': 'ok'}
        elif ans == False:
            return {'check_cert': 'error'}
        elif ans == None:
            return {'check_cert': 'server side problem'}

@api.route('/check_indexing', methods=['POST'], strict_slashes=False)
def route_check_indexing():
    # API function which allows
    # you to check if this URL
    # is indexed by Google

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)
        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}
        
        ans = check_indexing(url)

        if ans == True:
            return {'check_indexing': 'ok'}
        elif ans == False:
            return {'check_indexing': 'error'}

@api.route('/check_redirecting', methods=['POST'], strict_slashes=False)
def route_check_redirecting():
    # API function which
    # looks for redirect's route

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)
        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}

        ans, redirects = check_redirecting(url)

        if ans == True:
            return {'check_redirecting': 'ok'}
        elif ans == False:
            return {{'ans': 'error'}, {'redirects': redirects}}

@api.route('/check_favicon', methods=['POST'], strict_slashes=False)
def route_check_favicon():
    # API function which
    # ckecks presents of favicon.ico

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)
        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}

        ans = check_favicon(url)

        if ans == True:
            return {'check_favicon': 'ok'}
        elif ans == False:
            return {'check_favicon': 'error'}

@api.route('/whois', methods=['POST'], strict_slashes=False)
def route_whois():
    # API function which allows
    # you to find out registration date

    if request.method == 'POST':
        ip = request.form.get('ip')
        try:
            check = IP(ip)
            ans = whois(ip)

            return {'Created': ans}
        except:
            return {'error': 'specified wrong ip'}

@api.route('/get_ip_from_url', methods=['POST'], strict_slashes=False)
def route_get_ip_from_url():
    # API function which allows
    # you to get IP from URL

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)
        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}

        ans = get_ip_from_url(url)

        return {'get_ip_from_url': ans}

@api.route('/check_leet', methods=['POST'], strict_slashes=False)
def route_check_leet():
    # API function which allows
    # you to find out if URL
    # contains leet alphabet

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)

        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}

        ans, possible_links = check_leet(url)

        if ans:
            return {'check_leet': 'ok'}
        else:
            return {'check_leet': 'error', 'possible_links': possible_links}

@api.route('/check_urloip', methods=['POST'], strict_slashes=False)
def route_check_urloip():
    # API function which check
    # if the string is URL or IP

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)

        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}

        ans = check_urloip(url)

        if ans:
            return {'check_urloip': 'ok'}
        else:
            return {'check_urloip': 'error'}

@api.route('/check_at_symbol', methods=['POST'], strict_slashes=False)
def route_check_at_symbol():
    # API function which allows you
    # to find At symbol at URL

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)

        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}

        ans = check_at_symbol(url)

        if ans:
            return {'check_at_symbol': 'ok'}
        else:
            return {'check_at_symbol': 'error'}

@api.route('/check_sub_domain', methods=['POST'], strict_slashes=False)
def route_check_sub_domain():
    # API function which allows you to
    # find out if URL contains subdomain

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)

        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}

        ans = check_sub_domain(url)

        if ans:
            return {'check_sub_domain': 'ok'}
        else:
            return {'check_sub_domain': 'error'}

@api.route('/check_https', methods=['POST'], strict_slashes=False)
def route_check_https():
    # API function which allows
    # you to check if this URL
    # redirects from http to https

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)

        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}

        ans = check_https(url)

        if ans:
            return {'check_https': 'ok'}
        else:
            return {'check_https': 'error'}

@api.route('/check_url_length', methods=['POST'], strict_slashes=False)
def route_check_url_length():
    # API function which allows
    # you to check the length of an URL

    if request.method == 'POST':
        url = request.form.get('url')
        check = urlparse(url)

        if not (check.scheme != '' and check.netloc != ''):
            return {'error': 'invalid url'}

        ans = check_https(url)

        if ans:
            return {'check_url_length': 'ok'}
        else:
            return {'check_url_length': 'error'}


if __name__ == "__main__":
    print(check_redirecting('https://bit.ly/3yohRFK'))
