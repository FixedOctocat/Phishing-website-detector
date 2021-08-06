from datetime import datetime
from helpful_functions import *
from urllib.parse import urlparse
from modules.api_module import api
from modules.ml.module import predict
from flask import Flask, render_template, request


app = Flask(__name__, static_folder='static')
app.register_blueprint(api, url_prefix='/api')

@app.route("/", methods=['GET', 'POST'], strict_slashes=False)
def main_page():
    # Function of main page route

    if request.method == 'POST':
        url = request.form.get('url')
        
        if url != '':
            check = urlparse(url)

            if check.scheme != '' and check.netloc != '':
                s = 0

                ping_status = ping(url)

                if ping_status:
                    print('Host up')
                    
                    print('Created: ', end='')
                    
                    create_date = whois(get_ip_from_url(url))
                    print(create_date, end=' ')

                    converted_date = datetime.strptime(create_date, '%Y-%m-%d')
                    datetime_sub = datetime.now() - converted_date
                    time_compare = datetime.strptime('2021-02-15', '%Y-%m-%d') - datetime.strptime('2021-01-01', '%Y-%m-%d')
                    
                    if time_compare < datetime_sub:
                        s += 1
                        print('| ok')
                    else:
                        print('| domain created recently')

                    print('Certificate: ', end="")
                    if check_cert(url):
                        s += 1
                        print('ok')
                    else:
                        print('error')

                    print('favicon.ico: ', end="")
                    if check_favicon(url):
                        s += 1
                        print('ok')
                    else:
                        print('error')

                    print('Google indexing: ', end="")
                    if check_indexing(url):
                        s += 1
                        print('ok')
                    else:
                        print('error')

                    print('Redirecting: ', end="")
                    ans, redirects = check_redirecting(url)
                    if ans:
                        s += 1
                        print('ok')
                    else:
                        print('error', '|', redirects)

                    print('Leet check: ', end="")
                    ans, possible_links = check_leet(url)
                    if ans:
                        s += 1
                        print('ok')
                    else:
                        print('error', '|', possible_links)

                    ans = check_urloip(url)
                    print('IP in URL: ', end="")
                    if ans:
                        s += 1
                        print('ok')
                    else:
                        print('error')

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

                    print('Final score: {}/11'.format(s))
                else:
                    print('Host down')
            else:
                print('Invalid url')
        else:
            print('Invalid url')

    return render_template('main_page.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
