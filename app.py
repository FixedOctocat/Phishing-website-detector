from datetime import datetime
from urllib.parse import urlparse
from modules.api.module import api
from modules.ml.model import predict, build_features
from modules.api.helpful_functions import ping
from flask import Flask, render_template, request


app = Flask(__name__, static_folder='static')
app.register_blueprint(api, url_prefix='/api')

@app.route("/", methods=['GET'], strict_slashes=False)
def main_page():
    # Function of UI main page route

    return render_template('main_page.html')

@app.route("/res", methods=['GET', 'POST'], strict_slashes=False)
def res_page():
    # Function of UI result page route

    if request.method == 'POST':
        try:
            url = request.form.to_dict(flat=False)['url'][0]
        except:
            error = 'Specify url'
        
        if url != '':
            check = urlparse(url)

            if check.scheme != '' and check.netloc != '':
                ping_status = ping(url)

                if ping_status:
                    features = build_features(url)

                    detailed = predict(url, features)
                    detailed = features.get_features()
                    checks = """["URL contains IP"
                                "URL's length check"
                                "Is shortning present"
                                "Is At symbol present"
                                "Redirecting using '//'"
                                "If prefix or suffix separated by -"
                                "If subdomain  is present"
                                "If ssl is present"
                                "For how long domain is registred"
                                "Is favicon  present"
                                "Is port is non-standart"
                                "Is https tokein is present in the domain"
                                "Are internal links leading to another domain"
                                "If the anchor and the website have different domain names/If anchor doesnt link to any webpage"
                                "If links in tags lead to a same domain"
                                "If contains sfh"
                                "If personal information is directed to a server or to an external email"
                                "If URL is in WHOIS database"
                                "If site redirects more than once"
                                "If status bar changes or not"
                                "If right click is disabled or not"
                                "Is pop-up window is present"
                                "Does site use Iframe or not"
                                "If domain is older than 6 month or not"
                                "Is there DNS record for a website or not"
                                "If website traffic is lower than 100000"
                                "If pageRank is lower than 0.2 or not"
                                "Is website is indexed by google or not"
                                "Are there any links leading to a website"
                                "Is host is on Top Phishing IP's rank or not"]""".split('\n')

                    if detailed == Features.PHISHING:
                        status = 'phishing'
                    elif detailed == Features.NOT_PHISHING:
                        status = 'not_phishing'

                    return render_template('result.html', status=ans, checks=checks, detailed=detailed)
                else:
                    error = 'Host down'

            else:
                error = 'Invalid url'
        else:
            error = 'Invalid url'

        return render_template('result.html', error=error)
    elif request.method == 'GET':
        return render_template('result.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
