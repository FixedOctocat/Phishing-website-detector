from datetime import datetime
from helpful_functions import *
from urllib.parse import urlparse
from modules.api_module import api
from modules.ml.module import predict
from flask import Flask, render_template, request


app = Flask(__name__, static_folder='static')
app.register_blueprint(api, url_prefix='/api')

@app.route("/", methods=['GET'], strict_slashes=False)
def main_page():
    # Function of UI main page route

    if request.method == 'POST':
        url = request.form.get('url')
        
        if url != '':
            check = urlparse(url)

            if check.scheme != '' and check.netloc != '':
                ping_status = ping(url)

                if not ping_status:
                    error = 'Host down'
            else:
                error = 'Invalid url'
        else:
            error = 'Invalid url'

    return render_template('main_page.html', error=error)

@app.route("/res", methods=['GET', 'POST'], strict_slashes=False)
def main_page():
    # Function of UI result page route

    if request.method == 'POST':
        url = request.form.get('url')
        
        if url != '':
            check = urlparse(url)

            if check.scheme != '' and check.netloc != '':
                ping_status = ping(url)

                if not ping_status:
                    error = 'Host down'
                else:
                    data = predict(url)
                    render_template('result.html', data=data)

            else:
                error = 'Invalid url'
        else:
            error = 'Invalid url'

    return render_template('result.html', error=error)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
