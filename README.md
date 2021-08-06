![the_best_logo](img/logo.png)
# Phising-website-detector
---
## Useful sites

### Some theory
- https://www.activestate.com/blog/phishing-url-detection-with-python-and-ml/
- https://lib.dr.iastate.edu/cgi/viewcontent.cgi?article=1734&context=etd
- https://meu.edu.jo/libraryTheses/How%20to%20Detect%20Phishing%20Website.pdf
- https://www.youtube.com/watch?v=zKNXHluHneU

### Git reps with good realisation
- https://github.com/npapernot/phishing-detection
- https://github.com/zpettry/AI-Deep-Learning-for-Phishing-URL-Detection
- https://github.com/abhisheksaxena1998/Malicious-Urlv5

### Sites for checking functionality
- SSL check: https://badssl.com/
- Short url: https://clck.ru/ or https://bitly.com/
- Site with phishing urls db: https://phishydomains.com/
- Phishing websites data set: https://archive.ics.uci.edu/ml/datasets/Phishing+Websites#
- Site with good urls: https://www.alexa.com/topsites
- Good sites: https://raw.githubusercontent.com/urbanadventurer/WhatWeb/master/plugin-development/alexa-top-100.txt

### Sites with same ideas
- https://www.urlvoid.com/scan/
---
### Plan
1) Make better frontend
2) More check types
3) Some security measures (can we replace ipwois python library with whois linux util? will be it secure? is it secure now?)
4) Can we connect ML to the project? - I'm too stupid
5) Just test all functions
6) Fix bug in check_redirecting
7) Obrabotka oshibok (try, except)
8) Collect statistics about URL score
---
## Docs
Website have UI (beta) and API

### Run
```
pip3 install -r requirments.txt
python3 app.py
```

### UI
Now we have only one page  
And all output response we can see only on server  
  
![Site UI](img/site_ui_1.png)

### API
In API you can access next functions:  
  
#### Check URL on all functions  
> **path:** /api/check_url  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'error': 'invalid url'}```  - URL incorrect  
>	 ```{'ping': 'host down'}```  - host seems down  
>	 ```{"ping": "Host up", "Created": {{ date }}, ..., "final_score": "7/10"}```  - service checked; in response you get all functions answers and final score of service  
  
#### Checking certificate
> **path:** /api/check_cert  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'check_cert': 'ok'}``` - service is checked and have verified certificate  
>	 ```{'check_cert': 'error'}``` - service is checked and have problems with certificate  
>	 ```{'check_cert': 'server side problem'}``` - service ins't being checked  
  
#### Check indexing by Google
> **path:** /api/check_indexing  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'check_indexing': 'ok'}``` - service checked and is being indexed by Google 
>	 ```{'check_indexing': 'error'}``` -  service checked and isn't being indexed by Google   
  
#### Check redirects
> **path:** /api/check_redirecting  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'check_redirecting': 'ok'}``` - service checked and is being indexed by Google  
>	 ```{{'ans': 'error'}, {'redirects': {{ redirects }} }}``` - service checked and isn't being indexed by Google  
  
#### Check presense of favicon.ico
> **path:** /api/check_favicon  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'check_favicon': 'ok'}``` - service is checked and have favicon.ico  
>	 ```{'check_favicon': 'error'}``` - service ischecked and doesnt have favicon.ico  
  
#### Get creation time
> **path:** /api/whois  
> In POST request you should specify IP  
> Response answers:  
>	 ```{'Created': {{ date }} }``` - time when domain was created  
>    ```{'error': 'invalid ip'}``` - you specified wrong URL  
  
#### Get IP from URL
> **path:** /api/get_ip_from_url  
> In POST request you should specify URL  
> Response answer:  
>	 ```{'get_ip_from_url': {{ ip }} }```  
  
#### Check URL on leet text
> **path:** /api/check_leet  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'check_leet': 'ok'}```  - service is checked and URL doesnt have any leet text  
>	 ```{'check_leet': 'error', 'possible_links': {{ array_of_possible_normal_links }} }``` - service is checked and has leet in URL  

#### Check if URL contains IP
> **path:** /api/check_urloip  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'check_urloip': 'ok' }``` - URL doesnt have ip in it   
>    ```{'check_urloip': 'error'}``` - URL has ip in it  

#### Check if URL contains @ (At symbol)
> **path:** /api/check_at_symbol  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'check_at_symbol': 'ok' }``` - URL doesnt have At symbol   
>    ```{'check_at_symbol': 'error'}``` - URL has At symbol  

#### Check if URL contains subdomain
> **path:** /api/check_sub_domain  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'check_sub_domain': 'ok' }``` - URL doesnt have subdomain   
>    ```{'check_sub_domain': 'error'}``` - URL have subdomain  

#### Check if site redirects to https from http
> **path:** /api/check_https  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'check_https': 'ok' }``` - site redirects to https from http   
>    ```{'check_https': 'error'}``` - site doesn’t redirect to https to http

#### Check site URL length
> **path:** /api/check_url_length  
> In POST request you should specify URL  
> Response answers:  
>	 ```{'check_url_length': 'ok' }``` - site has normal url length   
>    ```{'check_url_length': 'error'}``` - site's url length has an anomaly   
