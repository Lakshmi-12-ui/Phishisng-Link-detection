import os
import pandas as pd

from flask import Flask, request, jsonify
import pickle
from xgboost import XGBClassifier

app = Flask(__name__)

from urllib.parse import urlparse, urlencode
import ipaddress
import re


def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip


def haveAtSign(url):
    if "@" in url:
        at = 1
    else:
        at = 0
    return at


def getLength(url):
    length = len(url)
    return length



def getDepth(url):
    s = urlparse(url).path
    depth = 0
    for i in s:
        if i == '/':
            depth = depth + 1
    return depth



def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0



def httpDomain(url):
    domain = url

    if 'https' in domain:
        return 0
    else:
        return 1
    # return 1



shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"



def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0



def prefixSuffix(url):
    if '-' in url:
        return 1  # phishing
    else:
        return 0  # legitimate



import re
from bs4 import BeautifulSoup # web scraping and parsing HTML and XML documents
import whois #The WHOIS library is a Python module that provides functionality to retrieve WHOIS information for domain names
import urllib
import urllib.request # It includes the urlopen function for opening URLs, the urlretrieve function for retrieving URLs to a local file, and other functions for handling URLs.
from datetime import datetime


def web_traffic(url):
    try:
        # Filling the whitespaces in the URL if any
        url = urllib.parse.quote(url)
        rank = \
        BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
            "REACH")['RANK']
        rank = int(rank)
    except TypeError:
        return 1
    if rank < 100000:
        return 1
    else:
        return 0



def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            # print("Except")
            return 1
    if ((expiration_date is None) or (creation_date is None)):
        # print("if")
        return 1
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        # print("elif")
        if (type(creation_date) is list):
            creation_date = creation_date[0]
        if (type(expiration_date) is list):
            expiration_date = expiration_date[0]

        ageofdomain = abs((expiration_date - creation_date).days)
        if ((ageofdomain / 30) < 6):
            age = 1
        else:
            age = 0
        return age
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if ((ageofdomain / 30) < 6):
            age = 1
        else:
            age = 0
    return age



def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if (expiration_date is None):
        return 1
    elif (type(expiration_date) is list):
        expiration_date = expiration_date[0]
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if ((end / 30) < 6):
            end = 1
        else:
            end = 0
        return end
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if ((end / 30) < 6):
            end = 1
        else:
            end = 0
    return end



import requests


def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1



def mouseOver(response):
    if response == "":
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0



def rightClick(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1



def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1




def getNumberOfDots(url):
    s = url
    NumberOfDots = 0
    for i in s:
        if i == '.':
            NumberOfDots = NumberOfDots + 1
    return NumberOfDots


def getNumberOfAnd(url):
    s = url
    NumberOfAnds = 0
    for i in s:
        if i == '&':
            NumberOfAnds = NumberOfAnds + 1
    return NumberOfAnds


def getNumberOfEquals(url):
    s = url
    NumberOfEquals = 0
    for i in s:
        if i == '=':
            NumberOfEquals = NumberOfEquals + 1
    return NumberOfEquals


def getNumberOfQuestionMark(url):
    s = url
    NumberOfQuestionMark = 0
    for i in s:
        if i == '?':
            NumberOfQuestionMark = NumberOfQuestionMark + 1
    return NumberOfQuestionMark


def getNumberOfUnderscore(url):
    s = url
    NumberOfUnderscore = 0
    for i in s:
        if i == '_':
            NumberOfUnderscore = NumberOfUnderscore + 1
    return NumberOfUnderscore


def getNumberOfPlus(url):
    s = url
    NumberOfPlus = 0
    for i in s:
        if i == '+':
            NumberOfPlus = NumberOfPlus + 1
    return NumberOfPlus


def getDomainLength(url):
    return len(urlparse(url).netloc)



def featureExtraction(url):
    if not 'http' in url:
        url = 'http://' + url

    print("Current URL - " + url)
    features = []
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url)-1)
    features.append(getDomainLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))

    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except Exception as e:
        print(str(e))
        dns = 1

    features.append(dns)

    features.append(1 if dns == 1 else domainAge(domain_name)) 
    features.append(1 if dns == 1 else domainEnd(domain_name))
#If dns is 1 which means no dns found then take domain age and Domain end date as 1
#If not, then calculate the age and end date


    features.append(getNumberOfDots(url))
    features.append(getNumberOfAnd(url))
    features.append(getNumberOfEquals(url))
    features.append(getNumberOfQuestionMark(url))
    features.append(getNumberOfUnderscore(url))
    features.append(getNumberOfPlus(url))

    return features




def checkMalicious(features):
    model = pickle.load(open("XGBoostClassifierModel_Test_1.pkl", "rb"))

    test_data = [features]  
    test_data_df = pd.DataFrame(test_data, columns = model.feature_names_in_)
    prediction = model.predict(test_data_df)
    return prediction[0]

import pyodbc
from pymongo import MongoClient

def StoreURLAndResult(URL, Result):
    client = MongoClient('mongodb://phishingdataresult:zC4U0VyMe37SokI1F4AnBOUDvZPvlb7Lzm9po5qJEgAaajvcVSammpiYp8JFI5TvLTrRfplpx3oUACDbIQKuZA==@phishingdataresult.mongo.cosmos.azure.com:10255/?ssl=true&retrywrites=false&replicaSet=globaldb&maxIdleTimeMS=120000&appName=@phishingdataresult@')
    database = client.PhishingData
    collection = database.ModelResult
    document = {
        "url" : str(URL),
        "result" : Result 
    }
    
    collection.insert_one(document)


@app.get('/predict')
def predict():
    # Get the URL from the request
    print(request.args.get('url'))
    url = request.args.get('url')

    result = checkMalicious(featureExtraction(url))

    StoreURLAndResult(url, int(str(result)))


    return str(result)


@app.get('/')
def index():
   print('Request for index page received')
   return "ok"

  
if __name__ == '__main__':
    app.run()
