import requests
import os

os.environ["http_proxy"] = "http://a:a@1.1.1.1:3"
os.environ["https_proxy"] = "http://user:pass@1.1.1.1:3"
os.environ["no_proxy"] = "localhost,127.0.0.0/8,*.local"

url = "https://api.us-2.crowdstrike.com:443/oauth2/token"

session = requests.Session()
session.trust_env = True

h = {"Accept":"application/json","Content-Type":"application/x-www-form-urlencoded","user-agent":"oca_stixshifter_1.0"}
params = {"client_id":"asdf","client_secret":"asdf"}

r = session.post(url, headers=h, params=params).json()

print(r)
