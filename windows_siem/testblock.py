import requests
print(requests.post("http://10.14.114.21:5001/block", json={"ip":"1.2.3.4"}).text)