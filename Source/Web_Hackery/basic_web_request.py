import urllib2

url = "http://www.nostarch.com"
#define dict for headers
headers = {}
#add user-agent entry to headers dict
headers[User-Agent] = "Googlebot"
#define web request
request = urllib2.Request(url,headers=headers)
#make request and save the response
response = urllib2.urlopen(request)
#print out the response and then close
print response.read()
response.close()