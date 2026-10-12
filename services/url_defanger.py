from urllib.parse import urlsplit,urlunsplit
def defang_url(url):
 p=urlsplit(url); host=p.netloc.replace(".","[.]").replace(":","[:]")
 return urlunsplit((p.scheme.replace("http","hxxp"),host,p.path,p.query,p.fragment))
