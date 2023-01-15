
import json
import typing
import urllib.request


def http_post(url: str, data: typing.Dict, headers: typing.Dict = {}):
    req = urllib.request.Request(url)
    for k, v in headers.items():
        req.add_header(k, v)
    jsondata = json.dumps(data)
    jsondataasbytes = jsondata.encode('utf-8') # needs to be bytes
    req.add_header('Content-Type', 'application/json')
    req.add_header('Content-Length', len(jsondataasbytes))
    return urllib.request.urlopen(req, jsondataasbytes)
