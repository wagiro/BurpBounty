[
  {
    "ProfileName": "WebCachePoisoning",
    "Name": "",
    "Enabled": true,
    "Scanner": 1,
    "Author": "@egarme",
    "Payloads": [
      "true,STRINGFORREQUEST"
    ],
    "Encoder": [],
    "UrlEncode": false,
    "CharsToUrlEncode": "",
    "Grep": [
      "true,,TOKEN1337"
    ],
    "Tags": [
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
    "RedirType": 4,
    "MaxRedir": 3,
    "payloadPosition": 1,
    "payloadsFile": "",
    "grepsFile": "",
    "IssueName": "Web-Cache-Poisoning",
    "IssueSeverity": "High",
    "IssueConfidence": "Certain",
    "IssueDetail": "Web Cache poisoning with payload: \u003cbr\u003e\u003cpayload\u003e\n\n\u003cbr\u003e\u003cbr\u003eBy James Kettle:\u003cbr\u003ehttps://portswigger.net/blog/practical-web-cache-poisoning",
    "RemediationDetail": "",
    "IssueBackground": "",
    "RemediationBackground": "",
    "Header": [
      {
        "type": "Request",
        "match": "",
        "replace": "X-Forwarded-For: TOKEN1337",
        "regex": "String"
      },
      {
        "type": "Request",
        "match": "",
        "replace": "X-Host: TOKEN1337",
        "regex": "String"
      },
      {
        "type": "Request",
        "match": "",
        "replace": "X-Forwarded-Server: TOKEN1337",
        "regex": "String"
      },
      {
        "type": "Request",
        "match": "",
        "replace": "X-Forwarded-Scheme: TOKEN1337",
        "regex": "String"
      },
      {
        "type": "Request",
        "match": "",
        "replace": "X-Original-URL: TOKEN1337",
        "regex": "String"
      },
      {
        "type": "Request",
        "match": "",
        "replace": "X-Rewrite-URL: TOKEN1337",
        "regex": "String"
      }
    ],
    "VariationAttributes": [],
    "InsertionPointType": [
      18,
      65,
      32,
      36,
      7,
      1,
      2,
      6,
      33,
      5,
      35,
      34,
      64,
      0,
      3,
      4,
      37,
      127,
      65,
      32,
      36,
      7,
      1,
      2,
      6,
      33,
      5,
      35,
      34,
      64,
      0,
      3,
      4,
      37,
      127
    ],
    "Scanas": false,
    "Scantype": 0,
    "pathDiscovery": false
  }
]