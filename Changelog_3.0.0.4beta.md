# Improvements Burp Bounty 3.0.4beta:

### "Path discovery" feature add new insertion points

New insertion points are added to the requests (To discover hidden files and files), when you check the "Path Discovery" option in "Payload Options" section. For example in the request:

GET /dir1/dir2/file.php?param=value HTTP/1.1

Generate three new Insertion points:

1- GET {HERE} HTTP/1.1
2- GET /dir1{HERE} HTTP/1.1
3- GET /dir1/dir2{HERE} HTTP/1.1

Then, if you put in payload /.git/HEAD, the three new request are:

1- GET /.git/HEAD HTTP/1.1
2- GET /dir1/.git/HEAD HTTP/1.1
3- GET /dir1/dir2/.git/HEAD HTTP/1.1

without param=value.

Another example, in request:

GET / HTTP/1.1
Generate one new insertion point:

1- GET {HERE} HTTP/1.1

Then, if you put in payload "/assets../static/app.js", the one new request are:

1- GET /assets../static/app.js HTTP/1.1


Code:
```java
@Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        List<IScannerInsertionPoint> insertionPoints = new ArrayList();
        IRequestInfo request = helpers.analyzeRequest(baseRequestResponse);

        if (request.getMethod().equals("GET")) {
            byte[] match = helpers.stringToBytes("/");
            byte[] req = baseRequestResponse.getRequest();
            int beginAt = 0;
            while (beginAt < req.length) {
                beginAt = helpers.indexOf(req, match, false, beginAt, helpers.bytesToString(baseRequestResponse.getRequest()).indexOf("HTTP"));
                if (beginAt == -1) {
                    break;
                }
                insertionPoints.add(helpers.makeScannerInsertionPoint("param" + beginAt, baseRequestResponse.getRequest(), beginAt, helpers.bytesToString(baseRequestResponse.getRequest()).indexOf(" HTTP")));
                beginAt += match.length;
            }
        }
        return insertionPoints;
    }
```
<br>


For discover some useful files or directories:

![PathFeature](https://github.com/wagiro/BurpBounty/blob/master/images/path.png)


### New tags for extract matches and better issue documentation 

All the matches of the requests and responses are highlighted. You can extract the matches of the requests and responses to the issuedetail, through the <payload> tags for the payloads and <grep> for the greps. It's useful for example, for extract endpoint from regex through passive scanner:


![TagsFeature](https://github.com/wagiro/BurpBounty/blob/master/images/tagsfeature.png)



### Variations/Invariations match type feature
You can add issues by checking Variations/Invariations between the base response, and each payoad response. I have 31 different attributes for this(the names of the attributes are quite descriptive):

![VariationsFeatur](https://github.com/wagiro/BurpBounty/blob/master/images/variations.png)


### Algorithm optimization

### New profiles added
