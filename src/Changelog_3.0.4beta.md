# Improvements Burp Bounty 3.0.4beta:

### "Path discovery" feature add new insertion points

New insertion points are added to the requests (To discover hidden files and directories), when you check the "Path Discovery" option in "Payload Options" section. For example in the request:

GET /dir1/dir2/file.php?param=value HTTP/1.1

Generate three new Insertion points:

1- GET {HERE} HTTP/1.1<br>
2- GET /dir1{HERE} HTTP/1.1<br>
3- GET /dir1/dir2{HERE} HTTP/1.1<br>

Then, if you put in payload /.git/HEAD, the three new request are:

1- GET /.git/HEAD HTTP/1.1<br>
2- GET /dir1/.git/HEAD HTTP/1.1<br>
3- GET /dir1/dir2/.git/HEAD HTTP/1.1<br>

without param=value.

Another example, in request:

GET / HTTP/1.1<br>

Generate one new insertion point:

1- GET {HERE} HTTP/1.1<br>

Then, if you put in payload "/assets../static/app.js", the one new request are:

1- GET /assets../static/app.js HTTP/1.1<br>


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
Improved some algorithms for better performance.

### New profiles added
Various profiles was added in profiles directory
