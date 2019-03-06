/*
Copyright 2018 Eduardo Garcia Melia <wagiro@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */
package burpbounty;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IResponseVariations;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GenericScan {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    String issuename;
    String issuedetail;
    String issuebackground;
    String remediationdetail;
    String remediationbackground;
    String charstourlencode;
    int scanner;
    int matchtype;
    String issueseverity;
    String issueconfidence;
    boolean excludeHTTP;
    boolean onlyHTTP;
    boolean notresponse;
    boolean iscontenttype;
    boolean isresponsecode;
    boolean negativect;
    boolean negativerc;
    String contenttype;
    String responsecode;
    boolean casesensitive;
    boolean urlencode;
    Integer maxredirect;
    Integer redirtype;
    int payloadposition;
    String timeout;
    String contentLength;
    List<String> payloads;
    List<String> payloadsEncoded;
    List<String> payloadsenc;
    List<String> greps;
    List<String> encoders;
    JsonArray data;
    Gson gson;
    Issue issue;
    List<Headers> headers;
    CollaboratorData burpCollaboratorData;
    Properties issueProperties;
    List<IHttpRequestResponse> responses;
    List<String> variationAttributes;
    Boolean pathDiscovery;

    public GenericScan(IBurpExtenderCallbacks callbacks, JsonArray data, CollaboratorData burpCollaboratorData) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        this.data = data;
        this.burpCollaboratorData = burpCollaboratorData;
        issueProperties = new Properties();
        gson = new Gson();
    }

    public List<IScanIssue> runAScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        if (helpers.analyzeResponse(baseRequestResponse.getResponse()) == null | helpers.analyzeRequest(baseRequestResponse.getRequest()) == null) {
            return null;
        }

        int baseResponseContentLength = getContentLength(baseRequestResponse);
        List<IScanIssue> issues = new ArrayList<>();
        IHttpService httpService = baseRequestResponse.getHttpService();
        List<Integer> responseCodes = new ArrayList<>(Arrays.asList(300, 301, 303, 302, 307, 308));

        for (int i = 0; i < data.size(); i++) {
            responses = new ArrayList();
            Object idata = data.get(i);
            issue = gson.fromJson(idata.toString(), Issue.class);

            //if example scanner or passive scanner...continue.
            scanner = issue.getScanner();
            if (scanner == 0 || scanner == 2 || scanner == 3 || !issue.getActive()) {
                continue;
            }

            //get values from json
            payloads = issue.getPayloads();
            greps = issue.getGreps();
            issuename = issue.getIssueName();
            issueseverity = issue.getIssueSeverity();
            issueconfidence = issue.getIssueConfidence();
            issuedetail = issue.getIssueDetail();
            issuebackground = issue.getIssueBackground();
            remediationdetail = issue.getRemediationDetail();
            remediationbackground = issue.getRemediationBackground();
            matchtype = issue.getMatchType();
            notresponse = issue.getNotResponse();
            casesensitive = issue.getCaseSensitive();
            encoders = issue.getEncoder();
            urlencode = issue.getUrlEncode();
            charstourlencode = issue.getCharsToUrlEncode();
            iscontenttype = issue.getIsContentType();
            isresponsecode = issue.getIsResponseCode();
            contenttype = issue.getContentType();
            responsecode = issue.getResponseCode();
            excludeHTTP = issue.getExcludeHTTP();
            onlyHTTP = issue.getOnlyHTTP();
            negativect = issue.getNegativeCT();
            negativerc = issue.getNegativeRC();
            maxredirect = issue.getMaxRedir();
            redirtype = issue.getRedirection();
            payloadposition = issue.getPayloadPosition();
            timeout = issue.getTime();
            contentLength = issue.getContentLength();
            headers = issue.getHeader();
            variationAttributes = issue.getVariationAttributes();
            IScanIssue matches = null;
            GrepMatch gm = new GrepMatch(callbacks);
            pathDiscovery = issue.getPathDiscover();

            if (headers == null) {
                headers = new ArrayList();
            }

            if (pathDiscovery == null) {
                pathDiscovery = false;
            }

            if (variationAttributes == null) {
                variationAttributes = new ArrayList();
            }

            while (greps.contains("")) {//remove void greps, because get auto DOS atack ;)
                greps.remove(greps.indexOf(""));
            }

            //If encoders exist...
            if (!encoders.isEmpty()) {
                switch (matchtype) {
                    case 1:
                        payloadsEncoded = processPayload(payloads, encoders);
                        payloads = new ArrayList(payloadsEncoded);
                        break;
                    case 2:
                        payloadsEncoded = processPayload(payloads, encoders);
                        payloads = new ArrayList(payloadsEncoded);
                        break;
                    case 3:
                        payloadsEncoded = processPayload(payloads, encoders);
                        greps = payloadsEncoded;
                        payloads = payloadsEncoded;
                        break;
                    case 4:
                        payloadsEncoded = processPayload(payloads, encoders);
                        greps = new ArrayList(payloads);
                        payloads = new ArrayList(payloadsEncoded);
                        break;
                    default:
                        payloadsEncoded = processPayload(payloads, encoders);
                        payloads = new ArrayList(payloadsEncoded);
                        break;
                }

            } else {
                if (matchtype == 3) {
                    greps = payloads;
                }
            }

            for (String payload : payloads) {
                if (!pathDiscovery && insertionPoint.getInsertionPointName().startsWith("p4r4m")) {
                    break;
                }

                if (urlencode) {
                    payload = encodeTheseURL(payload, charstourlencode);
                }

                if (payloadposition == 2) {
                    payload = insertionPoint.getBaseValue().concat(payload);
                }

                if (!headers.isEmpty()) {
                    for (int x = 0; x < headers.size(); x++) {
                        if (headers.get(x).type.equals("Payload")) {
                            if (headers.get(x).regex.equals("String")) {
                                payload = payload.replace(headers.get(x).match, headers.get(x).replace);
                            } else {
                                payload = payload.replaceAll(headers.get(x).match, headers.get(x).replace);
                            }
                        }
                    }
                }

                if (payload.contains(" ")) {//for avoid space in payload
                    payload = payload.replace(" ", "+");
                }

                switch (matchtype) {
                    case 5://Timeout match type
                    {
                        long startTime = System.currentTimeMillis();
                        IHttpRequestResponse response;
                        try {
                            response = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers));
                        } catch (Exception ex) {
                            Logger.getLogger(GenericScan.class.getName()).log(Level.SEVERE, null, ex);
                            break;
                        }
                        long endTime = System.currentTimeMillis();
                        long duration = (endTime - startTime);
                        Integer time = Integer.parseInt(timeout);
                        if (duration >= time * 1000) {
                            matches = new CustomScanIssue(response.getHttpService(), helpers.analyzeRequest(response).getUrl(),
                                    new IHttpRequestResponse[]{callbacks.applyMarkers(response, null, null)},
                                    "BurpBounty - " + issuename, issuedetail.replace("<grep>", helpers.urlEncode(payload)), issueseverity,
                                    issueconfidence, remediationdetail, issuebackground, remediationbackground);
                        }
                        if (matches != null) {
                            issues.add(matches);
                        }
                        break;
                    }
                    case 7://Variations match type
                    case 8://Invariation match type
                    {
                        IHttpRequestResponse requestResponse;
                        try {
                            requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers));
                        } catch (Exception ex) {
                            Logger.getLogger(GenericScan.class.getName()).log(Level.SEVERE, null, ex);
                            break;
                        }
                        IResponseVariations ipv = helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), requestResponse.getResponse());
                        List<String> var;

                        if (matchtype == 7) {
                            var = ipv.getVariantAttributes();
                        } else {
                            var = ipv.getInvariantAttributes();
                        }

                        List requestMarkers = new ArrayList();
                        byte[] request = requestResponse.getRequest();
                        if (var.containsAll(variationAttributes)) {
                            int start = 0;
                            byte[] match = helpers.stringToBytes(payload);
                            while (start < request.length) {
                                start = helpers.indexOf(request, match, false, start, request.length);
                                if (start == -1) {
                                    break;
                                }
                                requestMarkers.add(new int[]{start, start + match.length});
                                start += match.length;
                            }

                            matches = new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                                    new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                                    "BurpBounty - " + issuename, issuedetail.replace("<payload>", helpers.urlEncode(payload)), issueseverity,
                                    issueconfidence, remediationdetail, issuebackground, remediationbackground);
                        }
                        if (matches != null) {
                            issues.add(matches);
                        }
                        break;
                    }
                    case 6://Content Length difference match type
                    {
                        IHttpRequestResponse requestResponse;
                        try {
                            requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers));
                        } catch (Exception ex) {
                            Logger.getLogger(GenericScan.class.getName()).log(Level.SEVERE, null, ex);
                            break;
                        }
                        int currentResponseContentLength = getContentLength(requestResponse);
                        if (Math.abs(baseResponseContentLength - currentResponseContentLength) > Integer.parseInt(contentLength)) {
                            List responseMarkers = new ArrayList(1);
                            String grep = "CONTENT-LENGTH:";
                            responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep),
                                helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep) + grep.length()});

                            matches = new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                                    new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, responseMarkers)},
                                    "BurpBounty - " + issuename, issuedetail.replace("<grep>", helpers.urlEncode(grep)), issueseverity,
                                    issueconfidence, remediationdetail, issuebackground, remediationbackground);
                        }
                        if (matches != null) {
                            issues.add(matches);
                        }
                        break;
                    }
                    default://String, Regex, Payload, Payload without encode match types 

                        if (payload.contains("{BC}")) {
                            IBurpCollaboratorClientContext CollaboratorClientContext = callbacks.createBurpCollaboratorClientContext();

                            burpCollaboratorData.setCollaboratorClientContext(CollaboratorClientContext);
                            String bchost = CollaboratorClientContext.generatePayload(true);
                            payload = payload.replace("{BC}", bchost);
                            IHttpRequestResponse requestResponse;
                            IResponseInfo r;
                            try {
                                requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers));
                            } catch (Exception ex) {
                                Logger.getLogger(GenericScan.class.getName()).log(Level.SEVERE, null, ex);
                                break;
                            }
                            burpCollaboratorData.setIssueProperties(requestResponse, bchost, issuename, issuedetail, issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);

                            try {
                                r = helpers.analyzeResponse(requestResponse.getResponse());
                            } catch (NullPointerException e) {
                                break;
                            }

                            Integer responseCode = new Integer(r.getStatusCode());
                            int redirect = 0;

                            while (responseCodes.contains(responseCode) && redirect < 30) {
                                r = helpers.analyzeResponse(requestResponse.getResponse());
                                responseCode = new Integer(r.getStatusCode());
                                requestResponse = getRedirection(requestResponse, payload, httpService);
                                if (requestResponse == null) {
                                    break;
                                }
                                redirect += 1;
                            }

                        } else {
                            IHttpRequestResponse requestResponse;
                            try {
                                requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers));
                            } catch (Exception ex) {
                                Logger.getLogger(GenericScan.class.getName()).log(Level.SEVERE, null, ex);
                                break;
                            }

                            if (requestResponse.getResponse() == null) {
                                break;
                            }

                            IResponseInfo r;
                            Integer responseCode;
                            if (redirtype != 1) {
                                Integer loop = 0;

                                if (maxredirect > 50) {
                                    maxredirect = 50;
                                }

                                while (loop != maxredirect + 1) {
                                    IHttpRequestResponse redirectRequestResponse = requestResponse;
                                    try {
                                        r = helpers.analyzeResponse(redirectRequestResponse.getResponse());
                                    } catch (NullPointerException e) {
                                        break;
                                    }
                                    responseCode = new Integer(r.getStatusCode());
                                    if (responseCodes.contains(responseCode)) {

                                        if (!isresponsecode && isResponseCode(responsecode, negativerc, responseCode) || !iscontenttype && isContentType(contenttype, negativect, r)) {
                                            for (String grep : greps) {
                                                matches = gm.getResponseMatches(requestResponse, payload, grep, issuename, issuedetail, issuebackground, remediationdetail, remediationbackground, charstourlencode, matchtype,
                                                        issueseverity, issueconfidence, notresponse, casesensitive, urlencode, excludeHTTP, onlyHTTP);

                                                if (matches != null) {
                                                    issues.add(matches);
                                                }
                                            }
                                        }
                                        redirectRequestResponse = getRedirection(redirectRequestResponse, payload, httpService);

                                        if (redirectRequestResponse == null) {
                                            break;
                                        }

                                        requestResponse.setResponse(redirectRequestResponse.getResponse());

                                    } else {
                                        if (!isresponsecode && isResponseCode(responsecode, negativerc, responseCode) || !iscontenttype && isContentType(contenttype, negativect, r)) {
                                            for (String grep : greps) {
                                                matches = gm.getResponseMatches(requestResponse, payload, grep, issuename, issuedetail, issuebackground, remediationdetail, remediationbackground, charstourlencode, matchtype,
                                                        issueseverity, issueconfidence, notresponse, casesensitive, urlencode, excludeHTTP, onlyHTTP);

                                                if (matches != null) {
                                                    issues.add(matches);
                                                }
                                            }
                                        }
                                        break;
                                    }
                                    loop += 1;
                                }
                            }
                        }
                }
            }
        }

        if (issues.size() > 0) {
            return issues;
        }
        return null;
    }

    public List<IScanIssue> runPScan(IHttpRequestResponse baseRequestResponse) throws Exception {

        List<IScanIssue> issues = new ArrayList<>();

        for (int i = 0; i < this.data.size(); i++) {
            Object idata = this.data.get(i);
            issue = gson.fromJson(idata.toString(), Issue.class);;

            scanner = issue.getScanner();
            //if example scanner or active scanner...continue.
            if (scanner == 0 || scanner == 1 || !issue.getActive()) {
                continue;
            }

            greps = issue.getGreps();
            issuename = issue.getIssueName();
            issueseverity = issue.getIssueSeverity();
            issueconfidence = issue.getIssueConfidence();
            issuedetail = issue.getIssueDetail();
            issuebackground = issue.getIssueBackground();
            remediationdetail = issue.getRemediationDetail();
            remediationbackground = issue.getRemediationBackground();
            matchtype = issue.getMatchType();
            notresponse = issue.getNotResponse();
            casesensitive = issue.getCaseSensitive();
            iscontenttype = issue.getIsContentType();
            isresponsecode = issue.getIsResponseCode();
            contenttype = issue.getContentType();
            responsecode = issue.getResponseCode();
            excludeHTTP = issue.getExcludeHTTP();
            onlyHTTP = issue.getOnlyHTTP();
            negativect = issue.getNegativeCT();
            negativerc = issue.getNegativeRC();

            GrepMatch gm = new GrepMatch(callbacks);

            if (scanner == 2) {//passive response
                for (String grep : greps) {
                    if (baseRequestResponse == null) {
                        break;
                    }
                    IResponseInfo r;
                    try {
                        r = helpers.analyzeResponse(baseRequestResponse.getResponse());
                    } catch (NullPointerException e) {
                        break;
                    }
                    Integer responseCode = new Integer(r.getStatusCode());

                    IScanIssue matches = null;
                    if (!isresponsecode && isResponseCode(responsecode, negativerc, responseCode) || !iscontenttype && isContentType(contenttype, negativect, r)) {
                        matches = gm.getResponseMatches(baseRequestResponse, "", grep, issuename, issuedetail, issuebackground, remediationdetail, remediationbackground, "", matchtype,
                                issueseverity, issueconfidence, notresponse, casesensitive, false, excludeHTTP, onlyHTTP);
                    }

                    if (matches != null) {
                        issues.add(matches);
                    }
                }
            } else if (scanner == 3) {//passive request
                for (String grep : greps) {
                    if (baseRequestResponse == null) {
                        return null;
                    }

                    IScanIssue matches;
                    matches = gm.getRequestMatches(baseRequestResponse, grep, issuename, issuedetail, issuebackground, remediationdetail, remediationbackground, matchtype,
                            issueseverity, issueconfidence, casesensitive, notresponse, excludeHTTP, onlyHTTP);

                    if (matches != null) {
                        issues.add(matches);
                    }
                }
            }
        }
        if (issues.size() > 0) {
            return issues;
        }
        return null;
    }

    public IHttpRequestResponse Redirection(IHttpRequestResponse response, URL url, String payload) {
        try {
            byte[] checkRequest = helpers.buildHttpRequest(url);
            boolean https = false;

            if (url.getProtocol().equals("https")) {
                https = true;
            }

            Integer port = 0;
            if (url.getPort() == -1) {
                port = url.getDefaultPort();
            }

            checkRequest = getMatchAndReplace(headers, checkRequest, payload);

            IHttpService newrequest = helpers.buildHttpService(url.getHost(), port, https);
            response = callbacks.makeHttpRequest(newrequest, checkRequest);
        } catch (IndexOutOfBoundsException | IllegalArgumentException e) {
            System.out.println("Error in redirection request: " + e.getMessage());
            return null;
        } catch (RuntimeException e) {
            System.out.println("Error in redirection request: " + e.getMessage());
            return null;
        }

        return response;
    }

    public IHttpRequestResponse getRedirection(IHttpRequestResponse response, String payload, IHttpService httpService) {

        URL url = getLocation(httpService, response);
        if (url == null) {
            return null;
        }
        if (redirtype == 2) {
            if (url.getHost().contains(httpService.getHost())) {
                return Redirection(response, url, payload);
            }
        } else if (redirtype == 3) {
            boolean isurl = callbacks.isInScope(url);
            if (isurl) {
                return Redirection(response, url, payload);
            }

        }
        return Redirection(response, url, payload);
    }

    public byte[] getMatchAndReplace(List<Headers> headers, byte[] checkRequest, String payload) {
        String tempRequest = helpers.bytesToString(checkRequest);

        if (!headers.isEmpty()) {
            for (int x = 0; x < headers.size(); x++) {
                String replace = headers.get(x).replace;
                if (headers.get(x).type.equals("Request")) {
                    if (headers.get(x).regex.equals("String")) {
                        if (replace.contains("{PAYLOAD}")) {
                            replace = replace.replace("{PAYLOAD}", payload);
                        }
                        if (headers.get(x).match.isEmpty()) {
                            tempRequest = tempRequest.replace("\r\n\r\n", "\r\n" + replace + "\r\n\r\n");
                        } else {
                            tempRequest = tempRequest.replace(headers.get(x).match, replace);
                        }
                    } else {
                        if (replace.contains("{PAYLOAD}")) {
                            replace = replace.replaceAll("\\{PAYLOAD\\}", payload);
                        }
                        if (headers.get(x).match.isEmpty()) {
                            tempRequest = tempRequest.replaceAll("\\r\\n\\r\\n", "\r\n" + replace + "\r\n\r\n");
                        } else {
                            tempRequest = tempRequest.replaceAll(headers.get(x).match, replace);
                        }
                    }

                }
            }
        }
        return helpers.stringToBytes(tempRequest);
    }

    public URL getLocation(IHttpService httpService, IHttpRequestResponse response) {
        try {
            IResponseInfo response_info = helpers.analyzeResponse(response.getResponse());
            String[] host = null;
            String Location = "";
            URL url;
            String regex = "(www)?([a-zA-Z0-9]+).[a-zA-Z0-9]*.[a-z]{3}.*";
            Pattern p = Pattern.compile(regex);

            for (String header : response_info.getHeaders()) {
                if (header.toUpperCase().contains("LOCATION")) {

                    host = header.split("\\s+");
                    Location = host[1];

                }
            }

            Matcher m = p.matcher(Location);
            if (host[1].startsWith("http://") || host[1].startsWith("https://")) {
                url = new URL(Location);
                return url;
            } else if (!host[1].startsWith("/") && m.find()) {
                url = new URL("http://" + Location);
                return url;
            } else {
                url = new URL(httpService.getProtocol() + "://" + httpService.getHost() + Location);
                return url;
            }

        } catch (MalformedURLException | NullPointerException | ArrayIndexOutOfBoundsException ex) {
            return null;
        }
    }

    public int getContentLength(IHttpRequestResponse response) {
        IResponseInfo response_info;
        try {
            response_info = helpers.analyzeResponse(response.getResponse());
        } catch (NullPointerException ex) {
            return 0;
        }

        int ContentLength = 0;

        for (String headers : response_info.getHeaders()) {
            if (headers.toUpperCase().contains("CONTENT-LENGTH:")) {
                ContentLength = Integer.parseInt(headers.split("\\s+")[1]);
            }
        }
        return ContentLength;
    }

    public boolean isResponseCode(String responsecodes, boolean negativerc, Integer responsecode) {

        boolean iscode = true;
        if (responsecodes.equals("")) {
            return iscode;
        }
        List<String> items = Arrays.asList(responsecodes.split("\\s*,\\s*"));

        for (String i : items) {
            int code = Integer.parseInt(i);
            if (code != responsecode && !negativerc) {
                iscode = false;
            } else if (code != responsecode && negativerc) {
                iscode = true;
                break;
            } else if (code == responsecode && !negativerc) {
                iscode = true;
                break;
            } else if (code == responsecode && negativerc) {
                iscode = false;
                break;
            }
        }
        return iscode;
    }

    public boolean isContentType(String contenttype, boolean negativect, IResponseInfo r) {
        List<String> HEADERS = r.getHeaders();
        boolean isct = true;
        if (contenttype.isEmpty()) {
            return isct;
        }
        List<String> items = Arrays.asList(contenttype.split("\\s*,\\s*"));

        for (String i : items) {
            for (String header : HEADERS) {
                if (header.toUpperCase().contains("CONTENT-TYPE") && !header.toUpperCase().contains(i.toUpperCase()) && !negativect) {
                    isct = false;
                } else if (header.toUpperCase().contains("CONTENT-TYPE") && !header.toUpperCase().contains(i.toUpperCase()) && negativect) {
                    isct = true;
                    break;
                } else if (header.toUpperCase().contains("CONTENT-TYPE") && header.toUpperCase().contains(i.toUpperCase()) && !negativect) {
                    isct = true;
                    break;
                } else if (header.toUpperCase().contains("CONTENT-TYPE") && header.toUpperCase().contains(i.toUpperCase()) && negativect) {
                    isct = false;
                    break;
                }
            }
        }
        return isct;
    }

    public List processPayload(List<String> payloads, List<String> encoders) {
        List pay = new ArrayList();
        for (String payload : payloads) {

            for (String p : encoders) {
                switch (p) {
                    case "URL-encode key characters":
                        payload = encodeKeyURL(payload);
                        break;
                    case "URL-encode all characters":
                        payload = encodeURL(payload);
                        break;
                    case "URL-encode all characters (Unicode)":
                        payload = encodeUnicodeURL(payload);
                        break;
                    case "HTML-encode key characters":
                        payload = encodeKeyHTML(payload);
                        break;
                    case "HTML-encode all characters":
                        payload = encodeHTML(payload);
                        break;
                    case "Base64-encode":
                        payload = helpers.base64Encode(payload);
                    default:
                        break;
                }
            }
            pay.add(payload);
        }

        return pay;
    }

    public static String encodeURL(String s) {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            out.append("%" + Integer.toHexString((int) c));
        }
        return out.toString();
    }

    public static String encodeUnicodeURL(String s) {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            out.append("%u00" + Integer.toHexString((int) c));
        }
        return out.toString();
    }

    public static String encodeHTML(String s) {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            out.append("&#x" + Integer.toHexString((int) c) + ";");
        }
        return out.toString();
    }

    public static String encodeKeyHTML(String s) {
        StringBuffer out = new StringBuffer();
        String key = "\\<\\(\\[\\\\\\^\\-\\=\\$\\!\\|\\]\\)\\?\\*\\+\\.\\>]\\&\\%\\:\\@ ";
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (key.contains(s.substring(i, i + 1))) {
                out.append("&#x" + Integer.toHexString((int) c) + ";");
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    public static String encodeKeyURL(String s) {
        StringBuffer out = new StringBuffer();
        String key = "\\<\\(\\[\\\\\\^\\-\\=\\$\\!\\|\\]\\)\\?\\*\\+\\.\\>]\\&\\%\\:\\@ ";
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (key.contains(s.substring(i, i + 1))) {
                out.append("%" + Integer.toHexString((int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    public static String encodeTheseURL(String s, String characters) {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (characters.indexOf(c) >= 0) {
                out.append("%" + Integer.toHexString((int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

}
