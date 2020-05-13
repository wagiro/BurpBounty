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
    ProfilesProperties profile_property;
    List<Headers> headers;
    CollaboratorData burpCollaboratorData;
    List<String> variationAttributes;
    List<Integer> insertionPointType;
    Boolean pathDiscovery;

    public GenericScan(IBurpExtenderCallbacks callbacks, JsonArray data, CollaboratorData burpCollaboratorData) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        this.data = data;
        this.burpCollaboratorData = burpCollaboratorData;
        gson = new Gson();
    }

    public List<IScanIssue> runAScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String bchost) {

        if (helpers.analyzeResponse(baseRequestResponse.getResponse()) == null | helpers.analyzeRequest(baseRequestResponse.getRequest()) == null) {
            return null;
        }

        List<IScanIssue> issues = new ArrayList<>();
        IHttpService httpService = baseRequestResponse.getHttpService();
        List<Integer> responseCodes = new ArrayList<>(Arrays.asList(300, 301, 303, 302, 307, 308));
        int limitredirect = 30;

        for (int i = 0; i < data.size(); i++) {
            Object idata = data.get(i);
            profile_property = gson.fromJson(idata.toString(), ProfilesProperties.class);

            payloads = profile_property.getPayloads();
            greps = profile_property.getGreps();
            issuename = profile_property.getIssueName();
            issueseverity = profile_property.getIssueSeverity();
            issueconfidence = profile_property.getIssueConfidence();
            issuedetail = profile_property.getIssueDetail();
            issuebackground = profile_property.getIssueBackground();
            remediationdetail = profile_property.getRemediationDetail();
            remediationbackground = profile_property.getRemediationBackground();
            matchtype = profile_property.getMatchType();
            notresponse = profile_property.getNotResponse();
            casesensitive = profile_property.getCaseSensitive();
            encoders = profile_property.getEncoder();
            urlencode = profile_property.getUrlEncode();
            charstourlencode = profile_property.getCharsToUrlEncode();
            iscontenttype = profile_property.getIsContentType();
            isresponsecode = profile_property.getIsResponseCode();
            contenttype = profile_property.getContentType();
            responsecode = profile_property.getResponseCode();
            excludeHTTP = profile_property.getExcludeHTTP();
            onlyHTTP = profile_property.getOnlyHTTP();
            negativect = profile_property.getNegativeCT();
            negativerc = profile_property.getNegativeRC();
            maxredirect = profile_property.getMaxRedir();
            redirtype = profile_property.getRedirection();
            payloadposition = profile_property.getPayloadPosition();
            timeout = profile_property.getTime();
            contentLength = profile_property.getContentLength();
            headers = profile_property.getHeader() != null ? profile_property.getHeader() : new ArrayList();
            variationAttributes = profile_property.getVariationAttributes() != null ? profile_property.getVariationAttributes() : new ArrayList();
            insertionPointType = profile_property.getInsertionPointType() != null ? profile_property.getInsertionPointType() : new ArrayList(Arrays.asList(0));
            pathDiscovery = profile_property.getPathDiscover();

            IScanIssue matches = null;
            GrepMatch gm = new GrepMatch(callbacks);

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
                    payload = payload.replace(" ", "%20");
                }

                switch (matchtype) {
                    case 5://Timeout match type
                    {
                        long startTime, endTime, difference = 0;
                        matches = null;
                        IHttpRequestResponse requestResponse;
                        Integer responseCode;
                        Integer responseCodeBase;
                        IResponseInfo r;
                        IResponseInfo rbase;

                        try {
                            startTime = System.currentTimeMillis();
                            requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers));
                            endTime = System.currentTimeMillis();
                            difference = (endTime - startTime);
                        } catch (Exception ex) {
                            break;
                        }

                        r = helpers.analyzeResponse(requestResponse.getResponse());
                        rbase = helpers.analyzeResponse(baseRequestResponse.getResponse());

                        responseCode = new Integer(r.getStatusCode());
                        responseCodeBase = new Integer(rbase.getStatusCode());

                        if ((!isresponsecode || isresponsecode && isResponseCode(responsecode, negativerc, responseCode) && isResponseCode(responsecode, negativerc, responseCodeBase)) && (!iscontenttype || iscontenttype && isContentType(contenttype, negativect, r))) {
                            Integer time = Integer.parseInt(timeout);
                            if (difference >= time * 1000) {
                                matches = new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                                        new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, null)},
                                        "BurpBounty - " + issuename, issuedetail.replace("<grep>", helpers.urlEncode(payload)), issueseverity,
                                        issueconfidence, remediationdetail, issuebackground, remediationbackground);
                            }
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
                        matches = null;
                        Integer responseCode;
                        IResponseInfo r;

                        try {
                            requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers));
                        } catch (Exception ex) {
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
                        r = helpers.analyzeResponse(requestResponse.getResponse());
                        responseCode = new Integer(r.getStatusCode());

                        if ((!isresponsecode || isresponsecode && isResponseCode(responsecode, negativerc, responseCode)) && (!iscontenttype || iscontenttype && isContentType(contenttype, negativect, r))) {
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
                        }
                        if (matches != null) {
                            issues.add(matches);
                        }
                        break;
                    }
                    case 6://Content Length difference match type
                    {
                        IHttpRequestResponse requestResponse;
                        matches = null;
                        Integer responseCode;
                        Integer responseCodeBase;
                        IResponseInfo r;
                        IResponseInfo rbase;

                        try {
                            requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers));
                            r = helpers.analyzeResponse(requestResponse.getResponse());
                            rbase = helpers.analyzeResponse(baseRequestResponse.getResponse());
                        } catch (Exception ex) {
                            break;
                        }

                        responseCode = new Integer(r.getStatusCode());
                        responseCodeBase = new Integer(rbase.getStatusCode());

                        if ((!isresponsecode || isresponsecode && isResponseCode(responsecode, negativerc, responseCode) && isResponseCode(responsecode, negativerc, responseCodeBase)) && (!iscontenttype || iscontenttype && isContentType(contenttype, negativect, r))) {
                            int baseResponseContentLength = getContentLength(baseRequestResponse);
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
                        }
                        if (matches != null) {
                            issues.add(matches);
                        }
                        break;
                    }
                    default://String, Regex, Payload, Payload without encode match types 

                        if (payload.contains("{BC}")) {

                            IHttpRequestResponse requestResponse;
                            IResponseInfo r;
                            Integer responseCode;
                            int loop = 0;
                            Boolean redirect = true;
                            URL url;

                            payload = payload.replace("{BC}", bchost);

                            do {
                                try {
                                    requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers));
                                    r = helpers.analyzeResponse(requestResponse.getResponse());
                                } catch (Exception ex) {
                                    break;
                                }

                                burpCollaboratorData.setIssueProperties(requestResponse, bchost, issuename, issuedetail, issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);

                                responseCode = new Integer(r.getStatusCode());

                                if (responseCodes.contains(responseCode) && loop < limitredirect) {
                                    httpService = requestResponse.getHttpService();
                                    url = getRedirection(requestResponse, httpService);

                                    if (url != null) {
                                        httpService = helpers.buildHttpService(url.getHost(), httpService.getPort(), httpService.getProtocol());
                                    } else {
                                        redirect = false;
                                    }
                                    loop += 1;
                                } else {
                                    redirect = false;
                                }
                            } while (redirect);

                        } else {
                            IHttpRequestResponse requestResponse;
                            IResponseInfo r;
                            Integer responseCode;
                            int loop = 0;
                            URL url;
                            Boolean redirect = true;

                            try {
                                requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers));
                                IHttpRequestResponse redirectRequestResponse = requestResponse;
                                r = helpers.analyzeResponse(redirectRequestResponse.getResponse());
                            } catch (NullPointerException e) {
                                break;
                            }

                            responseCode = new Integer(r.getStatusCode());

                            if ((!isresponsecode || isresponsecode && isResponseCode(responsecode, negativerc, responseCode)) && (!iscontenttype || iscontenttype && isContentType(contenttype, negativect, r))) {
                                for (String grep : greps) {
                                    matches = gm.getResponseMatches(requestResponse, payload, grep, issuename, issuedetail, issuebackground, remediationdetail, remediationbackground, charstourlencode, matchtype,
                                            issueseverity, issueconfidence, notresponse, casesensitive, urlencode, excludeHTTP, onlyHTTP);

                                    if (matches != null) {
                                        issues.add(matches);
                                    }
                                }
                            }

                            do {
                                if (responseCodes.contains(responseCode) && redirtype != 1 && loop < maxredirect && maxredirect < limitredirect) {
                                    httpService = requestResponse.getHttpService();
                                    url = getRedirection(requestResponse, httpService);

                                    if (url != null) {
                                        byte[] checkRequest = helpers.buildHttpRequest(url);
                                        checkRequest = getMatchAndReplace(headers, checkRequest, payload);
                                        int port = 0;
                                        if (url.getPort() == -1) {
                                            port = url.getDefaultPort();
                                        }
                                        IHttpService newrequest = helpers.buildHttpService(url.getHost(), port, url.getProtocol());
                                        requestResponse = callbacks.makeHttpRequest(newrequest, checkRequest);
                                        IHttpRequestResponse redirectRequestResponse = requestResponse;
                                        r = helpers.analyzeResponse(redirectRequestResponse.getResponse());
                                        responseCode = new Integer(r.getStatusCode());

                                    } else {
                                        redirect = false;
                                    }

                                } else {
                                    redirect = false;
                                }
                                loop += 1;

                            } while (redirect);
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
            profile_property = gson.fromJson(idata.toString(), ProfilesProperties.class);

            greps = profile_property.getGreps();
            issuename = profile_property.getIssueName();
            issueseverity = profile_property.getIssueSeverity();
            issueconfidence = profile_property.getIssueConfidence();
            issuedetail = profile_property.getIssueDetail();
            issuebackground = profile_property.getIssueBackground();
            remediationdetail = profile_property.getRemediationDetail();
            remediationbackground = profile_property.getRemediationBackground();
            matchtype = profile_property.getMatchType();
            notresponse = profile_property.getNotResponse();
            casesensitive = profile_property.getCaseSensitive();
            iscontenttype = profile_property.getIsContentType();
            isresponsecode = profile_property.getIsResponseCode();
            contenttype = profile_property.getContentType();
            responsecode = profile_property.getResponseCode();
            excludeHTTP = profile_property.getExcludeHTTP();
            onlyHTTP = profile_property.getOnlyHTTP();
            negativect = profile_property.getNegativeCT();
            negativerc = profile_property.getNegativeRC();
            scanner = profile_property.getScanner();

            GrepMatch gm = new GrepMatch(callbacks);

            if (scanner == 2) {//passive response
                IScanIssue matches = null;
                IResponseInfo r;

                if (baseRequestResponse == null) {
                    break;
                }

                try {
                    r = helpers.analyzeResponse(baseRequestResponse.getResponse());
                } catch (NullPointerException e) {
                    break;
                }

                Integer responseCode = new Integer(r.getStatusCode());

                for (String grep : greps) {
                    if ((!isresponsecode || isresponsecode && isResponseCode(responsecode, negativerc, responseCode)) && (!iscontenttype || iscontenttype && isContentType(contenttype, negativect, r))) {
                        matches = gm.getResponseMatches(baseRequestResponse, "", grep, issuename, issuedetail, issuebackground, remediationdetail, remediationbackground, "", matchtype,
                                issueseverity, issueconfidence, notresponse, casesensitive, false, excludeHTTP, onlyHTTP);
                    }

                    if (matches != null) {
                        issues.add(matches);
                    }
                }
            } else if (scanner == 3) {//passive request
                IScanIssue matches;

                if (baseRequestResponse == null) {
                    return null;
                }

                for (String grep : greps) {
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

    public URL getRedirection(IHttpRequestResponse response, IHttpService httpService) {

        try {
            URL url = getLocation(httpService, response);

            if (url.getHost().contains("burpcollaborator.net")) {
                return url;
            } else if (redirtype == 2) {
                if (url.getHost().contains(httpService.getHost())) {
                    return url;
                }
            } else if (redirtype == 3) {
                boolean isurl = callbacks.isInScope(url);
                if (isurl) {
                    return url;
                }
            } else if (redirtype == 4) {
                return url;
            } else {
                return null;
            }

            return null;
        } catch (NullPointerException | ArrayIndexOutOfBoundsException ex) {
            return null;
        }
    }

    public URL getLocation(IHttpService httpService, IHttpRequestResponse response) {
        String[] host = null;
        String Location = "";
        URL url;

        try {
            IResponseInfo response_info = helpers.analyzeResponse(response.getResponse());

            for (String header : response_info.getHeaders()) {
                if (header.toUpperCase().contains("LOCATION")) {
                    host = header.split("\\s+");
                    Location = host[1];
                }
            }

            if (Location.startsWith("http://") || Location.startsWith("https://")) {
                url = new URL(Location);
                return url;
            } else if (Location.startsWith("/")) {
                url = new URL(httpService.getProtocol() + "://" + httpService.getHost() + Location);
                return url;
            } else {
                return null;
            }

        } catch (MalformedURLException | NullPointerException | ArrayIndexOutOfBoundsException ex) {
            return null;
        }
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
