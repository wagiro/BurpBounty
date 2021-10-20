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
package burpbountyfree;

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
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 *
 * @author wagiro
 */
public class ActiveScanner {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    JsonArray active_profiles;
    BurpBountyExtension bbe;
    Gson gson;
    CollaboratorData burpCollaboratorData;
    BurpBountyGui bbg;
    JsonArray allprofiles;
    Integer redirtype;
    List<String> rules_done = new ArrayList<>();
    Integer smartscandelay;
    Utils utils;
    String issuename;
    String name;
    String issuedetail;
    String issuebackground;
    String remediationdetail;
    String remediationbackground;
    String charstourlencode;
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
    String httpresponsecode;
    boolean casesensitive;
    boolean urlencode;
    Integer maxredirect;
    int payloadposition;
    String timeout1;
    String timeout2;
    String contentLength;
    List<String> payloads;
    List<String> payloadsEncoded;
    List<String> greps;
    List<String> encoders;
    ProfilesProperties profile_property;
    List<Headers> headers;
    List<String> variationAttributes;
    List<Integer> insertionPointType;
    String urlextension;
    Boolean isurlextension;
    Boolean NegativeUrlExtension;
    GrepMatch gm;
    Boolean passive;

    List<Integer> responseCodes = new ArrayList<>(Arrays.asList(300, 301, 303, 302, 307, 308));
    int limitredirect = 30;

    public ActiveScanner(BurpBountyExtension bbe, IBurpExtenderCallbacks callbacks, CollaboratorData burpCollaboratorData, JsonArray allprofiles, BurpBountyGui bbg) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        this.burpCollaboratorData = burpCollaboratorData;
        this.allprofiles = allprofiles;
        this.bbe = bbe;
        this.bbg = bbg;
        utils = new Utils(bbe, callbacks, burpCollaboratorData, allprofiles, bbg);
        gm = new GrepMatch(this.callbacks);
    }

    public void runAScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, JsonArray activeprofiles, Boolean come_from_passive, Boolean reqpassive, String rule_name, Boolean passive) {
        try {
            this.passive = passive;

            Boolean collaborator = true;
            IBurpCollaboratorClientContext CollaboratorClientContext2 = null;
            gson = new Gson();

            try {
                CollaboratorClientContext2 = callbacks.createBurpCollaboratorClientContext();
                burpCollaboratorData.setCollaboratorClientContext(CollaboratorClientContext2);
            } catch (Exception ex) {
                System.out.println("ActiveScanner line 115: " + ex.getMessage());
                collaborator = false;
            }

            for (int i = 0; i < activeprofiles.size(); i++) {

                Object idata = activeprofiles.get(i);
                profile_property = gson.fromJson(idata.toString(), ProfilesProperties.class);

                //initialized the profile values
                setProfilesValues(profile_property);
                if (!come_from_passive && !insertionPointType.contains(insertionPoint.getInsertionPointType() & 0xFF)) {
                    continue;
                    
                }
                if (come_from_passive && !reqpassive) {
                    Boolean continue_or_not = false;

                    for (int ip : insertionPointType) {
                        if (insertionPoint.getInsertionPointName().endsWith("_" + String.valueOf(ip))) {
                            continue_or_not = true;
                        }
                    }
                    if (!continue_or_not) {
                        continue;//COMPROBAR ESTE RETURN
                    }
                }

                //inicializa valores de payload, payloadencode y grep
                processPayloads();

                for (String payload : payloads) {
                    if (payload.startsWith("false,")) {
                        continue;
                    } else if (payload.startsWith("true,")) {
                        payload = payload.replace("true,", "");
                    }

                    Thread.sleep(60);
                    String bchost = "";

                    if (urlencode) {
                        payload = utils.encodeTheseURL(payload, charstourlencode);
                    }

                    if (payloadposition == 2) {
                        payload = insertionPoint.getBaseValue().concat(payload);
                    }

                    if (payloadposition == 3) {
                        payload = insertPayload(insertionPoint.getBaseValue(), payload);
                    }

                    //processHeaders
                    try {
                        if (!headers.isEmpty()) {
                            for (int x = 0; x < headers.size(); x++) {
                                if (headers.get(x).type.equals("Payload")) {
                                    if (headers.get(x).regex.equals("String")) {
                                        payload = payload.replace(headers.get(x).match, headers.get(x).replace);
                                    } else {
                                        payload = payload.replaceAll(headers.get(x).match, headers.get(x).replace);
                                    }
                                }

                                if (headers.get(x).type.equals("Request") && collaborator) {
                                    if (headers.get(x).regex.equals("String")) {
                                        String a = headers.get(x).replace;
                                        if (headers.get(x).replace.contains("{BC}")) {
                                            bchost = CollaboratorClientContext2.generatePayload(true);
                                            String subdomain = generateString();
                                            bchost = subdomain + "." + bchost;
                                        }
                                    }
                                }
                            }

                        }
                    } catch (Exception ex) {
                        //escondido porque muestra mucho 
                        bchost = "";

                    }

                    if (payload.contains(" ") && utils.encode(insertionPoint, reqpassive)) {//for avoid space in payload
                        payload = payload.replace(" ", "%20");
                    }

                    if (matchtype == 5)//Timeout match type
                    {
                        timeoutMatchType(baseRequestResponse, insertionPoint, payload, rule_name);

                    } else if (matchtype == 7 || matchtype == 8)//Variations match type//Invariation match type
                    {
                        variationsInvariationsMatchType(baseRequestResponse, insertionPoint, payload, rule_name);

                    } else if (matchtype == 6)//Content Length difference match type
                    {
                        contentLengthMatchType(baseRequestResponse, insertionPoint, payload, rule_name);

                    } else if (matchtype == 9)//HTTP Response Code
                    {
                        httpCodeMatchType(baseRequestResponse, insertionPoint, payload, rule_name);

                    } else if (payload.contains("{BC}") && collaborator || !bchost.equals("") && collaborator)//Burp Collaborator
                    {
                        CollaboratorMatchType(baseRequestResponse, insertionPoint, payload, bchost, rule_name, CollaboratorClientContext2);

                    } else {//String, Regex, Payload, Payload without encode match types 
                        stringRegexMatchType(baseRequestResponse, insertionPoint, payload, rule_name,CollaboratorClientContext2,bchost);
                    }

                }
            }
        } catch (Exception ex) {
            System.out.println("ActiveScanner line 175: " + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public static String insertPayload(String original, String payload) {

        String bagBegin = original.substring(0, original.length() / 2);
        String bagEnd = original.substring(original.length() / 2, original.length());
        return bagBegin + payload + bagEnd;
    }

    public void processPayloads() {
        //If encoders exist...
        if (!encoders.isEmpty()) {
            switch (matchtype) {
                case 1:
                    payloadsEncoded = utils.processPayload(payloads, encoders);
                    payloads = new ArrayList(payloadsEncoded);
                    break;
                case 2:
                    payloadsEncoded = utils.processPayload(payloads, encoders);
                    payloads = new ArrayList(payloadsEncoded);
                    break;
                case 3:
                    payloadsEncoded = utils.processPayload(payloads, encoders);
                    greps = new ArrayList();
                    for (String p : payloads) {
                        greps.add("true,Or," + p);
                    }
                    payloads = payloadsEncoded;
                    break;
                case 4:
                    greps = new ArrayList();
                    payloadsEncoded = utils.processPayload(payloads, encoders);
                    for (String p : payloads) {
                        greps.add("true,Or," + p);
                    }
                    payloads = new ArrayList(payloadsEncoded);
                    break;
                default:
                    payloadsEncoded = utils.processPayload(payloads, encoders);
                    payloads = new ArrayList(payloadsEncoded);
                    break;
            }

        } else {
            if (matchtype == 3) {
                for (String p : payloads) {
                    greps.add("true,Or," + p);
                }
            }
        }
    }

    public void setProfilesValues(ProfilesProperties profile_property) {
        payloads = profile_property.getPayloads();
        name = profile_property.getProfileName();
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
        httpresponsecode = profile_property.getHttpResponseCode();
        excludeHTTP = profile_property.getExcludeHTTP();
        onlyHTTP = profile_property.getOnlyHTTP();
        negativect = profile_property.getNegativeCT();
        negativerc = profile_property.getNegativeRC();
        maxredirect = profile_property.getMaxRedir();
        redirtype = profile_property.getRedirection();
        payloadposition = profile_property.getPayloadPosition();
        timeout1 = profile_property.getTime1();
        timeout2 = profile_property.getTime2();
        contentLength = profile_property.getContentLength();
        headers = profile_property.getHeader() != null ? profile_property.getHeader() : new ArrayList();
        variationAttributes = profile_property.getVariationAttributes() != null ? profile_property.getVariationAttributes() : new ArrayList();
        insertionPointType = profile_property.getInsertionPointType() != null ? profile_property.getInsertionPointType() : new ArrayList(Arrays.asList(0));
        isurlextension = profile_property.getIsURLExtension();
        urlextension = profile_property.getURLExtension();
        NegativeUrlExtension = profile_property.getNegativeURLExtension();
    }

    public void timeoutMatchType(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String payload, String rule_name) {
        long startTime, endTime, difference = 0;
        try {
            Boolean isduplicated = utils.checkDuplicated(baseRequestResponse, issuename, insertionPoint);

            if (!isduplicated) {
                IHttpService httpService = baseRequestResponse.getHttpService();

                startTime = System.currentTimeMillis();
                IHttpRequestResponse payloadRequestResponse;
                try {
                    payloadRequestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers, ""));
                } catch (Exception e) {
                    return;
                }
                if (payloadRequestResponse != null) {

                    endTime = System.currentTimeMillis();
                    difference = (endTime - startTime);

                    IResponseInfo r;
                    IResponseInfo rbase;

                    try {
                        if (payloadRequestResponse.getResponse() == null || baseRequestResponse.getResponse() == null) {
                            return;
                        }
                        r = helpers.analyzeResponse(payloadRequestResponse.getResponse());
                        rbase = helpers.analyzeResponse(baseRequestResponse.getResponse());
                    } catch (Exception ex) {
                        System.out.println("ActiveScanner line 378: " + ex.getMessage());
                        for (StackTraceElement element : ex.getStackTrace()) {
                            System.out.println(element);
                        }
                        return;
                    }

                    Integer responseCode = new Integer(r.getStatusCode());
                    Integer responseCodeBase = new Integer(rbase.getStatusCode());
                    IRequestInfo requestInfo = helpers.analyzeRequest(payloadRequestResponse);

                    if ((!isresponsecode || isresponsecode && utils.isResponseCode(responsecode, negativerc, responseCode) && utils.isResponseCode(responsecode, negativerc, responseCodeBase)) && (!iscontenttype || iscontenttype && utils.isContentType(contenttype, negativect, r))) {
                        try {
                            Integer time1 = Integer.parseInt(timeout1);
                            Integer time2 = Integer.parseInt(timeout2);
                            if (time2 * 1000 >= difference && difference >= time1 * 1000) {
                                callbacks.addScanIssue(new CustomScanIssue(payloadRequestResponse.getHttpService(), helpers.analyzeRequest(payloadRequestResponse).getUrl(),
                                        new IHttpRequestResponse[]{callbacks.applyMarkers(payloadRequestResponse, null, null)},
                                        "BurpBounty - " + issuename, "Vulnerable parameter: " + insertionPoint.getInsertionPointName() + ".<br/>" + issuedetail.replace("<payload>", payload), issueseverity,
                                        issueconfidence, remediationdetail.replace("<payload>", payload), issuebackground.replace("<payload>", payload),
                                        remediationbackground.replace("<payload>", payload)));
                                return;
                            }
                        } catch (NumberFormatException e) {

                        }
                    }
                }

            }
        } catch (Exception ex) {
            System.out.println("ActiveScanner line 410: " + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public void httpCodeMatchType(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String payload, String rule_name) {

        try {
            Boolean isduplicated = utils.checkDuplicated(baseRequestResponse, issuename, insertionPoint);

            if (!isduplicated) {
                IHttpService httpService = baseRequestResponse.getHttpService();

                IHttpRequestResponse payloadRequestResponse;
                try {
                    payloadRequestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers, ""));
                } catch (Exception e) {
                    return;
                }

                if (payloadRequestResponse != null) {
                    IResponseInfo r;
                    try {
                        if (payloadRequestResponse.getResponse() == null) {
                            return;
                        }
                        r = helpers.analyzeResponse(payloadRequestResponse.getResponse());
                    } catch (Exception ex) {
                        System.out.println("ActiveScanner line 440: " + ex.getMessage());
                        for (StackTraceElement element : ex.getStackTrace()) {
                            System.out.println(element);
                        }
                        return;
                    }

                    Integer responseCode = new Integer(r.getStatusCode());
                    IRequestInfo requestInfo = helpers.analyzeRequest(payloadRequestResponse);

                    if ((!iscontenttype || iscontenttype && utils.isContentType(contenttype, negativect, r))) {
                        if (utils.isResponseCode(httpresponsecode, negativerc, responseCode)) {
                            List responseMarkers = new ArrayList(1);
                            List requestMarkers = new ArrayList(1);

                            requestMarkers.add(new int[]{helpers.bytesToString(payloadRequestResponse.getRequest()).indexOf(payload),
                                helpers.bytesToString(payloadRequestResponse.getRequest()).indexOf(payload) + payload.length()});
                            String grep = "HTTP/";
                            responseMarkers.add(new int[]{helpers.bytesToString(payloadRequestResponse.getResponse()).toUpperCase().indexOf(grep) + 9,
                                helpers.bytesToString(payloadRequestResponse.getResponse()).toUpperCase().indexOf(grep) + 12});

                            callbacks.addScanIssue(new CustomScanIssue(payloadRequestResponse.getHttpService(), helpers.analyzeRequest(payloadRequestResponse).getUrl(),
                                    new IHttpRequestResponse[]{callbacks.applyMarkers(payloadRequestResponse, requestMarkers, responseMarkers)},
                                    "BurpBounty - " + issuename, "Vulnerable parameter: " + insertionPoint.getInsertionPointName() + ".<br/>" + issuedetail, issueseverity,
                                    issueconfidence, remediationdetail, issuebackground, remediationbackground));
                            return;

                        }
                    }
                }

            }
        } catch (Exception ex) {
            System.out.println("ActiveScanner line 475: " + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public void variationsInvariationsMatchType(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String payload, String rule_name) {

        Integer responseCode;
        IResponseInfo r;

        try {
            Boolean isduplicated = utils.checkDuplicated(baseRequestResponse, issuename, insertionPoint);

            if (!isduplicated) {
                IHttpService httpService = baseRequestResponse.getHttpService();
                IHttpRequestResponse requestResponse;
                try {
                    requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers, ""));
                } catch (Exception e) {
                    return;
                }
                if (requestResponse == null) {
                    return;
                }
                try {
                    if (requestResponse.getResponse() == null) {
                        return;

                    }
                    r = helpers.analyzeResponse(requestResponse.getResponse());
                } catch (Exception ex) {
                    System.out.println("ActiveScanner line 509: " + ex.getMessage());
                    for (StackTraceElement element : ex.getStackTrace()) {
                        System.out.println(element);
                    }
                    return;
                }

                IResponseVariations ipv = helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), requestResponse.getResponse());
                List<String> var;
                List<String> var2;

                if (matchtype == 7) {
                    var = ipv.getVariantAttributes();
                    var2 = ipv.getInvariantAttributes();
                } else {
                    var = ipv.getInvariantAttributes();
                    var2 = ipv.getVariantAttributes();
                }

                List requestMarkers = new ArrayList();
                byte[] request;
                try {
                    request = requestResponse.getRequest();
                } catch (Exception e) {
                    return;
                }
                responseCode = new Integer(r.getStatusCode());
                IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);

                if ((!isresponsecode || isresponsecode && utils.isResponseCode(responsecode, negativerc, responseCode)) && (!iscontenttype || iscontenttype && utils.isContentType(contenttype, negativect, r))) {
                    if (var.containsAll(variationAttributes) && !var2.containsAll(variationAttributes)) {
                        int start = 0;
                        byte[] match = helpers.stringToBytes(payload);
                        int end = 0;
                        while (start < request.length) {
                            end = end + 1;
                            if (end == 30) {
                                break;
                            }
                            start = helpers.indexOf(request, match, false, start, request.length);
                            if (start == -1) {
                                break;
                            }
                            requestMarkers.add(new int[]{start, start + match.length});
                            start += match.length;
                        }
                        callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                                new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                                "BurpBounty - " + issuename, "Vulnerable parameter: " + insertionPoint.getInsertionPointName() + ".<br/>" + issuedetail.replace("<payload>", helpers.urlEncode(payload)), issueseverity,
                                issueconfidence, remediationdetail.replace("<payload>", helpers.urlEncode(payload)), issuebackground.replace("<payload>", helpers.urlEncode(payload)),
                                remediationbackground.replace("<payload>", helpers.urlEncode(payload))));
                        return;

                    }
                }
            }
        } catch (Exception ex) {
            System.out.println("ActiveScanner line 566: " + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }

    }

    public void contentLengthMatchType(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String payload, String rule_name) {

        try {
            Boolean isduplicated = utils.checkDuplicated(baseRequestResponse, issuename, insertionPoint);

            if (!isduplicated) {

                IHttpService httpService = baseRequestResponse.getHttpService();
                IHttpRequestResponse requestResponse;
                try {
                    requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers, ""));
                } catch (Exception e) {
                    return;
                }
                if (requestResponse == null) {
                    return;
                }
                IResponseInfo r;
                IResponseInfo rbase;

                try {
                    r = helpers.analyzeResponse(requestResponse.getResponse());
                    rbase = helpers.analyzeResponse(baseRequestResponse.getResponse());
                } catch (Exception e) {
                    return;
                }

                try {
                    if (requestResponse.getResponse() == null || baseRequestResponse.getResponse() == null) {
                        return;
                    }
                    r = helpers.analyzeResponse(requestResponse.getResponse());
                    rbase = helpers.analyzeResponse(baseRequestResponse.getResponse());
                } catch (Exception ex) {
                    System.out.println("ActiveScanner line 608: " + ex.getMessage());
                    for (StackTraceElement element : ex.getStackTrace()) {
                        System.out.println(element);
                    }
                    return;
                }

                Integer responseCode = new Integer(r.getStatusCode());
                Integer responseCodeBase = new Integer(rbase.getStatusCode());
                IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);

                if ((!isresponsecode || isresponsecode && utils.isResponseCode(responsecode, negativerc, responseCode) && utils.isResponseCode(responsecode, negativerc, responseCodeBase)) && (!iscontenttype || iscontenttype && utils.isContentType(contenttype, negativect, r))) {
                    int baseResponseContentLength = utils.getContentLength(baseRequestResponse);
                    int currentResponseContentLength = utils.getContentLength(requestResponse);

                    if (Math.abs(baseResponseContentLength - currentResponseContentLength) > Integer.parseInt(contentLength)) {
                        List responseMarkers = new ArrayList(1);
                        String grep = "CONTENT-LENGTH:";
                        responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep),
                            helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep) + grep.length()});

                        callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                                new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, responseMarkers)},
                                "BurpBounty - " + issuename, "Vulnerable parameter: " + insertionPoint.getInsertionPointName() + ".<br/>" + issuedetail.replace("<payload>", helpers.urlEncode(payload)).replace("<grep>", helpers.urlEncode(grep)), issueseverity,
                                issueconfidence, remediationdetail.replace("<payload>", helpers.urlEncode(payload)).replace("<grep>", helpers.urlEncode(grep)), issuebackground.replace("<payload>", helpers.urlEncode(payload)).replace("<grep>", helpers.urlEncode(grep)),
                                remediationbackground.replace("<payload>", helpers.urlEncode(payload)).replace("<grep>", helpers.urlEncode(grep))));
                        return;
                    }
                }

            }
        } catch (Exception ex) {
            System.out.println("ActiveScanner line 502: " + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }

    }

    public void CollaboratorMatchType(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String payload, String bchost, String rule_name, IBurpCollaboratorClientContext CollaboratorClientContext2) {

        int loop = 0;
        Boolean redirect = true;
        try {
            if (bchost.isEmpty()) {
                bchost = CollaboratorClientContext2.generatePayload(true);
                String subdomain = generateString();
                bchost = subdomain + "." + bchost;
            }
        } catch (Exception ex) {
            return;
        }

        try {

            Boolean isduplicated = utils.checkDuplicated(baseRequestResponse, issuename, insertionPoint);

            if (!isduplicated) {
                IHttpService httpService = baseRequestResponse.getHttpService();

                payload = payload.replace("{BC}", bchost);
                IHttpRequestResponse requestResponse;
                try {
                    requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers, bchost));
                } catch (Exception e) {
                    return;
                }
                if (requestResponse == null) {
                    return;
                }

                IResponseInfo r;

                try {
                    if (requestResponse.getResponse() == null) {
                        return;
                    }
                    r = helpers.analyzeResponse(requestResponse.getResponse());
                } catch (Exception ex) {
                    System.out.println("ActiveScanner line 685: " + ex.getMessage());
                    for (StackTraceElement element : ex.getStackTrace()) {
                        System.out.println(element);
                    }
                    return;
                }

                burpCollaboratorData.setIssueProperties(requestResponse, bchost, issuename, issuedetail.replace("<payload>", helpers.urlEncode(payload)), issueseverity.replace("<payload>", helpers.urlEncode(payload)), issueconfidence.replace("<payload>", (payload)), remediationdetail.replace("<payload>", (payload)), issuebackground.replace("<payload>", (payload)), remediationbackground.replace("<payload>", (payload)));
                Integer responseCode = new Integer(r.getStatusCode());

                do {
                    if (responseCodes.contains(responseCode) && loop < limitredirect) {
                        httpService = requestResponse.getHttpService();
                        URL url = null;
                        try {
                            url = utils.getRedirection(requestResponse, httpService, redirtype);
                        } catch (NullPointerException e) {
                            redirect = false;
                        }

                        if (url != null) {
                            try {
                                byte[] checkRequest = helpers.buildHttpRequest(url);
                                checkRequest = utils.getMatchAndReplace(headers, checkRequest, payload, bchost);

                                int port = 0;

                                if (url.getPort() == -1) {
                                    port = url.getDefaultPort();
                                }

                                IHttpService newrequest = helpers.buildHttpService(url.getHost(), port, url.getProtocol());

                                requestResponse = callbacks.makeHttpRequest(newrequest, checkRequest);
                            } catch (Exception e) {
                                return;
                            }
                            if (requestResponse == null) {
                                return;
                            }

                            try {
                                if (requestResponse.getResponse() == null) {
                                    return;
                                }
                                r = helpers.analyzeResponse(requestResponse.getResponse());
                            } catch (Exception ex) {
                                System.out.println("ActiveScanner line 735: " + ex.getMessage());
                                for (StackTraceElement element : ex.getStackTrace()) {
                                    System.out.println(element);
                                }
                                return;
                            }
                            responseCode = new Integer(r.getStatusCode());
                        }
                        loop += 1;
                    } else {
                        redirect = false;
                    }
                } while (redirect);
            }
        } catch (Exception ex) {
            System.out.println("ActiveScanner line 589: " + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }

    }

    public void stringRegexMatchType(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String payload, String rule_name,IBurpCollaboratorClientContext CollaboratorClientContext2, String bchost) {
        int loop = 0;
        Boolean redirect = true;
        try {
            if (bchost.isEmpty()) {
                bchost = CollaboratorClientContext2.generatePayload(true);
                String subdomain = generateString();
                bchost = subdomain + "." + bchost;
            }
        } catch (Exception ex) {
            bchost = "";
        }

        //multiarray
        int grep_index = 0;
        ArrayList<ArrayList<String>> greps_final = new ArrayList<>();
        IScanIssue matches = null;

        try {
            Boolean isduplicated = utils.checkDuplicated(baseRequestResponse, issuename, insertionPoint);

            if (!isduplicated) {
                IHttpService httpService = baseRequestResponse.getHttpService();

                greps_final.add(new ArrayList());
                for (String grep : greps) {

                    String[] tokens = grep.split(",", 3);

                    if (tokens[0].equals("true")) {
                        if (tokens[1].equals("And") || tokens[1].equals("")) {
                            if (!tokens[2].equals("")) {
                                greps_final.get(grep_index).add(tokens[2]);
                            }
                        } else {
                            if (!tokens[2].equals("")) {
                                if (!greps_final.get(0).isEmpty()) {
                                    greps_final.add(new ArrayList());
                                    grep_index = grep_index + 1;
                                    greps_final.get(grep_index).add(tokens[2]);
                                } else {
                                    greps_final.get(grep_index).add(tokens[2]);
                                }
                            }
                        }
                    }
                }
                IHttpRequestResponse requestResponse;
                try {
                    requestResponse = callbacks.makeHttpRequest(httpService, new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload), headers, bchost));
                } catch (NullPointerException e) {
                    return;
                }
                if (requestResponse == null) {
                    return;
                }

                IHttpRequestResponse redirectRequestResponse = requestResponse;
                IResponseInfo r;

                try {
                    if (redirectRequestResponse.getResponse() == null) {
                        return;

                    }
                    r = helpers.analyzeResponse(redirectRequestResponse.getResponse());
                } catch (Exception ex) {
                    System.out.println("ActiveScanner line 816: " + ex.getMessage());
                    for (StackTraceElement element : ex.getStackTrace()) {
                        System.out.println(element);
                    }
                    return;
                }

                Integer responseCode = new Integer(r.getStatusCode());
                IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);

                if ((!isresponsecode || isresponsecode && utils.isResponseCode(responsecode, negativerc, responseCode)) && (!iscontenttype || iscontenttype && utils.isContentType(contenttype, negativect, r))) {
                    for (int x = 0; x <= grep_index; x++) {
                        if (!greps_final.get(x).isEmpty()) {
                            matches = gm.getResponseMatches(requestResponse, payload, greps_final.get(x), issuename, "Vulnerable parameter: " + insertionPoint.getInsertionPointName() + ".<br/>" + issuedetail, issuebackground, remediationdetail, remediationbackground, charstourlencode, matchtype,
                                    issueseverity, issueconfidence, notresponse, casesensitive, urlencode, excludeHTTP, onlyHTTP);
                            //mirar si peta asi
                            if (matches != null) {
                                callbacks.addScanIssue(matches);
                                return;
                            }
                        }

                    }
                }
                do {
                    if (responseCodes.contains(responseCode) && redirtype != 1 && loop < maxredirect && maxredirect < limitredirect) {
                        httpService = requestResponse.getHttpService();
                        URL url = null;
                        try {
                            url = utils.getRedirection(requestResponse, httpService, redirtype);
                        } catch (NullPointerException e) {
                            redirect = false;
                        }

                        if (url != null) {
                            try {
                                byte[] checkRequest = helpers.buildHttpRequest(url);
                                checkRequest = utils.getMatchAndReplace(headers, checkRequest, payload, "");
                                int port = 0;

                                if (url.getPort() == -1) {
                                    port = url.getDefaultPort();
                                }

                                IHttpService newrequest = helpers.buildHttpService(url.getHost(), port, url.getProtocol());
                                requestResponse = callbacks.makeHttpRequest(newrequest, checkRequest);
                            } catch (Exception e) {
                                return;
                            }

                            if (requestResponse == null) {
                                return;
                            }

                            try {
                                if (requestResponse.getResponse() == null) {
                                    return;

                                }
                                r = helpers.analyzeResponse(requestResponse.getResponse());
                            } catch (Exception ex) {
                                System.out.println("ActiveScanner line 880: " + ex.getMessage());
                                for (StackTraceElement element : ex.getStackTrace()) {
                                    System.out.println(element);
                                }
                                return;
                            }
                            responseCode = new Integer(r.getStatusCode());
                            requestInfo = helpers.analyzeRequest(baseRequestResponse);

                            if ((!isresponsecode || isresponsecode && utils.isResponseCode(responsecode, negativerc, responseCode)) && (!iscontenttype || iscontenttype && utils.isContentType(contenttype, negativect, r))) {
                                for (int x = 0; x <= grep_index; x++) {
                                    if (!greps_final.get(x).isEmpty()) {
                                        matches = gm.getResponseMatches(requestResponse, payload, greps_final.get(x), issuename, "Vulnerable parameter: " + insertionPoint.getInsertionPointName() + ".<br/>" + issuedetail, issuebackground, remediationdetail, remediationbackground, charstourlencode, matchtype,
                                                issueseverity, issueconfidence, notresponse, casesensitive, urlencode, excludeHTTP, onlyHTTP);
                                        //mirar si peta asi
                                        if (matches != null) {
                                            callbacks.addScanIssue(matches);
                                            return;
                                        }
                                    }

                                }

                            }
                        } else {
                            redirect = false;
                        }
                    } else {
                        redirect = false;
                    }
                    loop += 1;
                } while (redirect);
            }
        } catch (Exception ex) {
            System.out.println("ActiveScanner line 729: " + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public static String generateString() {
        String uuid = UUID.randomUUID().toString().replace("-", "").replace("7", "");
        return "7"+uuid+"7";
    }
}
