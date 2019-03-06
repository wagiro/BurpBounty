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

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.IRequestInfo;
import burp.IScanIssue;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class GrepMatch {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    String issuename;
    String issuedetail;
    String issuebackground;
    String remediationdetail;
    String remediationbackground;
    int scanner;
    int matchtype;
    String issueseverity;
    String issueconfidence;
    boolean notresponse;
    boolean excludeHTTP;
    boolean onlyHTTP;
    boolean casesensitive;
    boolean iscontenttype;
    boolean isresponsecode;
    String contenttype;
    String responsecode;
    List<String> greps;

    public GrepMatch(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        greps = new ArrayList();
        issuename = "";
        issuedetail = "";
        issuebackground = "";
        remediationdetail = "";
        remediationbackground = "";
        scanner = 0;
        matchtype = 0;
        issueseverity = "";
        issueconfidence = "";
        notresponse = false;
        excludeHTTP = false;
        onlyHTTP = false;
        casesensitive = false;
        iscontenttype = false;
        isresponsecode = false;
        contenttype = "";
        responsecode = "";

    }

    public IScanIssue getResponseMatches(IHttpRequestResponse requestResponse, String payload, String grep, String issuename, String issuedetail, String issuebackground,
            String remediationdetail, String remediationbackground, String charstourlencode, int matchtype, String issueseverity, String issueconfidence, boolean notresponse,
            boolean casesensitive, boolean urlencode, boolean excludeHTTP, boolean onlyHTTP) {

        String responseString;
        String headers = "";
        Pattern p;
        Matcher m;
        IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
        byte[] request = requestResponse.getRequest();

        if (casesensitive) {
            responseString = helpers.bytesToString(requestResponse.getResponse());
            for (String header : responseInfo.getHeaders()) {
                headers += header + "\r\n";
            }
        } else {
            responseString = helpers.bytesToString(requestResponse.getResponse()).toUpperCase();
            grep = grep.toUpperCase();
            for (String header : responseInfo.getHeaders()) {
                headers += header.toUpperCase() + "\r\n";
            }
        }

        if (matchtype == 2) {
            List<int[]> responseMarkers = new ArrayList();
            List<int[]> requestMarkers = new ArrayList();
            String matches = "<br>";
            //Start regex grep
            int beginAt = 0;

            try {
                if (excludeHTTP && !onlyHTTP) {
                    beginAt = responseInfo.getBodyOffset();
                    p = Pattern.compile(grep);
                    m = p.matcher(responseString);
                } else if (!excludeHTTP && onlyHTTP) {
                    p = Pattern.compile(grep);
                    m = p.matcher(headers);
                } else {
                    p = Pattern.compile(grep);
                    m = p.matcher(responseString);
                }
            } catch (PatternSyntaxException pse) {
                callbacks.printError("Incorrect regex: " + pse.getPattern());
                return null;
            }

            if (!payload.equals("")) {
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
            }

            if (notresponse) {
                if (!m.find(beginAt)) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replace("<payload>", helpers.urlEncode(payload)),
                            issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }

            } else {
                while (m.find(beginAt)) {
                    responseMarkers.add(new int[]{m.start(), m.end()});
                    matches = matches + m.group().toLowerCase() + "<br>";
                    beginAt = m.end();
                }

                if (!responseMarkers.isEmpty()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replace("<payload>", helpers.urlEncode(payload)).replace("<grep>", helpers.urlEncode(matches)),
                            issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            }
            //End regex grep    
            //Start Simple String, payload in response and payload without encode 
        } else {

            List<int[]> responseMarkers = new ArrayList();
            List<int[]> requestMarkers = new ArrayList();
            int beginAt = 0;
            byte[] response = helpers.stringToBytes(responseString);

            if (excludeHTTP && !onlyHTTP) {
                beginAt = responseInfo.getBodyOffset();
            } else if (!excludeHTTP && onlyHTTP) {
                response = helpers.stringToBytes(headers);
            }

            if (!payload.equals("")) {
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
            }

            if (notresponse) {
                if (!responseString.contains(grep)) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replace("<payload>", helpers.urlEncode(payload)),
                            issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }

            } else {

                byte[] match = helpers.stringToBytes(grep);

                while (beginAt < response.length) {
                    beginAt = helpers.indexOf(response, match, false, beginAt, response.length);
                    if (beginAt == -1) {
                        break;
                    }
                    responseMarkers.add(new int[]{beginAt, beginAt + match.length});
                    beginAt += match.length;
                }

                if (!responseMarkers.isEmpty()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replace("<payload>", helpers.urlEncode(payload)).replace("<grep>", helpers.urlEncode(grep)),
                            issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            }
            //End Simple String, payload in response and payload without encode
        }
    }

    public IScanIssue getRequestMatches(IHttpRequestResponse requestResponse, String grep, String issuename, String issuedetail, String issuebackground,
            String remediationdetail, String remediationbackground, int matchtype, String issueseverity, String issueconfidence, boolean casesensitive, boolean notresponse,
            boolean excludeHTTP, boolean onlyHTTP) {

        if (requestResponse.getRequest() == null) {
            return null;
        }

        String requestString;
        String headers = "";
        Pattern p;
        Matcher m;
        byte[] request = requestResponse.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse.getRequest());

        if (casesensitive) {
            requestString = helpers.bytesToString(requestResponse.getRequest());
            for (String header : requestInfo.getHeaders()) {
                headers += header + "\r\n";
            }
        } else {
            requestString = helpers.bytesToString(requestResponse.getResponse()).toUpperCase();
            grep = grep.toUpperCase();
            for (String header : requestInfo.getHeaders()) {
                headers += header.toUpperCase() + "\r\n";
            }
        }

        if (matchtype == 2) {
            List<int[]> requestMarkers = new ArrayList();
            String matches = "<br>";
            //Start regex grep
            int beginAt = 0;
            try {
                if (excludeHTTP && !onlyHTTP) {
                    beginAt = requestInfo.getBodyOffset();
                    p = Pattern.compile(grep);
                    m = p.matcher(requestString);
                } else if (!excludeHTTP && onlyHTTP) {
                    p = Pattern.compile(grep);
                    m = p.matcher(headers);
                } else {
                    p = Pattern.compile(grep);
                    m = p.matcher(requestString);
                }
            } catch (PatternSyntaxException pse) {
                callbacks.printError("Incorrect regex: " + pse.getPattern());
                return null;
            }

            if (notresponse) {
                if (!m.find(beginAt)) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replace("<grep>", helpers.urlEncode(grep)),
                            issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }

            } else {
                while (m.find(beginAt)) {
                    requestMarkers.add(new int[]{m.start(), m.end()});
                    matches = matches + m.group().toLowerCase() + "<br>";
                    beginAt = m.end();
                }

                if (!requestMarkers.isEmpty()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replace("<grep>", helpers.urlEncode(matches)),
                            issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            }
            //End regex grep    
            //Start Simple String, payload in response and payload without encode 
        } else {
            List<int[]> requestMarkers = new ArrayList();
            int beginAt = 0;

            if (excludeHTTP && !onlyHTTP) {
                beginAt = requestInfo.getBodyOffset();
            } else if (!excludeHTTP && onlyHTTP) {
                request = helpers.stringToBytes(headers);
            }

            if (notresponse) {
                if (!requestString.contains(grep)) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replace("<grep>", helpers.urlEncode(grep)),
                            issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }

            } else {
                byte[] match = helpers.stringToBytes(grep);
                while (beginAt < request.length) {
                    beginAt = helpers.indexOf(request, match, false, beginAt, request.length);
                    if (beginAt == -1) {
                        break;
                    }
                    requestMarkers.add(new int[]{beginAt, beginAt + match.length});
                    beginAt += match.length;
                }

                if (!requestMarkers.isEmpty()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replace("<grep>", helpers.urlEncode(grep)),
                            issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            }
            //End Simple String, payload and payload without encode
        }
    }
}
