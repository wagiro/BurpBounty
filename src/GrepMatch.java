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
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class GrepMatch {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    List<String> greps;

    public GrepMatch(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        greps = new ArrayList();
    }

    public IScanIssue getResponseMatches(IHttpRequestResponse requestResponse, String payload, List<String> greps, String issuename, String issuedetail, String issuebackground,
            String remediationdetail, String remediationbackground, String charstourlencode, int matchtype, String issueseverity, String issueconfidence, boolean notresponse,
            boolean casesensitive, boolean urlencode, boolean excludeHTTP, boolean onlyHTTP) {

        String responseString;
        String headers = "";
        Pattern p;
        Matcher m;
        IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
        byte[] request = requestResponse.getRequest();
        List<int[]> responseMarkers = new ArrayList();
        List<int[]> requestMarkers = new ArrayList();

        for (String grep : greps) {
            Boolean vuln = false;
            if (casesensitive || matchtype == 2) {
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
                String matches = "<br>";
                //Start regex grep
                int beginAt = 0;

                try {
                    if (excludeHTTP && !onlyHTTP) {
                        beginAt = responseInfo.getBodyOffset();
                        p = Pattern.compile(grep, Pattern.CASE_INSENSITIVE);
                        m = p.matcher(responseString);
                    } else if (!excludeHTTP && onlyHTTP) {
                        p = Pattern.compile(grep, Pattern.CASE_INSENSITIVE);
                        m = p.matcher(headers);
                    } else {
                        p = Pattern.compile(grep, Pattern.CASE_INSENSITIVE);
                        m = p.matcher(responseString);
                    }
                } catch (PatternSyntaxException pse) {
                    callbacks.printError("Grep Match line 93 Incorrect regex: " + pse.getPattern());
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
                    if (m.find(beginAt)) {
                        return null;
                    }

                } else {
                    while (m.find(beginAt)) {
                        responseMarkers.add(new int[]{m.start(), m.end()});
                        matches = matches + m.group().toLowerCase() + "<br>";
                        beginAt = m.end();
                        vuln = true;
                    }

                    if (!vuln) {
                        return null;
                    }
                }
                //End regex grep    
                //Start Simple String, payload in response and payload without encode 
            } else {
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
                    if (responseString.contains(grep)) {
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
                        vuln = true;
                    }

                    if (!vuln) {
                        return null;
                    }
                }
                //End Simple String, payload in response and payload without encode
            }
        }

        Collections.sort(responseMarkers, new Comparator<int[]>() {
            private static final int INDEX = 0;

            @Override
            public int compare(int[] o1, int[] o2) {
                return Integer.compare(o1[INDEX], o2[INDEX]);
            }
        });

        return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)
                },
                "BurpBounty - " + issuename, issuedetail
                        .replace(
                                "<payload>", helpers.urlEncode(payload)),
                issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
    }

    public Object[] getRequestMatches(IHttpRequestResponse requestResponse, List<String> greps, String issuename, String issuedetail, String issuebackground,
            String remediationdetail, String remediationbackground, int matchtype, String issueseverity, String issueconfidence, Boolean casesensitive, Boolean notresponse) {

        String data = "";
        Pattern p;
        Matcher m;
        byte[] request = requestResponse.getRequest();
        List<int[]> requestMarkers = new ArrayList();
        List<IScannerInsertionPoint> insertionPoints = new ArrayList();

        for (String grep : greps) {
            String[] tokens = grep.split(",",2);
            String value = tokens[1];
            grep = value;
            Boolean vuln = false;

            if (casesensitive && matchtype == 1) {

                data = helpers.bytesToString(requestResponse.getRequest());

            } else if (matchtype == 1) {

                data = helpers.bytesToString(requestResponse.getRequest()).toUpperCase();
                grep = grep.toUpperCase();

            } else if (matchtype == 2) {
                Matcher matcher;
                try {
                    p = Pattern.compile(grep, Pattern.CASE_INSENSITIVE);
                } catch (PatternSyntaxException pse) {
                    callbacks.printError("Grep Match line 251 Incorrect regex: " + pse.getPattern());
                    return null;
                }

                data = helpers.bytesToString(requestResponse.getRequest());
                matcher = p.matcher(data);

            }

            if (matchtype == 2) {
                //Start regex grep
                int beginAt = 0;
                try {
                    p = Pattern.compile(grep, Pattern.CASE_INSENSITIVE);
                    m = p.matcher(helpers.bytesToString(requestResponse.getRequest()));
                } catch (PatternSyntaxException pse) {
                    callbacks.printError("Grep Match line 251 Incorrect regex: " + pse.getPattern());
                    return null;
                }

                if (m.find(beginAt)) {
                    if (notresponse) {
                        return null;
                    } else {
                        while (m.find(beginAt)) {
                            requestMarkers.add(new int[]{m.start(), m.end()});
                            beginAt = m.end();
                            vuln = true;
                        }

                        if (!vuln) {
                            return null;
                        }
                    }
                } else {
                    return null;
                }
                //End regex grep    
                //Start Simple String, payload in response and payload without encode 
            } else {
                int beginAt = 0;

                if (data.contains(grep.toUpperCase())) {
                    if (notresponse) {
                        return null;
                    } else {
                        byte[] match = helpers.stringToBytes(grep);
                        while (beginAt < request.length) {
                            beginAt = helpers.indexOf(request, match, false, beginAt, request.length);
                            if (beginAt == -1) {
                                break;
                            }
                            requestMarkers.add(new int[]{beginAt, beginAt + match.length});
                            beginAt += match.length;
                            vuln = true;
                        }

                        if (!vuln) {
                            return null;
                        }
                    }
                } else {
                    return null;
                }
                //End Simple String, payload and payload without encode
            }
        }

        Collections.sort(requestMarkers, new Comparator<int[]>() {
            private static final int INDEX = 0;

            @Override
            public int compare(int[] o1, int[] o2) {
                return Integer.compare(o1[INDEX], o2[INDEX]);
            }
        });

        return new Object[]{new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
            "BurpBounty - " + issuename, issuedetail, issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground), insertionPoints};
    }
}
