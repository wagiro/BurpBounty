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

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.IRequestInfo;
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
                    System.out.println("GrepMatch line 93 Incorrect regex: " + pse.getPattern());
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
                    int end = 0;
                    while (m.find(beginAt)) {
                        end = end + 1;
                        if (end == 30) {
                            break;
                        }
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
                }

                if (notresponse) {
                    if (responseString.contains(grep)) {
                        return null;
                    }

                } else {

                    byte[] match = helpers.stringToBytes(grep);
                    int end = 0;
                    while (beginAt < response.length) {
                        end = end + 1;
                        if (end == 30) {
                            break;
                        }
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

        Collections.sort(requestMarkers, new Comparator<int[]>() {
            private static final int INDEX = 0;

            @Override
            public int compare(int[] o1, int[] o2) {
                return Integer.compare(o1[INDEX], o2[INDEX]);
            }
        });

        String results_req = "";
        String results_resp = "";
        for (int[] res : responseMarkers) {
            results_resp = results_resp + "<br/>  " + helpers.urlDecode(helpers.bytesToString(requestResponse.getResponse()).substring(res[0], res[1]));
        }

        for (int[] req : requestMarkers) {
            results_req = results_req + "<br/>  " + helpers.urlDecode(helpers.bytesToString(requestResponse.getRequest()).substring(req[0], req[1]));
        }

        return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)
                }, "BurpBounty - " + issuename, issuedetail.replace("<payload>", results_req).replace("<grep>", results_resp), issueseverity.replace("<payload>", results_req).replace("<grep>", results_resp), issueconfidence.replace("<payload>", results_req).replace("<grep>", results_resp), remediationdetail.replace("<payload>", results_req).replace("<grep>", results_resp), issuebackground.replace("<payload>", results_req).replace("<grep>", results_resp), remediationbackground.replace("<payload>", results_req).replace("<grep>", results_resp));
    }

    public Object[] getRequestMatches(IHttpRequestResponse requestResponse, List<String> greps, String issuename, String issuedetail, String issuebackground,
            String remediationdetail, String remediationbackground, int matchtype, String issueseverity, String issueconfidence, Boolean casesensitive, Boolean notresponse, Boolean scanas, int scantype) {

        String data = "";
        Pattern p;
        Matcher m;
        byte[] request = requestResponse.getRequest();
        List<int[]> requestMarkers = new ArrayList();
        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse.getRequest());
        List<IScannerInsertionPoint> insertionPoints = new ArrayList();
        int matches = 0;
        List<int[]> requestMarkersInsertionPoints = new ArrayList();
        Boolean isInsertionPoint = true;

        for (String grep : greps) {
            String[] tokens = grep.split(",", 3);
            String insertionPoint = tokens[0];
            String where = tokens[1];
            String value = tokens[2];
            grep = value;

            if (casesensitive && matchtype == 1) {
                switch (insertionPoint) {
                    case "All Request":
                        data = helpers.bytesToString(requestResponse.getRequest());
                        isInsertionPoint = false;
                        break;
                    default:
                        break;
                }
            } else if (matchtype == 1) {
                switch (insertionPoint) {
                    case "All Request":
                        data = helpers.bytesToString(requestResponse.getRequest()).toUpperCase();
                        grep = grep.toUpperCase();
                        isInsertionPoint = false;
                        break;
                    default:
                        break;
                }
            } else if (matchtype == 2) {
                Matcher matcher;
                try {
                    p = Pattern.compile(grep, Pattern.CASE_INSENSITIVE);
                } catch (PatternSyntaxException pse) {
                    System.out.println("Grep Match line 251 Incorrect regex: " + pse.getPattern());
                    return null;
                }

                switch (insertionPoint) {
                    case "All Request":
                        matcher = p.matcher(helpers.bytesToString(requestResponse.getRequest()));
                        if (matcher.find()) {
                            data = helpers.bytesToString(requestResponse.getRequest());
                        }
                        isInsertionPoint = false;
                        break;
                    default:
                        break;
                }
            }

            try {
                if (!isInsertionPoint) {
                    if (matchtype == 2) {
                        //Start regex grep
                        int beginAt = 0;
                        if (!data.isEmpty()) {
                            try {
                                p = Pattern.compile(grep, Pattern.CASE_INSENSITIVE);
                                m = p.matcher(data);
                            } catch (Exception e) {
                                System.out.println("Grep Match line 251 Incorrect regex: " + e.getMessage());
                                return null;
                            }
                            int end = 0;
                            while (m.find(beginAt)) {
                                end = end + 1;
                                if (end == 30) {
                                    break;
                                }
                                if (notresponse) {
                                    return null;
                                } else {
                                    matches = matches + 1;
                                    requestMarkers.add(new int[]{m.start(), m.end()});
                                    beginAt = m.end();
                                }
                            }
                        }
                        //End regex grep    
                        //Start Simple String, payload in response and payload without encode 
                    } else {
                        int beginAt = 0;

                        if (data.contains(grep.toUpperCase())) {

                            if (notresponse) {
                                return null;
                            } else {
                                matches = matches + 1;
                                //if (grep.length() >= 3) {
                                byte[] match = helpers.stringToBytes(grep);
                                int end = 1;
                                while (beginAt < request.length) {
                                    end = end + 1;
                                    if (end == 30) {
                                        break;
                                    }
                                    beginAt = helpers.indexOf(request, match, false, beginAt, request.length);
                                    if (beginAt == -1) {
                                        break;
                                    }

                                    requestMarkers.add(new int[]{beginAt, beginAt + match.length});
                                    beginAt += match.length;

                                }
                                //}
                            }
                        }
                        //End Simple String, payload and payload without encode
                    }
                } else {
                    if (matchtype == 2) {
                        //Start regex grep
                        int beginAt = 0;
                        String[] match = data.split(",", 3);
                        for (String single : match) {
                            if (!single.isEmpty()) {
                                try {
                                    p = Pattern.compile(grep, Pattern.CASE_INSENSITIVE);
                                    m = p.matcher(single);
                                } catch (PatternSyntaxException pse) {
                                    System.out.println("Grep Match line 251 Incorrect regex: " + pse.getPattern());
                                    return null;
                                }

                                if (m.find(beginAt)) {
                                    if (notresponse) {
                                        return null;
                                    } else {
                                        matches = matches + 1;
                                        requestMarkers.addAll(requestMarkersInsertionPoints);
                                    }
                                }
                            }
                        }
                    } else {
                        if (data.contains(grep.toUpperCase())) {

                            if (notresponse) {
                                return null;
                            } else {
                                matches = matches + 1;
                                requestMarkers.addAll(requestMarkersInsertionPoints);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Grep Match line 898: " + e.getMessage());
                return null;
            }
        }

        try {
            if (matches >= greps.size()) {
                Collections.sort(requestMarkers, new Comparator<int[]>() {
                    private static final int INDEX = 0;

                    @Override
                    public int compare(int[] o1, int[] o2) {
                        return Integer.compare(o1[INDEX], o2[INDEX]);
                    }
                });

                List<int[]> requestMarkers_noduplicates = new ArrayList();
                if (requestMarkers.size() == 1) {
                    requestMarkers_noduplicates = requestMarkers;
                } else {
                    for (int i = 0; i <= requestMarkers.size() - 1; i++) {
                        if (i == requestMarkers.size() - 1) {
                            requestMarkers_noduplicates.add(requestMarkers.get(i));
                        } else if (requestMarkers.get(i)[0] != requestMarkers.get(i + 1)[0]) {
                            requestMarkers_noduplicates.add(requestMarkers.get(i));
                        }
                    }
                }

                String results_req = "";
                for (int[] req : requestMarkers) {
                    results_req = results_req + "<br/>-  " + helpers.urlDecode(helpers.bytesToString(requestResponse.getRequest()).substring(req[0], req[1]).replace("\"", "").replace("'", ""));
                }

                return new Object[]{new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                    new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers_noduplicates, null)},
                    "BurpBounty - " + issuename, "It may be that the detected parameter is highlighted in red more times through the request. "
                    + "This is because of the marking system the burpsuite uses.<br/><br/>" + issuedetail.replace("<payload>", results_req), issueseverity.replace("<payload>", results_req), issueconfidence.replace("<payload>", results_req), remediationdetail.replace("<payload>", results_req), issuebackground.replace("<payload>", results_req), remediationbackground.replace("<payload>", results_req)), insertionPoints};
            } else {
                return null;
            }
        } catch (Exception e) {
            System.out.println("Grep Match line 898: " + e.getMessage());
            return null;
        }
    }
}
