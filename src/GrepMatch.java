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

public class GrepMatch {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    String name;
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
        name = "";
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

    public IScanIssue getResponseMatches(IHttpRequestResponse requestResponse, String payload, String grep, String name, String issuename, String issuedetail, String issuebackground,
            String remediationdetail, String remediationbackground, String charstourlencode, int matchtype, String issueseverity, String issueconfidence, boolean notresponse,
            boolean casesensitive, boolean urlencode, boolean excludeHTTP, boolean onlyHTTP) {
        IResponseInfo response = helpers.analyzeResponse(requestResponse.getResponse());

        if (response == null) {
            return null;
        }

        //Start regex grep 
        if (matchtype == 2) {
            if (casesensitive && !notresponse && !excludeHTTP && !onlyHTTP) {
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()));
                if (m.find()) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).indexOf(m.group()),
                        helpers.bytesToString(requestResponse.getResponse()).indexOf(m.group()) + m.group().length()});

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && !notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);

                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(body));
                if (m.find()) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).indexOf(m.group()),
                        helpers.bytesToString(requestResponse.getResponse()).indexOf(m.group()) + m.group().length()});

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && !notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                Matcher m = null;
                String text = "";
                for (String header : response.getHeaders()) {
                    Pattern p = Pattern.compile(grep);
                    m = p.matcher(header);
                    if (m.find()) {
                        text = m.group();
                        found = true;
                    }

                }

                if (found) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).indexOf(text),
                        helpers.bytesToString(requestResponse.getResponse()).indexOf(text) + text.length()});

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && !excludeHTTP && !onlyHTTP) {
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()).toUpperCase());
                if (m.find()) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(m.group()),
                        helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(m.group()) + m.group().length()});

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(body).toUpperCase());
                if (m.find()) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(m.group()),
                        helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(m.group()) + m.group().length()});

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                Matcher m = null;
                String text = "";
                for (String header : response.getHeaders()) {
                    Pattern p = Pattern.compile(grep.toUpperCase());
                    m = p.matcher(header.toUpperCase());
                    if (m.find()) {
                        text = m.group();
                        found = true;
                    }

                }
                if (found) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(text),
                        helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(text) + text.length()});

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && notresponse && !excludeHTTP && !onlyHTTP) {
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()));

                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if (i.equals(-1) || e.equals(-1)) {
                    requestMarkers.add(new int[]{0, 0});
                } else {
                    requestMarkers.add(new int[]{i, e});
                }

                if (!m.find()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }

            } else if (casesensitive && notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(body));

                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if (i.equals(-1) || e.equals(-1)) {
                    requestMarkers.add(new int[]{0, 0});
                } else {
                    requestMarkers.add(new int[]{i, e});
                }

                if (!m.find()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }

            } else if (casesensitive && notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                Matcher m = null;
                for (String header : response.getHeaders()) {
                    Pattern p = Pattern.compile(grep);
                    m = p.matcher(header);
                    if (m.find()) {
                        found = true;
                    }

                }
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if (i.equals(-1) || e.equals(-1)) {
                    requestMarkers.add(new int[]{0, 0});
                } else {
                    requestMarkers.add(new int[]{i, e});
                }

                if (!found) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }

            } else if (!casesensitive && notresponse && !excludeHTTP && !onlyHTTP) {
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()).toUpperCase());
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if (i.equals(-1) || e.equals(-1)) {
                    requestMarkers.add(new int[]{0, 0});
                } else {
                    requestMarkers.add(new int[]{i, e});
                }
                if (!m.find()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(body).toUpperCase());
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if (i.equals(-1) || e.equals(-1)) {
                    requestMarkers.add(new int[]{0, 0});
                } else {
                    requestMarkers.add(new int[]{i, e});
                }
                if (!m.find()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                Matcher m = null;
                for (String header : response.getHeaders()) {
                    Pattern p = Pattern.compile(grep.toUpperCase());
                    m = p.matcher(header.toUpperCase());
                    if (m.find()) {
                        found = true;
                    }

                }
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if (i.equals(-1) || e.equals(-1)) {
                    requestMarkers.add(new int[]{0, 0});
                } else {
                    requestMarkers.add(new int[]{i, e});
                }
                if (!found) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else {
                return null;
            }
            //End regex grep    
            //Start Simple String, payload in response and payload without encode 
        } else {
            if (casesensitive && !notresponse && !excludeHTTP && !onlyHTTP) {
                if (helpers.bytesToString(requestResponse.getResponse()).contains(grep)) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).indexOf(grep),
                        helpers.bytesToString(requestResponse.getResponse()).indexOf(grep) + grep.length()});
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && !notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);

                if (helpers.bytesToString(body).contains(grep)) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).indexOf(grep), helpers.bytesToString(requestResponse.getResponse()).indexOf(grep) + grep.length()});
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && !notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                for (String header : response.getHeaders()) {
                    if (header.contains(grep)) {
                        found = true;
                    }
                }
                if (found) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).indexOf(grep),
                        helpers.bytesToString(requestResponse.getResponse()).indexOf(grep) + grep.length()});
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && !excludeHTTP && !onlyHTTP) {
                if (helpers.bytesToString(requestResponse.getResponse()).toUpperCase().contains(grep.toUpperCase())) {

                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep.toUpperCase()),
                        helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length()});

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);

                if (helpers.bytesToString(body).toUpperCase().contains(grep.toUpperCase())) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep.toUpperCase()),
                        helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length()});

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                for (String header : response.getHeaders()) {
                    if (header.toUpperCase().contains(grep.toUpperCase())) {
                        found = true;
                    }

                }
                if (found) {
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep.toUpperCase()),
                        helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length()});

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, responseMarkers)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && notresponse && !excludeHTTP && !onlyHTTP) {
                if (!helpers.bytesToString(requestResponse.getResponse()).toUpperCase().contains(grep.toUpperCase())) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);

                if (!helpers.bytesToString(body).toUpperCase().contains(grep.toUpperCase())) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                for (String header : response.getHeaders()) {
                    if (header.toUpperCase().contains(grep.toUpperCase())) {
                        found = true;
                    }

                }
                if (!found) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && notresponse && !excludeHTTP && !onlyHTTP) {
                if (!helpers.bytesToString(requestResponse.getResponse()).contains(grep)) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                if (!helpers.bytesToString(body).contains(grep)) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                for (String header : response.getHeaders()) {
                    if (header.contains(grep)) {
                        found = true;
                    }

                }
                if (found) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else {
                return null;
            }
            //End Simple String, payload in response and payload without encode
        }
    }

    public IScanIssue getRequestMatches(IHttpRequestResponse requestResponse, String grep, String name, String issuename, String issuedetail, String issuebackground,
            String remediationdetail, String remediationbackground, int matchtype, String issueseverity, String issueconfidence, boolean casesensitive, boolean notresponse, boolean excludeHTTP, boolean onlyHTTP) {
        IRequestInfo request = helpers.analyzeRequest(requestResponse.getRequest());

        if (request == null) {
            return null;
        }

        //Start regex grep 
        if (matchtype == 2) {
            if (casesensitive && !notresponse && !excludeHTTP && !onlyHTTP) {
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getRequest()));
                if (m.find()) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).indexOf(grep);
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).indexOf(grep) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && !notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getRequest();
                int len = req.length - request.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, request.getBodyOffset(), body, 0, len);

                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(body));
                if (m.find()) {

                    List requestMarkers = new ArrayList(1);
                    requestMarkers.add(new int[]{helpers.bytesToString(requestResponse.getRequest()).indexOf(m.group()),
                        helpers.bytesToString(requestResponse.getRequest()).indexOf(m.group()) + m.group().length()});

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && !notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                Matcher m = null;
                String text = "";
                for (String header : request.getHeaders()) {
                    Pattern p = Pattern.compile(grep);
                    m = p.matcher(header);
                    if (m.find()) {
                        text = m.group();
                        found = true;
                    }

                }

                if (found) {
                    List requestMarkers = new ArrayList(1);
                    requestMarkers.add(new int[]{helpers.bytesToString(requestResponse.getRequest()).indexOf(text),
                        helpers.bytesToString(requestResponse.getRequest()).indexOf(text) + text.length()});

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && !excludeHTTP && !onlyHTTP) {
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getRequest()).toUpperCase());
                if (m.find()) {
                    List requestMarkers = new ArrayList(1);
                    requestMarkers.add(new int[]{helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(m.group()),
                        helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(m.group()) + m.group().length()});

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getRequest();
                int len = req.length - request.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, request.getBodyOffset(), body, 0, len);
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(body).toUpperCase());
                if (m.find()) {
                    List requestMarkers = new ArrayList(1);
                    requestMarkers.add(new int[]{helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(m.group()),
                        helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(m.group()) + m.group().length()});

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                Matcher m = null;
                String text = "";
                for (String header : request.getHeaders()) {
                    Pattern p = Pattern.compile(grep.toUpperCase());
                    m = p.matcher(header.toUpperCase());
                    if (m.find()) {
                        text = m.group();
                        found = true;
                    }

                }
                if (found) {
                    List requestMarkers = new ArrayList(1);
                    requestMarkers.add(new int[]{helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(text),
                        helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(text) + text.length()});

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && notresponse && !excludeHTTP && !onlyHTTP) {
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getRequest()));

                if (!m.find()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }

            } else if (casesensitive && notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getRequest();
                int len = req.length - request.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, request.getBodyOffset(), body, 0, len);
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(body));

                if (!m.find()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }

            } else if (casesensitive && notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                Matcher m = null;
                for (String header : request.getHeaders()) {
                    Pattern p = Pattern.compile(grep);
                    m = p.matcher(header);
                    if (m.find()) {
                        found = true;
                    }

                }

                if (!found) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }

            } else if (!casesensitive && notresponse && !excludeHTTP && !onlyHTTP) {
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getRequest()).toUpperCase());
                if (!m.find()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getRequest();
                int len = req.length - request.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, request.getBodyOffset(), body, 0, len);
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(body).toUpperCase());

                if (!m.find()) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                Matcher m = null;
                for (String header : request.getHeaders()) {
                    Pattern p = Pattern.compile(grep.toUpperCase());
                    m = p.matcher(header.toUpperCase());
                    if (m.find()) {
                        found = true;
                    }

                }
                if (!found) {
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else {
                return null;
            }
            //End regex grep    
            //Start Simple String
        } else {
            if (casesensitive && !notresponse && !excludeHTTP && !onlyHTTP) {
                if (helpers.bytesToString(requestResponse.getRequest()).contains(grep)) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && !notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getRequest();
                int len = req.length - request.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, request.getBodyOffset(), body, 0, len);

                if (helpers.bytesToString(body).contains(grep)) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && !notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                for (String header : request.getHeaders()) {
                    if (header.contains(grep)) {
                        found = true;
                    }
                }
                if (found) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && !excludeHTTP && !onlyHTTP) {
                if (helpers.bytesToString(requestResponse.getRequest()).toUpperCase().contains(grep.toUpperCase())) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getRequest();
                int len = req.length - request.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, request.getBodyOffset(), body, 0, len);

                if (helpers.bytesToString(body).toUpperCase().contains(grep.toUpperCase())) {

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                for (String header : request.getHeaders()) {
                    if (header.toUpperCase().contains(grep.toUpperCase())) {
                        found = true;
                    }

                }
                if (found) {

                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }

                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && notresponse && !excludeHTTP && !onlyHTTP) {
                if (!helpers.bytesToString(requestResponse.getRequest()).toUpperCase().contains(grep.toUpperCase())) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getRequest();
                int len = req.length - request.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, request.getBodyOffset(), body, 0, len);

                if (!helpers.bytesToString(body).toUpperCase().contains(grep.toUpperCase())) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                for (String header : request.getHeaders()) {
                    if (header.toUpperCase().contains(grep.toUpperCase())) {
                        found = true;
                    }

                }
                if (!found) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && notresponse && !excludeHTTP && !onlyHTTP) {
                if (!helpers.bytesToString(requestResponse.getRequest()).contains(grep)) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && notresponse && excludeHTTP && !onlyHTTP) {
                byte[] req = requestResponse.getRequest();
                int len = req.length - request.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, request.getBodyOffset(), body, 0, len);
                if (!helpers.bytesToString(body).contains(grep)) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (casesensitive && notresponse && !excludeHTTP && onlyHTTP) {
                boolean found = false;
                for (String header : request.getHeaders()) {
                    if (header.contains(grep)) {
                        found = true;
                    }

                }
                if (found) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                    Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                    if (i.equals(-1) || e.equals(-1)) {
                        requestMarkers.add(new int[]{0, 0});
                    } else {
                        requestMarkers.add(new int[]{i, e});
                    }
                    return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                            "BurpBounty - " + issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(grep)), issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                } else {
                    return null;
                }
            } else if (!casesensitive && !notresponse && !excludeHTTP && !onlyHTTP) {
                List<String> headers = request.getHeaders();
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase());
                Integer e = helpers.bytesToString(requestResponse.getRequest()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length();
                if (i.equals(-1) || e.equals(-1)) {
                    requestMarkers.add(new int[]{0, 0});
                } else {
                    requestMarkers.add(new int[]{i, e});
                }
                for (String header : headers) {
                    if (header.toUpperCase().contains("SET-COOKIE") && !header.toUpperCase().contains(grep.toUpperCase())) {
                        return new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                                new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)},
                                "BurpBounty - " + issuename, issuedetail, issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground);
                    }
                }
            } else {
                return null;
            }
            //End Simple String
        }
        return null;
    }
}
