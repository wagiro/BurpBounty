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
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author wagiro
 */
public class PassiveResponseScanner {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    JsonArray active_profiles;
    BurpBountyExtension bbe;
    Gson gson;
    CollaboratorData burpCollaboratorData;
    BurpBountyGui bbg;
    JsonArray allprofiles;
    Integer redirtype;
    Integer smartscandelay;
    String issuename;
    String issuedetail;
    String issuebackground;
    String remediationdetail;
    String remediationbackground;
    int matchtype;
    int scope;
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
    List<String> greps;
    ProfilesProperties profile_property;
    String urlextension;
    Boolean isurlextension;
    Boolean NegativeUrlExtension;
    ActiveScanner active_scanner;
    Utils utils;
    JsonArray activeprofiles;
    GrepMatch gm;

    public PassiveResponseScanner(BurpBountyExtension bbe, IBurpExtenderCallbacks callbacks, CollaboratorData burpCollaboratorData, JsonArray allprofiles, JsonArray activeprofiles, BurpBountyGui bbg) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        this.burpCollaboratorData = burpCollaboratorData;
        gson = new Gson();
        this.allprofiles = allprofiles;
        this.activeprofiles = activeprofiles;
        this.bbe = bbe;
        this.bbg = bbg;
        utils = new Utils(bbe, callbacks, burpCollaboratorData, allprofiles, bbg);
        gm = new GrepMatch(callbacks);
    }

    public void runResPScan(IHttpRequestResponse baseRequestResponse, JsonArray passiveresprofiles, JsonArray rules, List<String[]> urls, Boolean passive) {
        try {
            if (baseRequestResponse.getResponse() == null) {
                return;
            }

            for (int i = 0; i < passiveresprofiles.size(); i++) {
                IResponseInfo r;
                int grep_index = 0;
                ArrayList<ArrayList<String>> greps_final = new ArrayList<>();

                Object idata = passiveresprofiles.get(i);
                profile_property = gson.fromJson(idata.toString(), ProfilesProperties.class);

                setProfilesValues(profile_property);

                try {
                    r = helpers.analyzeResponse(baseRequestResponse.getResponse());
                } catch (NullPointerException e) {
                    System.out.println("PassiveResponseScanner line 616: " + e.getMessage());
                    return;
                }

                Boolean isduplicated = utils.checkDuplicatedPassiveResponse(baseRequestResponse, issuename);

                if (!isduplicated || passive) {

                    Integer responseCode = new Integer(r.getStatusCode());
                    IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);

                    if ((isresponsecode && !utils.isResponseCode(responsecode, negativerc, responseCode)) || (iscontenttype && !utils.isContentType(contenttype, negativect, r))) {
                        continue;
                    }

                    greps_final.add(new ArrayList());

                    for (String grep : greps) {
                        String[] tokens;

                        try {
                            tokens = grep.split(",", 3);
                        } catch (ArrayIndexOutOfBoundsException e) {
                            System.out.println("PassiveResponseScanner line 140: " + e.getMessage());
                            continue;
                        }

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

                    for (int x = 0; x <= grep_index; x++) {
                        IScanIssue matches = null;
                        if (!greps_final.get(x).isEmpty()) {

                            matches = gm.getResponseMatches(baseRequestResponse, "", greps_final.get(x), issuename, issuedetail, issuebackground, remediationdetail, remediationbackground, "", matchtype,
                                    issueseverity, issueconfidence, notresponse, casesensitive, false, excludeHTTP, onlyHTTP);
                        }

                        if (matches != null) {
                            if (scope != 1) {//porperty.equals("All Matches")) {
                                callbacks.addScanIssue(matches);
                            } else {
                                Boolean isUrlScanned = true;
                                for (String url[] : urls) {
                                    if (url[1].contains(baseRequestResponse.getHttpService().getHost())) {
                                        if (url[0].contains(issuename)) {
                                            isUrlScanned = false;
                                        }
                                    }
                                }

                                if (isUrlScanned) {
                                    callbacks.addScanIssue(matches);
                                    urls.add(new String[]{issuename, baseRequestResponse.getHttpService().getHost()});
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("PassiveResponseScanner line 210: " + e.getMessage());
            for (StackTraceElement element : e.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public void setProfilesValues(ProfilesProperties profile_property) {
        greps = profile_property.getGreps();
        issuename = profile_property.getIssueName();
        issueseverity = profile_property.getIssueSeverity();
        issueconfidence = profile_property.getIssueConfidence();
        issuedetail = profile_property.getIssueDetail();
        issuebackground = profile_property.getIssueBackground();
        remediationdetail = profile_property.getRemediationDetail();
        remediationbackground = profile_property.getRemediationBackground();
        matchtype = profile_property.getMatchType();
        scope = profile_property.getScope();
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
        isurlextension = profile_property.getIsURLExtension();
        urlextension = profile_property.getURLExtension();
        NegativeUrlExtension = profile_property.getNegativeURLExtension();
    }

}
