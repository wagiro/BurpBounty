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
import burp.IRequestInfo;
import burp.IScanIssue;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author wagiro
 */
public class PassiveRequestScanner {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    JsonArray active_profiles;
    BurpBountyExtension bbe;
    Gson gson;
    CollaboratorData burpCollaboratorData;
    BurpBountyGui bbg;
    JsonArray allprofiles;
    JsonArray activeprofiles;
    Integer redirtype;
    Integer smartscandelay;
    ActiveScanner active_scanner;
    Utils utils;
    String issuename;
    String issuedetail;
    String issuebackground;
    String remediationdetail;
    String remediationbackground;
    int matchtype;
    String issueseverity;
    String issueconfidence;
    boolean notresponse;
    boolean casesensitive;
    List<String> greps;
    ProfilesProperties profile_property;
    String urlextension;
    Boolean isurlextension;
    Boolean NegativeUrlExtension;
    Boolean scanas;
    int scantype;
    GrepMatch gm;

    public PassiveRequestScanner(BurpBountyExtension bbe, IBurpExtenderCallbacks callbacks, CollaboratorData burpCollaboratorData, JsonArray allprofiles, JsonArray activeprofiles, BurpBountyGui bbg) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        this.burpCollaboratorData = burpCollaboratorData;
        gson = new Gson();
        this.allprofiles = allprofiles;
        this.activeprofiles = activeprofiles;
        this.bbe = bbe;
        this.bbg = bbg;
        gm = new GrepMatch(callbacks);
        utils = new Utils(bbe, callbacks, burpCollaboratorData, allprofiles, bbg);
    }

    public void runReqPScan(IHttpRequestResponse baseRequestResponse, JsonArray passivereqprofiles, JsonArray rules, List<String[]> urls, Boolean passive) {

        try {
            if (baseRequestResponse.getRequest() == null) {
                    return;
                }
            
            for (int i = 0; i < passivereqprofiles.size(); i++) {

                int grep_index = 0;
                ArrayList<ArrayList<String>> greps_final = new ArrayList<>();
                Object idata = passivereqprofiles.get(i);
                profile_property = gson.fromJson(idata.toString(), ProfilesProperties.class);

                setProfilesValues(profile_property);

                Boolean isduplicated = utils.checkDuplicatedPassive(baseRequestResponse, issuename);

                if (!isduplicated || passive) {

                    IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);

                    greps_final.add(new ArrayList());

                    for (String grep : greps) {
                        String[] tokens = grep.split(",", 5);

                        if (tokens[0].equals("true")) {
                            if (tokens[1].equals("And") || tokens[1].equals("")) {
                                if (!tokens[4].equals("")) {
                                    greps_final.get(grep_index).add(tokens[2] + "," + tokens[3] + "," + tokens[4]);
                                }
                            } else {
                                if (!tokens[4].equals("")) {
                                    if (!greps_final.get(0).isEmpty()) {
                                        greps_final.add(new ArrayList());
                                        grep_index = grep_index + 1;
                                        greps_final.get(grep_index).add(tokens[2] + "," + tokens[3] + "," + tokens[4]);
                                    } else {
                                        greps_final.get(grep_index).add(tokens[2] + "," + tokens[3] + "," + tokens[4]);
                                    }
                                }
                            }
                        }
                    }

                    for (int x = 0; x <= grep_index; x++) {
                        Object[] matches = null;
                        try {
                            
                            if (!greps_final.get(x).isEmpty()) {
                                matches = gm.getRequestMatches(baseRequestResponse, greps_final.get(x), issuename, issuedetail, issuebackground, remediationdetail, remediationbackground, matchtype,
                                        issueseverity, issueconfidence, casesensitive, notresponse, scanas, scantype);
                            }

                            if (matches != null) {
                                callbacks.addScanIssue((IScanIssue) matches[0]);
                            }
                        } catch (Exception e) {

                            System.out.println("PassiveRequestScanner line 153: " + e.getMessage());
                            for (StackTraceElement element : e.getStackTrace()) {
                                System.out.println(element);
                            }
                            System.out.println(issuename);
                            continue;
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("PassiveRequestScanner line 164: " + e.getMessage());
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
        notresponse = profile_property.getNotResponse();
        casesensitive = profile_property.getCaseSensitive();
        isurlextension = profile_property.getIsURLExtension();
        urlextension = profile_property.getURLExtension();
        NegativeUrlExtension = profile_property.getNegativeURLExtension();
        scantype = profile_property.getScanType();
        scanas = profile_property.getScanAs();
    }
}
