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
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

public class BurpCollaboratorThread extends Thread {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public List<IBurpCollaboratorClientContext> CollaboratorClientContext;
    HashMap<String, IHttpRequestResponse> ccrequestResponse;
    HashMap<String, Properties> issues;
    public boolean doStop;
    Properties issueProperties;
    private String issuename;
    private String issuedetail;
    private String issuebackground;
    private String remediationdetail;
    private String remediationbackground;
    private String issueseverity;
    private String issueconfidence;
    CollaboratorData burpCollaboratorData;

    public BurpCollaboratorThread(IBurpExtenderCallbacks callbacks, CollaboratorData burpCollaboratorData) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        this.burpCollaboratorData = burpCollaboratorData;
        CollaboratorClientContext = new ArrayList();
        ccrequestResponse = new HashMap();
        issues = new HashMap();
        doStop = false;
        issueProperties = new Properties();
        issuename = "";
        issuedetail = "";
        issuebackground = "";
        remediationdetail = "";
        remediationbackground = "";
        issueseverity = "";
        issueconfidence = "";

    }

    public void doStop() {
        doStop = true;
    }

    public boolean keepRunning() {
        return doStop == false;
    }

    @Override
    public void run() {
        while (keepRunning()) {
            CollaboratorClientContext = burpCollaboratorData.getCollaboratorClientContext();
            try {
                for (int client = 0; client < CollaboratorClientContext.size(); client++) {
                    List<IBurpCollaboratorInteraction> CollaboratorInteraction = CollaboratorClientContext.get(client).fetchAllCollaboratorInteractions();
                    if (CollaboratorInteraction != null && !CollaboratorInteraction.isEmpty()) {
                        for (int interaction = 0; interaction < CollaboratorInteraction.size(); interaction++) {
                            addIssue(CollaboratorClientContext.get(client), CollaboratorInteraction.get(interaction));
                        }
                    }
                }

                BurpCollaboratorThread.sleep(10000);
            } catch (NullPointerException | InterruptedException e) {
                System.out.println("Thread error: " + e);
            }
        }
    }

    public void addIssue(IBurpCollaboratorClientContext cc, IBurpCollaboratorInteraction interactions) {
        String interaction_id = interactions.getProperty("interaction_id");
        String bchost = interaction_id + ".burpcollaborator.net";
        String type = interactions.getProperty("type");
        String client_ip = interactions.getProperty("client_ip");
        String time_stamp = interactions.getProperty("time_stamp");
        String query_type = interactions.getProperty("query_type");
        issueProperties = burpCollaboratorData.getIssueProperties(bchost);
        issuename = issueProperties.getProperty("issuename");
        issuedetail = issueProperties.getProperty("issuedetail");
        issuebackground = issueProperties.getProperty("issuebackground");
        remediationdetail = issueProperties.getProperty("remediationdetail");
        remediationbackground = issueProperties.getProperty("remediationbackground");
        issueseverity = issueProperties.getProperty("issueseverity");
        issueconfidence = issueProperties.getProperty("issueconfidence");
        issuedetail = issuedetail + "<br><br><strong>BurpCollaborator data:</strong><br><br><strong>Interaction id: </strong>" + interaction_id + "<br><strong>type: </strong>" + type
                + "<br><strong>client_ip: </strong>" + client_ip + "<br><strong>time_stamp: </strong>" + time_stamp + "<br><strong>query_type: </strong>" + query_type + "<br>";

        IHttpRequestResponse requestResponse = burpCollaboratorData.getRequestResponse(bchost);
        List requestMarkers = new ArrayList();
        int start = 0;
        byte[] match = helpers.stringToBytes(bchost);
        byte[] request = requestResponse.getRequest();

        while (start < request.length) {
            start = helpers.indexOf(request, match, false, start, request.length);
            if (start == -1) {
                break;
            }
            requestMarkers.add(new int[]{start, start + match.length});
            start += match.length;
        }

        callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), helpers.analyzeRequest(requestResponse).getUrl(),
                new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, requestMarkers, null)}, "BurpBounty - " + issuename,
                issuedetail, issueseverity, issueconfidence, remediationdetail, issuebackground, remediationbackground));

    }
}
