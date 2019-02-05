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
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

public class CollaboratorData {

    private IExtensionHelpers helpers;
    private List<IBurpCollaboratorClientContext> CollaboratorClientContext;
    HashMap<String, IHttpRequestResponse> ccrequestResponse;
    HashMap<String, Properties> issues;
    Properties issueProperties;
    private String issuename;
    private String issuedetail;
    private String issuebackground;
    private String remediationdetail;
    private String remediationbackground;
    private String issueseverity;
    private String issueconfidence;

    public CollaboratorData(IExtensionHelpers helpers) {
        this.helpers = helpers;
        CollaboratorClientContext = new ArrayList();
        ccrequestResponse = new HashMap();
        issues = new HashMap();
        issueProperties = new Properties();
        issuename = "";
        issuedetail = "";
        issuebackground = "";
        remediationdetail = "";
        remediationbackground = "";
        issueseverity = "";
        issueconfidence = "";
    }

    public synchronized void setIssueProperties(IHttpRequestResponse requestResponse, String bchost, String issuename, String issuedetail, String issueseverity, String issueconfidence,
            String issuebackground, String remediationdetail, String remediationbackground) {

        issueProperties = new Properties();
        issueProperties.put("issuename", issuename);
        issueProperties.put("issuedetail", issuedetail);
        issueProperties.put("issueseverity", issueseverity);
        issueProperties.put("issueconfidence", issueconfidence);
        issueProperties.put("issuebackground", issuebackground);
        issueProperties.put("remediationdetail", remediationdetail);
        issueProperties.put("remediationbackground", remediationbackground);
        issues.put(bchost, issueProperties);
        ccrequestResponse.put(bchost, requestResponse);

    }

    public synchronized Properties getIssueProperties(String bchost) {
        return issues.get(bchost);
    }

    public synchronized List<IBurpCollaboratorClientContext> getCollaboratorClientContext() {
        return CollaboratorClientContext;
    }

    public synchronized void setCollaboratorClientContext(IBurpCollaboratorClientContext bccc) {
        CollaboratorClientContext.add(bccc);
    }

    public synchronized IHttpRequestResponse getRequestResponse(String bchost) {
        return ccrequestResponse.get(bchost);
    }
}
