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

/**
 *
 * @author eduardogarcia
 */
public class BurpCollaboratorThread implements Runnable {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public List<IBurpCollaboratorClientContext> CollaboratorClientContext = new ArrayList();
    HashMap<String,IHttpRequestResponse> ccrequestResponse = new HashMap();
    HashMap<String,Properties> issues = new HashMap();
    Properties issueProperties = new Properties();
    public boolean doStop = false;
    private String issuename = "";
    private String issuedetail = "";
    private String issuebackground = "";
    private String remediationdetail = "";
    private String remediationbackground = "";
    private String issueseverity = "";
    private String issueconfidence = "";

    
    public BurpCollaboratorThread(BurpBountyExtension parent) {
        this.callbacks = parent.callbacks;
        this.helpers = callbacks.getHelpers();
        
    }
    
    
    public synchronized void doStop() {
        this.doStop = true;
    }

    public synchronized boolean keepRunning() {
        return this.doStop == false;
    }
    
    public List<IBurpCollaboratorClientContext> getCollaboratorClientContext(){    
        return this.CollaboratorClientContext;
    }
    
    
    public Properties getIssueProperties(String interaction_id){
       return issues.get(interaction_id);
    }
    
    public IHttpRequestResponse getRequestResponse(String interaction_id){
       return ccrequestResponse.get(interaction_id);
    }
    
   
    @Override
    public void run(){
        while(keepRunning()) {
            CollaboratorClientContext = this.getCollaboratorClientContext();
            try {
                for(int client=0;client<CollaboratorClientContext.size();client++) {
                    List<IBurpCollaboratorInteraction> CollaboratorInteraction = CollaboratorClientContext.get(client).fetchAllCollaboratorInteractions(); 
                    if(CollaboratorInteraction != null && !CollaboratorInteraction.isEmpty()){
                        for(int interaction=0;interaction<CollaboratorInteraction.size();interaction++){
                            addIssue(CollaboratorClientContext.get(client),CollaboratorInteraction.get(interaction));   
                        }
                    }
                }
                Thread.sleep(10000);
            } catch (NullPointerException | InterruptedException e) {
                System.out.println(e);
            }
        }
    }

    
    public void addIssue(IBurpCollaboratorClientContext cc, IBurpCollaboratorInteraction interactions){
        String interaction_id = interactions.getProperty("interaction_id");
        String bchost = interaction_id+".burpcollaborator.net";
        String type= interactions.getProperty("type");
        String client_ip= interactions.getProperty("client_ip");
        String time_stamp= interactions.getProperty("time_stamp");
        String query_type= interactions.getProperty("query_type");
        issueProperties = getIssueProperties(bchost);
        IHttpRequestResponse requestResponse = getRequestResponse(bchost);
        
        issuename = issueProperties.getProperty("issuename");
        issuedetail = issueProperties.getProperty("issuedetail");
        issuebackground = issueProperties.getProperty("issuebackground");
        remediationdetail = issueProperties.getProperty("remediationdetail");
        remediationbackground = issueProperties.getProperty("remediationbackground");
        issueseverity = issueProperties.getProperty("issueseverity");
        issueconfidence = issueProperties.getProperty("issueconfidence");
             

        issuedetail =   issuedetail +"<br><br><strong>BurpCollaborator data:</strong><br><br><strong>Interaction id: </strong>"+interaction_id+"<br><strong>type: </strong>"+type+
                "<br><strong>client_ip: </strong>"+client_ip+"<br><strong>time_stamp: </strong>"+time_stamp+"<br><strong>query_type: </strong>"+query_type+"<br>";
        
        List requestMarkers = new ArrayList(1);
        Integer i = helpers.bytesToString(requestResponse.getRequest()).indexOf(bchost);
        Integer e = helpers.bytesToString(requestResponse.getRequest()).indexOf(bchost) + bchost.length();
        if(i.equals(-1) || e.equals(-1)){
            requestMarkers.add(new int[]{0,0});
        }else{
            requestMarkers.add(new int[]{i,e});
        }

        callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                               new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, requestMarkers, null) },"BurpBounty - "+issuename,
                                issuedetail,issueseverity,issueconfidence,remediationdetail,issuebackground, remediationbackground));

    }   
}

