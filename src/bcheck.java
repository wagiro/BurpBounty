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
import burp.IScanIssue;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author eduardogarcia
 */
public class bcheck {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    String issuename;
    String issuedetail;
    String issuebackground;
    String remediationdetail;
    String remediationbackground;
    String issueseverity;
    String issueconfidence;
    
    
    public bcheck(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }
    
    
    public IScanIssue getMatches(IHttpRequestResponse Response, String bchost,IBurpCollaboratorClientContext bc, String payload,String issuename,String issuedetail,String issuebackground,
                                String remediationdetail,String remediationbackground,String issueseverity,String issueconfidence)
    {
        List<IBurpCollaboratorInteraction> interaction = bc.fetchCollaboratorInteractionsFor(bchost);
        if(interaction != null && !interaction.isEmpty()){
            List requestMarkers = new ArrayList(1);
            Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
            Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
            if(i.equals(-1) || e.equals(-1)){
                requestMarkers.add(new int[]{0,0});
            }else{
                requestMarkers.add(new int[]{i,e});
            }
            
            String interaction_id = interaction.get(0).getProperty("interaction_id");
            String type= interaction.get(0).getProperty("type");
            String client_ip= interaction.get(0).getProperty("client_ip");
            String time_stamp= interaction.get(0).getProperty("time_stamp");
            String query_type= interaction.get(0).getProperty("query_type");
            
            issuedetail = issuedetail.concat("<br><br><strong>BurpCollaborator data:</strong><br><br><strong>Interaction id: </strong>"+interaction_id+"<br><strong>type: </strong>"+type+
                    "<br><strong>client_ip: </strong>"+client_ip+"<br><strong>time_stamp: </strong>"+time_stamp+"<br><strong>query_type: </strong>"+query_type+"<br>");
            

            return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", payload) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
        }else{
            return null;
        }
    
        
    }
}
