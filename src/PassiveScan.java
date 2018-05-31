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
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author eduardogarcia
 */
public class PassiveScan {
    
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
    boolean notcookie;
    boolean casesensitive;
    boolean iscontenttype;
    boolean isresponsecode;
    String contenttype;
    String responsecode;
    List<String> greps = new ArrayList();
    JsonArray data;
    Gson gson = new Gson();
    Issue issue;
    
    public PassiveScan(IBurpExtenderCallbacks callbacks,JsonArray data) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.data = data;
    }
    
    
    
    public List<IScanIssue> doPScan(IHttpRequestResponse baseRequestResponse) throws Exception{                

            List<IScanIssue> issues = new ArrayList<>();
              
            for(int i=0;i<this.data.size();i++){
                Object idata = this.data.get(i);
                issue = gson.fromJson(idata.toString(), Issue.class);;
                
                scanner = issue.getScanner();
                //if example scanner or active scanner...continue.
                if(scanner == 0 || scanner == 1 || !issue.getActive()){
                    continue;
                }
                
                greps = issue.getGreps();
                issuename = issue.getIssueName();
                issueseverity = issue.getIssueSeverity();
                issueconfidence = issue.getIssueConfidence();
                issuedetail = issue.getIssueDetail();
                issuebackground = issue.getIssueBackground();
                remediationdetail = issue.getRemediationDetail();
                remediationbackground = issue.getRemediationBackground();
                matchtype = issue.getMatchType();
                notresponse = issue.getNotResponse();
                notcookie = issue.getNotCookie();
                casesensitive = issue.getCaseSensitive();
                iscontenttype = issue.getIsContentType();
                isresponsecode = issue.getIsResponseCode();
                contenttype = issue.getContentType();
                responsecode = issue.getResponseCode();
                                
                
                
                
                
                for(String grep: greps){
                    if(baseRequestResponse == null){return null;}
                    IResponseInfo r = helpers.analyzeResponse(baseRequestResponse.getResponse());
                       
                    IScanIssue matches;
                    if (isresponsecode && notResponseCode(responsecode, r.getStatusCode()) || iscontenttype && notContentType(contenttype,r)){
                        matches = null;
                    }else{
                        matches = getMatches(baseRequestResponse, grep, name, issuename, issuedetail, issuebackground, remediationdetail, remediationbackground, matchtype,
                        issueseverity, issueconfidence, notresponse, notcookie, casesensitive);
                        }
                        if (matches != null) issues.add(matches);
                    }
                }
            if (issues.size() > 0){
                return issues;
            }
        return null;
    }
    
    
    public boolean notResponseCode(String responsecodes, short responsecode){
        
        boolean iscode = false;
        List<String> items = Arrays.asList(responsecodes.split("\\s*,\\s*"));
        
        for(String i: items){
            int code = Integer.parseInt(i);
            if(code != responsecode){
                iscode = true;
            }else if(code == responsecode){
                iscode = false;
                break;
            }
        }
        return iscode;
    }

    
    public boolean notContentType(String contenttype,IResponseInfo r)
   {
        List<String> headers = r.getHeaders();
        boolean isct = false;
        List<String> items = Arrays.asList(contenttype.split("\\s*,\\s*"));        
        
        for(String i: items){
            for(String header: headers){
                if(header.toUpperCase().contains("CONTENT-TYPE") && !header.toUpperCase().contains(i.toUpperCase())){
                    isct = true;
                }else if(header.toUpperCase().contains("CONTENT-TYPE") && header.toUpperCase().contains(i.toUpperCase())){
                    isct = false;
                    break;
                }
            }
        }
        return isct;
    }
    
    
    public IScanIssue getMatches(IHttpRequestResponse requestResponse, String grep,String name,String issuename,String issuedetail,String issuebackground,
            String remediationdetail,String remediationbackground,int matchtype,String issueseverity,String issueconfidence, boolean notresponse, boolean notcookie, boolean casesensitive)
    {
        IResponseInfo response = helpers.analyzeResponse(requestResponse.getResponse());
        
        if (response == null) return null;
               
        //Start regex grep 
        if(matchtype == 2){
            if(casesensitive && !notresponse && !notcookie){
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()));
                if(m.find()){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).indexOf(m.group()),
                    helpers.bytesToString(requestResponse.getResponse()).indexOf(m.group()) + m.group().length()});

                    return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, responseMarkers) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", grep) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && !notcookie){
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()).toUpperCase());
                if(m.find()){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(m.group()),
                    helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(m.group()) + m.group().length()});

                    return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, responseMarkers) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", grep) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && notresponse && !notcookie){
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()));
                if(!m.find()){
                        return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", grep) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
                
            }else if(!casesensitive && notresponse && !notcookie){
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()).toUpperCase());
                if(!m.find()){
                    return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", grep) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && notcookie){
                Pattern p = Pattern.compile(grep.toUpperCase());
                
                List<String> headers =response.getHeaders();
                List<String> cookies = new ArrayList<String>();
                for (String header: headers) {
                    if (header.toUpperCase().contains("SET-COOKIE")){
                        Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()).toUpperCase());
                        if(!m.find()){
                            cookies.add(header.substring(11, header.indexOf("=")));
                        }
                    }
                }
                if (!cookies.isEmpty()) {
                   return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", cookies.toString()) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground); 
                }else{
                    return null;
                }   
            }else if(casesensitive && !notresponse && notcookie){
                Pattern p = Pattern.compile(grep);
                
                List<String> headers =response.getHeaders();
                List<String> cookies = new ArrayList<String>();
                for (String header: headers) {
                    if (header.toUpperCase().contains("SET-COOKIE")){
                        Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()));
                        if(!m.find()){
                            cookies.add(header.substring(11, header.indexOf("=")));
                        }
                    }
                }
                if (!cookies.isEmpty()) {
                   return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", cookies.toString()) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground); 
                }else{
                    return null;
                }     
            }else{
                return null;
            }
        //End regex grep    
        //Start Simple String, payload in response and payload without encode 
        }else{
            if(casesensitive && !notresponse && !notcookie){
                if(helpers.bytesToString(requestResponse.getResponse()).contains(grep)){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).indexOf(grep),
                    helpers.bytesToString(requestResponse.getResponse()).indexOf(grep) + grep.length()});
                    return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, responseMarkers) }, 
                            "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", grep) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && !notcookie){
                if(helpers.bytesToString(requestResponse.getResponse()).toUpperCase().contains(grep.toUpperCase())){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep.toUpperCase()),
                    helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length()});
                    return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, responseMarkers) }, 
                            "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", grep) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && notresponse && !notcookie){
                if(!helpers.bytesToString(requestResponse.getResponse()).toUpperCase().contains(grep.toUpperCase())){
                    return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", grep) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && notresponse && !notcookie){
                if(!helpers.bytesToString(requestResponse.getResponse()).contains(grep)){
                    return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", grep) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && notcookie){
                List<String> headers =response.getHeaders();
                for (String header: headers) { 
                    if (header.toUpperCase().contains("SET-COOKIE") && !header.toUpperCase().contains(grep.toUpperCase())){
                        return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                        "BurpBounty - "+issuename,issuedetail,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                    }
                }   
            }else if(casesensitive && !notresponse && notcookie){
                List<String> headers =response.getHeaders();
                for (String header: headers) {
                    if (header.toUpperCase().contains("SET-COOKIE") && !header.contains(grep)){
                        return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                        "BurpBounty - "+issuename,issuedetail,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground); 
                    }else{
                        return null;
                    }        
                }
            }else{
                return null;
            }
        //End Simple String, payload in response and payload without encode
        }return null;
    } 
}
