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
import burp.IHttpService;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
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
public class ActiveScan {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    
    String name;
    String issuename;
    String issuedetail;
    String issuebackground;
    String remediationdetail;
    String remediationbackground;
    String charstourlencode;
    int scanner;
    int matchtype;
    String issueseverity;
    String issueconfidence;
    boolean excludehttp; 
    boolean notresponse; 
    boolean notcookie;
    boolean iscontenttype;
    boolean isresponsecode;
    String contenttype;
    String responsecode;
    boolean casesensitive;
    boolean urlencode;
    List<String> payloads = new ArrayList();
    List<String> payloadsEncoded = new ArrayList();
    List<String> payloadsenc = new ArrayList();
    List<String> greps = new ArrayList();
    List<String> encoders = new ArrayList();
    JsonArray data;
    Gson gson = new Gson();
    Issue issue;
    
    public ActiveScan(IBurpExtenderCallbacks callbacks,JsonArray data) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.data = data;
    }
    
    public IScanIssue getMatches(IHttpRequestResponse requestResponse, String payload,String grep,String name,String issuename,String issuedetail,String issuebackground,
            String remediationdetail,String remediationbackground,String charstourlencode,int matchtype,String issueseverity,String issueconfidence, boolean notresponse,
            boolean notcookie,boolean casesensitive,boolean urlencode)
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
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", payload) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
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
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", payload) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && notresponse && !notcookie){
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()));
                if(!m.find()){
                        return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", payload) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
                
            }else if(!casesensitive && notresponse && !notcookie){
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(requestResponse.getResponse()).toUpperCase());
                if(!m.find()){
                    return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", payload) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
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
                            "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", payload) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
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
                            "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", payload) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && notresponse && !notcookie){
                if(!helpers.bytesToString(requestResponse.getResponse()).toUpperCase().contains(grep.toUpperCase())){
                    return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", payload) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && notresponse && !notcookie){
                if(!helpers.bytesToString(requestResponse.getResponse()).contains(grep)){
                    return new CustomScanIssue(requestResponse.getHttpService(),helpers.analyzeRequest(requestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", payload) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
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
    
    public List<IScanIssue> doAScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) throws Exception{                

            if (helpers.analyzeResponse(baseRequestResponse.getResponse()) == null | 
                helpers.analyzeRequest(baseRequestResponse.getRequest()) == null){
                    return null;
            }

            List<IScanIssue> issues = new ArrayList<>();
            IHttpService httpService = baseRequestResponse.getHttpService();
              
            for(int i=0;i<this.data.size();i++){
                Object idata = this.data.get(i);
                issue = gson.fromJson(idata.toString(), Issue.class);;
                
                scanner = issue.getScanner();
                //if example scanner or passive scanner...continue.
                if(scanner == 0 || scanner == 2 || !issue.getActive()){
                    continue;
                }
                
                payloads = issue.getPayloads();
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
                casesensitive = issue.getCaseSensitive();
                encoders = issue.getEncoder();
                urlencode = issue.getUrlEncode();
                charstourlencode = issue.getCharsToUrlEncode();
                iscontenttype = issue.getIsContentType();
                isresponsecode = issue.getIsResponseCode();
                contenttype = issue.getContentType();
                responsecode = issue.getResponseCode();

                
                if(!encoders.isEmpty()){
                    if(matchtype == 1){
                        payloadsEncoded = processPayload(payloads,encoders);
                        payloads = new ArrayList(payloadsEncoded);
                    }else if(matchtype == 2){
                        payloadsEncoded = processPayload(payloads,encoders);
                        payloads = new ArrayList(payloadsEncoded);      
                    }else if(matchtype == 3){
                        payloadsEncoded = processPayload(payloads,encoders);
                        greps = payloadsEncoded;
                        payloads = payloadsEncoded;
                    }else if(matchtype == 4){
                        payloadsEncoded = processPayload(payloads,encoders);
                        greps = new ArrayList(payloads);
                        payloads = new ArrayList(payloadsEncoded); 
                    }
                    
                }else if(encoders.isEmpty()){
                    if(matchtype == 3){
                        greps = payloads;
                    }
                }
                           
                
                for(String grep: greps){
                    for(String payload: payloads){
                        if(payload.length() >= 2){
                                IHttpRequestResponse response = this.callbacks.makeHttpRequest(httpService,new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload)));
                                if(response.getResponse() == null){return null;}
                                IScanIssue matches;
                                IResponseInfo r = helpers.analyzeResponse(response.getResponse());
                                
                                if (isresponsecode && notResponseCode(responsecode, r.getStatusCode()) || iscontenttype && notContentType(contenttype,r)){
                                    matches = null;
                                }else{
                                    matches = getMatches(response, payload,grep,name,issuename,issuedetail,issuebackground,remediationdetail,remediationbackground,charstourlencode,matchtype,
                                            issueseverity,issueconfidence,notresponse,notcookie,casesensitive, urlencode);
                                }

                                if (matches != null) issues.add(matches);
                        }else{
                            IHttpRequestResponse response = this.callbacks.makeHttpRequest(httpService,insertionPoint.buildRequest(helpers.stringToBytes(payload)));
                            if(response.getResponse() == null){return null;}
                            IResponseInfo r = helpers.analyzeResponse(response.getResponse());
                            IScanIssue matches;

                            if (isresponsecode && notResponseCode(responsecode, r.getStatusCode()) || iscontenttype && notContentType(contenttype,r)){
                                matches = null;
                            }else{  
                                matches = getMatches(response, payload,grep,name,issuename,issuedetail,issuebackground,remediationdetail,remediationbackground,charstourlencode,matchtype,
                                        issueseverity,issueconfidence,notresponse,notcookie,casesensitive,urlencode);
                            }
                            
                            if (matches != null) issues.add(matches);
                        }
                    }
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
    
    
    
    public List processPayload(List<String> payloads, List<String> encoders){
        List pay = new ArrayList();
        for(String payload: payloads){
            
            for(String p: encoders){
                switch (p) {
                    case "URL-encode key characters":
                        payload = encodeKeyURL(payload);
                        break;
                    case "URL-encode all characters":
                        payload = encodeURL(payload);
                        break;
                    case "URL-encode all characters (Unicode)":
                        payload = encodeUnicodeURL(payload);
                        break;
                    case "HTML-encode key characters":
                        payload = encodeKeyHTML(payload);
                        break;
                    case "HTML-encode all characters":
                        payload = encodeHTML(payload);
                        break;
                    case "Base64-encode":
                        payload = helpers.base64Encode(payload);
                    default:
                        break;
                }
            }
            if(urlencode){
                payload = encodeTheseURL(payload,charstourlencode);
            }
            pay.add(payload);
        }
        
       return pay; 
    }
    
    
    
    public static String encodeURL(String s){
        StringBuffer out = new StringBuffer();
        for(int i=0; i<s.length(); i++)
        {
            char c = s.charAt(i);
            out.append("%"+Integer.toHexString((int) c));
        }
        return out.toString();
    }
    
    public static String encodeUnicodeURL(String s){
        StringBuffer out = new StringBuffer();
        for(int i=0; i<s.length(); i++)
        {
            char c = s.charAt(i);
            out.append("%u00"+Integer.toHexString((int) c));
        }
        return out.toString();
    }
    
    public static String encodeHTML(String s){
        StringBuffer out = new StringBuffer();
        for(int i=0; i<s.length(); i++)
        {
            char c = s.charAt(i);
            out.append("&#x"+Integer.toHexString((int) c)+";");
        }
        return out.toString();
    }
    
    
    public static String encodeKeyHTML(String s){
        StringBuffer out = new StringBuffer();
        for(int i=0; i<s.length(); i++)
        {
            char c = s.charAt(i);
            if(c > 127 || c=='"' || c=='<' || c=='>')
            {
               out.append("&#x"+Integer.toHexString((int) c)+";");
            }
            else
            {
                out.append(c);
            }
        }
        return out.toString();
    }
    
    public static String encodeKeyURL(String s){
        StringBuffer out = new StringBuffer();
        for(int i=0; i<s.length(); i++)
        {
            char c = s.charAt(i);
            if(c > 127 || c=='"' || c=='<' || c=='>')
            {
               out.append("%"+Integer.toHexString((int) c));
            }
            else
            {
                out.append(c);
            }
        }
        return out.toString();
    }
    
    public static String encodeTheseURL(String s, String characters){
        StringBuffer out = new StringBuffer();
        for(int i=0; i<s.length(); i++)
        {
            char c = s.charAt(i);
            if(characters.indexOf(c) >= 0 )
            {
               out.append("%"+Integer.toHexString((int) c));
            }
            else
            {
                out.append(c);
            }
        }
        return out.toString();
    }
    
}

