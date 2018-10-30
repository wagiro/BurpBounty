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
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author eduardogarcia
 */
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
    boolean notcookie;
    boolean excludeHTTP;
    boolean onlyHTTP;
    boolean casesensitive;
    boolean iscontenttype;
    boolean isresponsecode;
    String contenttype;
    String responsecode;
    List<String> greps = new ArrayList();
    
    
    public GrepMatch(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }
    
    
    public IScanIssue getMatches(IHttpRequestResponse Response, String payload,String grep,String name,String issuename,String issuedetail,String issuebackground,
            String remediationdetail,String remediationbackground,String charstourlencode,int matchtype,String issueseverity,String issueconfidence, boolean notresponse,
            boolean notcookie,boolean casesensitive,boolean urlencode, boolean excludeHTTP, boolean onlyHTTP)
    {
        IResponseInfo response = helpers.analyzeResponse(Response.getResponse());
        
        if (response == null) return null;
               
        //Start regex grep 
        if(matchtype == 2){
            if(casesensitive && !notresponse && !notcookie && !excludeHTTP && !onlyHTTP){
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(Response.getResponse()));
                if(m.find()){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).indexOf(m.group()),
                    helpers.bytesToString(Response.getResponse()).indexOf(m.group()) + m.group().length()});
                    
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }

                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && !notresponse && !notcookie && excludeHTTP && !onlyHTTP){
                byte[] req = Response.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(body));
                if(m.find()){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).indexOf(m.group()),
                    helpers.bytesToString(Response.getResponse()).indexOf(m.group()) + m.group().length()});
                    
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }

                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && !notresponse && !notcookie && !excludeHTTP && onlyHTTP){
                boolean found = false;
                Matcher m = null;
                String text = "";
                for(String header: response.getHeaders()){
                    Pattern p = Pattern.compile(grep);
                    m = p.matcher(header);
                    if(m.find()){
                        text = m.group();
                        found = true;
                    }

                }
                
                if(found){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).indexOf(text),
                    helpers.bytesToString(Response.getResponse()).indexOf(text) + text.length()});
                    
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }

                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && !notcookie && !excludeHTTP && !onlyHTTP){
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(Response.getResponse()).toUpperCase());
                if(m.find()){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(m.group()),
                    helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(m.group()) + m.group().length()});
                    
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }

                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && !notcookie && excludeHTTP && !onlyHTTP){
                byte[] req = Response.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(body).toUpperCase());
                if(m.find()){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(m.group()),
                    helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(m.group()) + m.group().length()});
                    
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }

                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && !notcookie && !excludeHTTP && onlyHTTP){
                boolean found = false;
                Matcher m = null;
                String text = "";
                for(String header: response.getHeaders()){
                    Pattern p = Pattern.compile(grep.toUpperCase());
                    m = p.matcher(header.toUpperCase());
                    if(m.find()){
                        text = m.group();
                        found = true;
                    }

                }
                if(found){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(text),
                    helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(text) + text.length()});
                   
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }

                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && notresponse && !notcookie && !excludeHTTP && !onlyHTTP){
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(Response.getResponse()));
                
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if(i.equals(-1) || e.equals(-1)){
                    requestMarkers.add(new int[]{0,0});
                }else{
                    requestMarkers.add(new int[]{i,e});
                }
                    
                if(!m.find()){
                        return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
                
            }else if(casesensitive && notresponse && !notcookie && excludeHTTP && !onlyHTTP){
                byte[] req = Response.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                Pattern p = Pattern.compile(grep);
                Matcher m = p.matcher(helpers.bytesToString(body));
                
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if(i.equals(-1) || e.equals(-1)){
                    requestMarkers.add(new int[]{0,0});
                }else{
                    requestMarkers.add(new int[]{i,e});
                }
                    
                if(!m.find()){
                        return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
                
            }else if(casesensitive && notresponse && !notcookie && !excludeHTTP && onlyHTTP){
                boolean found = false;
                Matcher m = null;
                for(String header: response.getHeaders()){
                    Pattern p = Pattern.compile(grep);
                    m = p.matcher(header);
                    if(m.find()){
                        found = true;
                    }

                }
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if(i.equals(-1) || e.equals(-1)){
                    requestMarkers.add(new int[]{0,0});
                }else{
                    requestMarkers.add(new int[]{i,e});
                }
                    
                if(!found){
                        return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
                
            }else if(!casesensitive && notresponse && !notcookie && !excludeHTTP && !onlyHTTP){
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(Response.getResponse()).toUpperCase());
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if(i.equals(-1) || e.equals(-1)){
                    requestMarkers.add(new int[]{0,0});
                }else{
                    requestMarkers.add(new int[]{i,e});
                }
                if(!m.find()){
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && notresponse && !notcookie && excludeHTTP && !onlyHTTP){
                byte[] req = Response.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                Pattern p = Pattern.compile(grep.toUpperCase());
                Matcher m = p.matcher(helpers.bytesToString(body).toUpperCase());
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if(i.equals(-1) || e.equals(-1)){
                    requestMarkers.add(new int[]{0,0});
                }else{
                    requestMarkers.add(new int[]{i,e});
                }
                if(!m.find()){
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && notresponse && !notcookie && !excludeHTTP && onlyHTTP){
                boolean found = false;
                Matcher m = null;
                for(String header: response.getHeaders()){
                    Pattern p = Pattern.compile(grep.toUpperCase());
                    m = p.matcher(header.toUpperCase());
                    if(m.find()){
                        found = true;
                    }

                }
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if(i.equals(-1) || e.equals(-1)){
                    requestMarkers.add(new int[]{0,0});
                }else{
                    requestMarkers.add(new int[]{i,e});
                }
                if(!found){
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                        "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && notcookie && !excludeHTTP && !onlyHTTP){
                Pattern p = Pattern.compile(grep.toUpperCase());
                
                List<String> headers =response.getHeaders();
                List<String> cookies = new ArrayList<String>();
                for (String header: headers) {
                    if (header.toUpperCase().contains("SET-COOKIE")){
                        Matcher m = p.matcher(helpers.bytesToString(Response.getResponse()).toUpperCase());
                        if(!m.find()){
                            cookies.add(header.substring(11, header.indexOf("=")));
                        }
                    }
                }
                if (!cookies.isEmpty()) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                   return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", cookies.toString()) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground); 
                }else{
                    return null;
                }   
            }else if(!casesensitive && !notresponse && notcookie && !excludeHTTP && onlyHTTP){
                Pattern p = Pattern.compile(grep.toUpperCase());
                
                List<String> headers =response.getHeaders();
                List<String> cookies = new ArrayList<String>();
                for (String header: headers) {
                    if (header.toUpperCase().contains("SET-COOKIE")){
                        Matcher m = p.matcher(helpers.bytesToString(Response.getResponse()).toUpperCase());
                        if(!m.find()){
                            cookies.add(header.substring(11, header.indexOf("=")));
                        }
                    }
                }
                if (!cookies.isEmpty()) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                   return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", cookies.toString()) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground); 
                }else{
                    return null;
                }   
            }else if(casesensitive && !notresponse && notcookie && !excludeHTTP && !onlyHTTP){
                Pattern p = Pattern.compile(grep);
                
                List<String> headers =response.getHeaders();
                List<String> cookies = new ArrayList<String>();
                for (String header: headers) {
                    if (header.toUpperCase().contains("SET-COOKIE")){
                        Matcher m = p.matcher(helpers.bytesToString(Response.getResponse()));
                        if(!m.find()){
                            cookies.add(header.substring(11, header.indexOf("=")));
                        }
                    }
                }
                if (!cookies.isEmpty()) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                   return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", cookies.toString()) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground); 
                }else{
                    return null;
                }     
            }else if(casesensitive && !notresponse && notcookie && !excludeHTTP && onlyHTTP){
                Pattern p = Pattern.compile(grep);
                
                List<String> headers =response.getHeaders();
                List<String> cookies = new ArrayList<String>();
                for (String header: headers) {
                    if (header.toUpperCase().contains("SET-COOKIE")){
                        Matcher m = p.matcher(helpers.bytesToString(Response.getResponse()));
                        if(!m.find()){
                            cookies.add(header.substring(11, header.indexOf("=")));
                        }
                    }
                }
                if (!cookies.isEmpty()) {
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                   return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
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
            if(casesensitive && !notresponse && !notcookie && !excludeHTTP && !onlyHTTP){
                if(helpers.bytesToString(Response.getResponse()).contains(grep)){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).indexOf(grep),
                    helpers.bytesToString(Response.getResponse()).indexOf(grep) + grep.length()});
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                                
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                            "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && !notresponse && !notcookie && excludeHTTP && !onlyHTTP){
                byte[] req = Response.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                
                if(helpers.bytesToString(body).contains(grep)){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).indexOf(grep),helpers.bytesToString(Response.getResponse()).indexOf(grep) + grep.length()});
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                                
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                            "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && !notresponse && !notcookie && !excludeHTTP && onlyHTTP){
                boolean found = false;
                for(String header: response.getHeaders()){
                    if(header.contains(grep)){
                        found = true;
                    }
                }
                if(found){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).indexOf(grep),
                    helpers.bytesToString(Response.getResponse()).indexOf(grep) + grep.length()});
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                                
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                            "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && !notcookie && !excludeHTTP && !onlyHTTP){
                if(helpers.bytesToString(Response.getResponse()).toUpperCase().contains(grep.toUpperCase())){
                    
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(grep.toUpperCase()),
                    helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length()});
                    
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                    
                    
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                            "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && !notcookie && excludeHTTP && !onlyHTTP){
                byte[] req = Response.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                
                if(helpers.bytesToString(body).toUpperCase().contains(grep.toUpperCase())){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(grep.toUpperCase()),
                    helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length()});
                    
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                    
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                            "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && !notcookie && !excludeHTTP && onlyHTTP){
                boolean found = false;
                for(String header: response.getHeaders()){
                    if(header.toUpperCase().contains(grep.toUpperCase())){
                        found = true;
                    }

                }
                if(found){
                    List responseMarkers = new ArrayList(1);
                    responseMarkers.add(new int[]{helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(grep.toUpperCase()),
                    helpers.bytesToString(Response.getResponse()).toUpperCase().indexOf(grep.toUpperCase()) + grep.length()});
                    
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                    
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, responseMarkers) }, 
                            "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && notresponse && !notcookie && !excludeHTTP && !onlyHTTP){
                if(!helpers.bytesToString(Response.getResponse()).toUpperCase().contains(grep.toUpperCase())){
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && notresponse && !notcookie && excludeHTTP && !onlyHTTP){
                byte[] req = Response.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                
                if(!helpers.bytesToString(body).toUpperCase().contains(grep.toUpperCase())){
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && notresponse && !notcookie && !excludeHTTP && onlyHTTP){
                boolean found = false;
                for(String header: response.getHeaders()){
                    if(header.toUpperCase().contains(grep.toUpperCase())){
                        found = true;
                    }

                }
                if(!found){
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && notresponse && !notcookie && !excludeHTTP && !onlyHTTP){
                if(!helpers.bytesToString(Response.getResponse()).contains(grep)){
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && notresponse && !notcookie && excludeHTTP && !onlyHTTP){
                byte[] req = Response.getResponse();
                int len = req.length - response.getBodyOffset();
                byte[] body = new byte[len];
                System.arraycopy(req, response.getBodyOffset(), body, 0, len);
                if(!helpers.bytesToString(body).contains(grep)){
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(casesensitive && notresponse && !notcookie && !excludeHTTP && onlyHTTP){
                boolean found = false;
                for(String header: response.getHeaders()){
                    if(header.contains(grep)){
                        found = true;
                    }

                }
                if(found){
                    List requestMarkers = new ArrayList(1);
                    Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                    Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                    if(i.equals(-1) || e.equals(-1)){
                        requestMarkers.add(new int[]{0,0});
                    }else{
                        requestMarkers.add(new int[]{i,e});
                    }
                    return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                    "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                }else{
                    return null;
                }
            }else if(!casesensitive && !notresponse && notcookie && !excludeHTTP && !onlyHTTP){
                List<String> headers =response.getHeaders();
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if(i.equals(-1) || e.equals(-1)){
                    requestMarkers.add(new int[]{0,0});
                }else{
                    requestMarkers.add(new int[]{i,e});
                }
                for (String header: headers) { 
                    if (header.toUpperCase().contains("SET-COOKIE") && !header.toUpperCase().contains(grep.toUpperCase())){
                        return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                        "BurpBounty - "+issuename,issuedetail,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                    }
                }   
            }else if(!casesensitive && !notresponse && notcookie && !excludeHTTP && onlyHTTP){
                List<String> headers =response.getHeaders();
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if(i.equals(-1) || e.equals(-1)){
                    requestMarkers.add(new int[]{0,0});
                }else{
                    requestMarkers.add(new int[]{i,e});
                }
                for (String header: headers) { 
                    if (header.toUpperCase().contains("SET-COOKIE") && !header.toUpperCase().contains(grep.toUpperCase())){
                        return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                        "BurpBounty - "+issuename,issuedetail,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground);
                    }
                }   
            }else if(casesensitive && !notresponse && notcookie && !excludeHTTP && !onlyHTTP){
                List<String> headers =response.getHeaders();
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if(i.equals(-1) || e.equals(-1)){
                    requestMarkers.add(new int[]{0,0});
                }else{
                    requestMarkers.add(new int[]{i,e});
                }
                for (String header: headers) {
                    if (header.toUpperCase().contains("SET-COOKIE") && !header.contains(grep)){
                        return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
                        "BurpBounty - "+issuename,issuedetail,issueseverity,issueconfidence,remediationdetail,issuebackground,remediationbackground); 
                    }else{
                        return null;
                    }        
                }
            }else if(casesensitive && !notresponse && notcookie && !excludeHTTP && onlyHTTP){
                List<String> headers =response.getHeaders();
                List requestMarkers = new ArrayList(1);
                Integer i = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase());
                Integer e = helpers.bytesToString(Response.getRequest()).toUpperCase().indexOf(payload.toUpperCase()) + payload.length();
                if(i.equals(-1) || e.equals(-1)){
                    requestMarkers.add(new int[]{0,0});
                }else{
                    requestMarkers.add(new int[]{i,e});
                }
                for (String header: headers) {
                    if (header.toUpperCase().contains("SET-COOKIE") && !header.contains(grep)){
                        return new CustomScanIssue(Response.getHttpService(),helpers.analyzeRequest(Response).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(Response, requestMarkers, null) }, 
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
