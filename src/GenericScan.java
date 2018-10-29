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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author eduardogarcia
 */
public class GenericScan {
        
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
    boolean excludeHTTP;
    boolean onlyHTTP;
    boolean notresponse; 
    boolean notcookie;
    boolean iscontenttype;
    boolean isresponsecode;
    boolean negativect;
    boolean negativerc;
    String contenttype;
    String responsecode;
    boolean casesensitive;
    boolean urlencode;
    Integer maxredirect;
    Integer redirtype;
    boolean spaceencode;
    String sencode;
    int payloadposition;
    String timeout;
    boolean istime;
    boolean isreplace;
    String replace1;
    String replace2;
    List<String> payloads = new ArrayList();
    List<String> payloadsEncoded = new ArrayList();
    List<String> payloadsenc = new ArrayList();
    List<String> greps = new ArrayList();
    List<String> encoders = new ArrayList();
    JsonArray data;
    Gson gson = new Gson();
    Issue issue;
    IBurpCollaboratorClientContext bc;
    
    public GenericScan(IBurpExtenderCallbacks callbacks,JsonArray data) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.data = data;
    }
    
     
    public List<IScanIssue> runAScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) throws Exception{                

            if (helpers.analyzeResponse(baseRequestResponse.getResponse()) == null | helpers.analyzeRequest(baseRequestResponse.getRequest()) == null){
                    return null;
            }

            List<IScanIssue> issues = new ArrayList<>();
            IHttpService httpService = baseRequestResponse.getHttpService();
            List<Integer> responseCodes = new ArrayList<>(Arrays.asList(300,301,302,303,304,305,306,307,308));
            
              
            for(int i=0;i<this.data.size();i++){
                Object idata = this.data.get(i);
                issue = gson.fromJson(idata.toString(), Issue.class);;
                 
                //if example scanner or passive scanner...continue.
                scanner = issue.getScanner();
                if(scanner == 0 || scanner == 2 || !issue.getActive()){
                    continue;
                }
                
                //get values from json
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
                excludeHTTP = issue.getExcludeHTTP();
                onlyHTTP = issue.getOnlyHTTP();
                negativect = issue.getNegativeCT();
                negativerc = issue.getNegativeRC();
                maxredirect = issue.getMaxRedir();
                redirtype = issue.getRedirection();
                name = issue.getName();
                spaceencode = issue.getSpaceEncode();
                sencode = issue.getSEncode();
                payloadposition = issue.getPayloadPosition();
                timeout = issue.getTime();
                istime = issue.getIsTime();
                isreplace = issue.getIsReplace();
                replace1 = issue.getReplace1();
                replace2 = issue.getReplace2();

                //If encoders exist...
                if(!encoders.isEmpty()){
                    switch (matchtype) {
                        case 1:
                            payloadsEncoded = processPayload(payloads,encoders);
                            payloads = new ArrayList(payloadsEncoded);
                            break;
                        case 2:
                            payloadsEncoded = processPayload(payloads,encoders);
                            payloads = new ArrayList(payloadsEncoded);
                            break;
                        case 3:
                            payloadsEncoded = processPayload(payloads,encoders);
                            greps = payloadsEncoded;
                            payloads = payloadsEncoded;
                            break; 
                        case 4:
                            payloadsEncoded = processPayload(payloads,encoders);
                            greps = new ArrayList(payloads);
                            payloads = new ArrayList(payloadsEncoded);
                            break;
                        default:
                            break;
                    }
                    
                }else{
                    if(matchtype == 3){
                        greps = payloads;
                    }
                }
                
                if(!spaceencode || sencode.isEmpty()){
                    sencode = "+";
                }
                
                
                IScanIssue matches = null;
                GrepMatch gm = new GrepMatch(callbacks);
                
                try{                
                    for(String payload: payloads){

                        if(isreplace){
                            payload = payload.replaceAll(replace1, replace2);
                        } 

                        payload = payload.replaceAll(" ", sencode);

                        if(payloadposition == 2){
                            payload = insertionPoint.getBaseValue().concat(payload);
                        } 

                        if(payload.contains("{BC}")){
                            IBurpCollaboratorClientContext bc = callbacks.createBurpCollaboratorClientContext();
                            String bchost = bc.generatePayload(true);
                            payload = payload.replaceAll("\\{BC\\}", bchost);

                            if(istime){
                                long startTime = System.currentTimeMillis();
                                IHttpRequestResponse response = callbacks.makeHttpRequest(httpService,new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload)));
                                long endTime = System.currentTimeMillis();
                                long duration = (endTime - startTime);
                                if(duration >= Integer.getInteger(timeout)*1000){
                                    matches = new CustomScanIssue(response.getHttpService(),helpers.analyzeRequest(response).getUrl(), 
                                              new IHttpRequestResponse[] { callbacks.applyMarkers(response, null, null) }, 
                                              "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,
                                              issueconfidence,remediationdetail,issuebackground,remediationbackground);
                                }else{
                                    matches = null;
                                }

                            }else{
                                IHttpRequestResponse response = callbacks.makeHttpRequest(httpService,new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload)));

                                if(response.getResponse() == null){
                                    return null;
                                }

                                bcheck bcheck = new bcheck(callbacks);
                                matches = bcheck.getMatches(response,bchost,bc,payload,issuename,issuedetail,issuebackground,remediationdetail,remediationbackground,issueseverity,issueconfidence);
                            }

                            if (matches != null){
                                issues.add(matches);
                            }

                        }else{
                            if(istime){
                                long startTime = System.currentTimeMillis();
                                IHttpRequestResponse response = callbacks.makeHttpRequest(httpService,new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload)));
                                long endTime = System.currentTimeMillis();
                                long duration = (endTime - startTime);
                                if(duration >= Integer.getInteger(timeout)*1000){
                                    matches = new CustomScanIssue(response.getHttpService(),helpers.analyzeRequest(response).getUrl(), 
                                              new IHttpRequestResponse[] { callbacks.applyMarkers(response, null, null) }, 
                                              "BurpBounty - "+issuename, issuedetail.replaceAll("<grep>", helpers.urlEncode(payload)) ,issueseverity,
                                              issueconfidence,remediationdetail,issuebackground,remediationbackground);
                                }else{
                                    matches = null;
                                }
                                if (matches != null){
                                    issues.add(matches);
                                }

                            }else{


                                IHttpRequestResponse response = callbacks.makeHttpRequest(httpService,new BuildUnencodeRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload)));

                                if(response.getResponse() == null){
                                    return null;
                                }

                                IResponseInfo r = helpers.analyzeResponse(response.getResponse());
                                Integer responseCode = new Integer(r.getStatusCode());
                                Integer loop = 0;

                                if(maxredirect > 50){
                                    maxredirect = 50;
                                }

                                if(redirtype != 1){
                                    while(loop != maxredirect+1){
                                        if(responseCodes.contains(responseCode)){

                                            if (isresponsecode && notResponseCode(responsecode, negativerc, r.getStatusCode()) || iscontenttype && notContentType(contenttype, negativect, r)){
                                                matches = null;
                                            }else{
                                                for(String grep: greps){
                                                    matches = gm.getMatches(response, payload,grep,name,issuename,issuedetail,issuebackground,remediationdetail,remediationbackground,charstourlencode,matchtype,
                                                          issueseverity,issueconfidence,notresponse,notcookie,casesensitive,urlencode,excludeHTTP,onlyHTTP);


                                                    if (matches != null){
                                                        issues.add(matches);
                                                    }
                                                }
                                            }

                                            URL url = getLocation(httpService,response);
                                            if(redirtype == 2){
                                                if(url.getHost().contains(httpService.getHost())){
                                                    byte[] checkRequest = helpers.buildHttpRequest(url);
                                                    boolean https = false;

                                                    if(url.getProtocol().equals("https")){
                                                        https = true;                                
                                                    }

                                                    Integer port = 0;
                                                    if(url.getPort() == -1){
                                                        port = url.getDefaultPort();
                                                    }

                                                    IHttpService newrequest = helpers.buildHttpService(url.getHost(),port,https);
                                                    response = callbacks.makeHttpRequest(newrequest, checkRequest);

                                                    r = helpers.analyzeResponse(response.getResponse());
                                                    responseCode = new Integer(r.getStatusCode());
                                                }
                                            }else if(redirtype == 3){
                                                boolean isurl = callbacks.isInScope(url);
                                                if(isurl){
                                                    byte[] checkRequest = helpers.buildHttpRequest(url);
                                                    boolean https = false;

                                                    if(url.getProtocol().equals("https")){
                                                        https = true;                                
                                                    }

                                                    Integer port = 0;
                                                    if(url.getPort() == -1){
                                                        port = url.getDefaultPort();
                                                    }

                                                    IHttpService newrequest = helpers.buildHttpService(url.getHost(),port,https);
                                                    response = callbacks.makeHttpRequest(newrequest, checkRequest);

                                                    r = helpers.analyzeResponse(response.getResponse());
                                                    responseCode = new Integer(r.getStatusCode());
                                                 }

                                            }else{
                                                byte[] checkRequest = helpers.buildHttpRequest(url);
                                                boolean https = false;

                                                if(url.getProtocol().equals("https")){
                                                    https = true;                                
                                                }

                                                Integer port = 0;
                                                if(url.getPort() == -1){
                                                    port = url.getDefaultPort();
                                                }

                                                IHttpService newrequest = helpers.buildHttpService(url.getHost(),port,https);
                                                response = callbacks.makeHttpRequest(newrequest, checkRequest);

                                                r = helpers.analyzeResponse(response.getResponse());
                                                responseCode = new Integer(r.getStatusCode());

                                            }
                                            loop = loop + 1;
                                        }else{

                                            if (isresponsecode && notResponseCode(responsecode, negativerc, r.getStatusCode()) || iscontenttype && notContentType(contenttype, negativect, r)){
                                                matches = null;
                                            }else{
                                                for(String grep: greps){
                                                    matches = gm.getMatches(response, payload,grep,name,issuename,issuedetail,issuebackground,remediationdetail,remediationbackground,charstourlencode,matchtype,
                                                          issueseverity,issueconfidence,notresponse,notcookie,casesensitive,urlencode,excludeHTTP,onlyHTTP);

                                                    if (matches != null){
                                                        issues.add(matches);
                                                    }
                                                }
                                            }
                                        break;
                                        }
                                    }
                                }else{
                                    if (isresponsecode && notResponseCode(responsecode, negativerc, r.getStatusCode()) || iscontenttype && notContentType(contenttype, negativect, r)){
                                        matches = null;
                                    }else{
                                        for(String grep: greps){
                                            matches = gm.getMatches(response, payload,grep,name,issuename,issuedetail,issuebackground,remediationdetail,remediationbackground,charstourlencode,matchtype,
                                            issueseverity,issueconfidence,notresponse,notcookie,casesensitive,urlencode,excludeHTTP,onlyHTTP);

                                            if (matches != null){
                                                issues.add(matches);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }catch(IndexOutOfBoundsException | IllegalArgumentException e){
                   continue;
                }catch(RuntimeException e){
                   continue;     
                }
            }
        if (issues.size() > 0){
            return issues;
        }
        return null;
    }
    
    public URL getLocation(IHttpService httpService,IHttpRequestResponse response){
        IResponseInfo response_info = helpers.analyzeResponse(response.getResponse());
        String[] host = null;
        String Location = "";
        URL url;
        String regex = "(www)?([a-zA-Z0-9]+).[a-zA-Z0-9]*.[a-z]{3}.*";
        Pattern p = Pattern.compile(regex);
        
        for(String header: response_info.getHeaders()){
            if(header.toUpperCase().contains("LOCATION")){
                
                host = header.split("\\s+");
                Location = host[1];
                
            }
        }
        Matcher m = p.matcher(Location);
        try{
            if (host[1].startsWith("http://") || host[1].startsWith("https://")){
                url = new URL(Location);
                return url;
            }else if(!host[1].startsWith("/") && m.find()){
                url = new URL("http://" + Location);
                return url;
            }else{
                url = new URL(httpService.getProtocol() + "://" + httpService.getHost() + Location);
                return url; 
            }
            
        }catch(MalformedURLException ex){
            return null;
        }
     }
    
    
    public List<IScanIssue> runPScan(IHttpRequestResponse baseRequestResponse) throws Exception{                

            List<IScanIssue> issues = new ArrayList<>();
            String payload = "";//For compatibility with ActiveScanner GrepMatch constructor
            String charstourlencode = "";//For compatibility with ActiveScanner GrepMatch constructor
            boolean urlencode = false;//For compatibility with ActiveScanner GrepMatch constructor
              
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
                excludeHTTP = issue.getExcludeHTTP();
                onlyHTTP = issue.getOnlyHTTP();
                negativect = issue.getNegativeCT();
                negativerc = issue.getNegativeRC();
                
                                
                
                
                
                GrepMatch gm = new GrepMatch(callbacks);
               
                for(String grep: greps){
                    if(baseRequestResponse == null){
                        return null;
                    }
                    
                    IResponseInfo r = helpers.analyzeResponse(baseRequestResponse.getResponse());
                       
                    IScanIssue matches = null;
                    if (isresponsecode && notResponseCode(responsecode, negativerc, r.getStatusCode()) || iscontenttype && notContentType(contenttype, negativect, r)){
                        matches = null;
                    }else{
                        matches = gm.getMatches(baseRequestResponse, payload, grep, name, issuename, issuedetail, issuebackground, remediationdetail, remediationbackground,charstourlencode, matchtype,
                        issueseverity, issueconfidence, notresponse, notcookie, casesensitive,urlencode,excludeHTTP,onlyHTTP);
                    }
                        
                    if (matches != null){
                            issues.add(matches);
                    }
                }
            }
            if (issues.size() > 0){
                return issues;
            }
        return null;
    }
    
   
    public boolean notResponseCode(String responsecodes, boolean negativerc, short responsecode){
        
        boolean iscode = false;
        List<String> items = Arrays.asList(responsecodes.split("\\s*,\\s*"));
        
        for(String i: items){
            int code = Integer.parseInt(i);
            if(code != responsecode && !negativerc){
                iscode = true;
            }else if(code != responsecode && negativerc){
                iscode = false;
                break;
            }else if(code == responsecode && !negativerc){
                iscode = false;
                break;
            }else if(code == responsecode && negativerc){
                iscode = true;
                break;
            }
        }
        return iscode;
    }

    
    public boolean notContentType(String contenttype, boolean negativect, IResponseInfo r){
        List<String> headers = r.getHeaders();
        boolean isct = false;
        List<String> items = Arrays.asList(contenttype.split("\\s*,\\s*"));        
        
        for(String i: items){
            for(String header: headers){
                if(header.toUpperCase().contains("CONTENT-TYPE") && !header.toUpperCase().contains(i.toUpperCase()) && !negativect){
                    isct = true;
                }else if(header.toUpperCase().contains("CONTENT-TYPE") && !header.toUpperCase().contains(i.toUpperCase()) && negativect){
                    isct = false;
                    break;
                }else if(header.toUpperCase().contains("CONTENT-TYPE") && header.toUpperCase().contains(i.toUpperCase()) && !negativect){
                    isct = false;
                    break;
                }else if(header.toUpperCase().contains("CONTENT-TYPE") && header.toUpperCase().contains(i.toUpperCase()) && negativect){
                    isct = true;
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
