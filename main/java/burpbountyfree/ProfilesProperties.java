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

import java.util.ArrayList;
import java.util.List;

public class ProfilesProperties {

    private String ProfileName;
    private String Name = "";
    private boolean Enabled = false;
    private int Scanner = 0;
    private String Author = "";
    private List<String> Payloads = new ArrayList();
    private List<String> Encoder = new ArrayList();
    private boolean UrlEncode = false;
    private String CharsToUrlEncode = "";
    private List<String> Grep = new ArrayList();
    private List<String> Tags = new ArrayList();
    private boolean PayloadResponse = false;
    private boolean NotResponse = false;
    private String TimeOut1 = "";
    private String TimeOut2 = "";
    private boolean isTime = false;
    private String contentLength = "";
    private boolean iscontentLength = false;
    private boolean CaseSensitive = false;
    private boolean ExcludeHTTP = false;
    private boolean OnlyHTTP = false;
    private boolean IsContentType = false;
    private String ContentType = "";
    private String HttpResponseCode = "";
    private boolean NegativeCT = false;
    private boolean IsResponseCode = false;
    private String ResponseCode = "";
    private boolean NegativeRC = false;
    private String urlextension = "";
    private boolean isurlextension = false;
    private boolean NegativeUrlExtension = false;
    private int MatchType = 0;
    private int Scope = 0;
    private int RedirType = 0;
    private int MaxRedir = 0;
    private int payloadPosition;
    private String payloadsFile = "";
    private String grepsFile = "";
    private String IssueName = "";
    private String IssueSeverity = "";
    private String IssueConfidence = "";
    private String IssueDetail = "";
    private String RemediationDetail = "";
    private String IssueBackground = "";
    private String RemediationBackground = "";
    private List<Headers> Header = new ArrayList();
    private List<String> VariationAttributes = new ArrayList();
    private List<Integer> InsertionPointType = new ArrayList();
    private Boolean Scanas = false;
    private int Scantype = 0;
    private boolean pathDiscovery = false;

    public ProfilesProperties() {
        super();
    }

    public String getProfileName() {
        return ProfileName;
    }
    
    public String getName() {
        return Name;
    }
  

    public List<Headers> getHeader() {
        return Header;
    }

    public List<String> getVariationAttributes() {
        return VariationAttributes;
    }
    
    public List<Integer> getInsertionPointType() {
        return InsertionPointType;
    }

    public String getAuthor() {
        return Author;
    }

    public boolean getEnabled() {
        return Enabled;
    }
    
    public boolean getScanAs() {
        return Scanas;
    }

    public int getScanner() {
        return Scanner;
    }
    
    public int getScanType() {
        return Scantype;
    }

    public int getPayloadPosition() {
        return payloadPosition;
    }

    public List<String> getPayloads() {
        return Payloads;
    }

    public List<String> getEncoder() {
        return Encoder;
    }

    public String getCharsToUrlEncode() {
        return CharsToUrlEncode;
    }

    public String getpayloadsFile() {
        return payloadsFile;
    }

    public String getgrepsFile() {
        return grepsFile;
    }

    public List<String> getGreps() {
        return Grep;
    }

    public List<String> getTags() {
        return Tags;
    }

    public boolean getCaseSensitive() {
        return CaseSensitive;
    }

    public boolean getPayloadResponse() {
        return PayloadResponse;
    }

    public boolean getNotResponse() {
        return NotResponse;
    }

    public boolean getExcludeHTTP() {
        return ExcludeHTTP;
    }

    public boolean getOnlyHTTP() {
        return OnlyHTTP;
    }

    public boolean getIsContentType() {
        return IsContentType;
    }

    public String getContentType() {
        return ContentType;
    }
    
    public String getHttpResponseCode() {
        return HttpResponseCode;
    }
    
    public String getTime1() {
        return TimeOut1;
    }
    
    public String getTime2() {
        return TimeOut2;
    }

    public boolean getIsTime() {
        return isTime;
    }

    public boolean getPathDiscover() {
        return pathDiscovery;
    }

    public String getContentLength() {
        return contentLength;
    }

    public boolean getIsContentLength() {
        return iscontentLength;
    }

    public boolean getNegativeCT() {
        return NegativeCT;
    }

    public boolean getIsResponseCode() {
        return IsResponseCode;
    }

    public String getResponseCode() {
        return ResponseCode;
    }

    public boolean getNegativeRC() {
        return NegativeRC;
    }
    
    public boolean getIsURLExtension() {
        return isurlextension;
    }

    public String getURLExtension() {
        return urlextension;
    }

    public boolean getNegativeURLExtension() {
        return NegativeUrlExtension;
    }

    public boolean getUrlEncode() {
        return UrlEncode;
    }

    public int getMatchType() {
        return MatchType;
    }
    
    public int getScope() {
        return Scope;
    }
        
    public int getRedirection() {
        return RedirType;
    }

    public int getMaxRedir() {
        return MaxRedir;
    }

    public String getIssueName() {
        return IssueName;
    }

    public String getIssueSeverity() {
        return IssueSeverity;
    }

    public String getIssueConfidence() {
        return IssueConfidence;
    }

    public String getIssueDetail() {
        return IssueDetail;
    }

    public String getIssueBackground() {
        return IssueBackground;
    }

    public String getRemediationDetail() {
        return RemediationDetail;
    }

    public String getRemediationBackground() {
        return RemediationBackground;
    }

    //Set functions
    public void setProfileName(String profilename) {
        ProfileName = profilename;
    }
    
    public void setHeader(List<Headers> header) {
        Header = header;
    }

    public void setVariationAttributes(List<String> variationAttributes) {
        VariationAttributes = variationAttributes;
    }
    
    public void setInsertionPointType(List<Integer> insertionPointType) {
        InsertionPointType = insertionPointType;
    }


    public void setAuthor(String author) {
        Author = author;
    }

    public void setEnabled(boolean enabled) {
        Enabled = enabled;
    }
    
    public void setScanAs(boolean scanas) {
        Scanas = scanas;
    }

    public void setScanner(int scanner) {
        Scanner = scanner;
    }
    
    public void setScanType(int scantype) {
        Scantype = scantype;
    }

    public void setPayloadPosition(int payloadposition) {
        payloadPosition = payloadposition;
    }

    public void setPayloads(List<String> payloads) {
        Payloads = payloads;
    }

    public void setEncoder(List<String> encoder) {
        Encoder = encoder;
    }

    public void setCharsToUrlEncode(String charstourlencode) {
        CharsToUrlEncode = charstourlencode;
    }

    public void setPayloadsFile(String payloadsfile) {
        payloadsFile = payloadsfile;
    }

    public void setGrepsFile(String grepsfile) {
        grepsFile = grepsfile;
    }

    public void setGreps(List<String> grep) {
        Grep = grep;
    }

    public void setTags(List<String> tags) {
        Tags = tags;
    }

    public void setPathDiscovery(boolean pathdiscovery) {
        pathDiscovery = pathdiscovery;
    }

    public void setCaseSensitive(boolean casesensitive) {
        CaseSensitive = casesensitive;
    }

    public void setPayloadResponse(boolean payloadresponse) {
        PayloadResponse = payloadresponse;
    }

    public void setNotResponse(boolean notresponse) {
        NotResponse = notresponse;
    }

    public void setOnlyHTTP(boolean onlyHTTP) {
        OnlyHTTP = onlyHTTP;
    }

    public void setExcludeHTTP(boolean excludeHTTP) {
        ExcludeHTTP = excludeHTTP;
    }

    public void setIsContentType(boolean iscontenttype) {
        IsContentType = iscontenttype;
    }

    public void setTime1(String timeout1) {
        TimeOut1 = timeout1;
    }
    
    public void setTime2(String timeout2) {
        TimeOut2 = timeout2;
    }

    public void setIsTime(boolean istime) {
        isTime = istime;
    }

    public void setContentLength(String contentlength) {
        contentLength = contentlength;
    }
    
    public void setHttpResponseCode(String httpresponsecode) {
        HttpResponseCode = httpresponsecode;
    }
    
    public void setIsContentLength(boolean iscontentlength) {
        iscontentLength = iscontentlength;
    }
    
    public void setURLExtension(String urlExtension) {
        urlextension = urlExtension;
    }

    public void setIsURLExtension(boolean isurlExtension) {
        isurlextension = isurlExtension;
    }
    
    public void setNegativeURLExtension(boolean negativeurlextension) {
        NegativeUrlExtension = negativeurlextension;
    }

    public void setContentType(String contenttype) {
        ContentType = contenttype;
    }

    public void setNegativeCT(boolean negativect) {
        NegativeCT = negativect;
    }

    public void setIsResponseCode(boolean isresponsecode) {
        IsResponseCode = isresponsecode;
    }

    public void setResponseCode(String responsecode) {
        ResponseCode = responsecode;
    }

    public void setNegativeRC(boolean negativerc) {
        NegativeRC = negativerc;
    }

    public void setUrlEncode(boolean urlencode) {
        UrlEncode = urlencode;
    }

    public void setMatchType(int matchtype) {
        MatchType = matchtype;
    }
    
    public void setScope(int scope) {
        Scope = scope;
    }

    public void setRedirType(int redirtype) {
        RedirType = redirtype;
    }

    public void setMaxRedir(int maxredir) {
        MaxRedir = maxredir;
    }

    public void setIssueName(String issuename) {
        IssueName = issuename;
    }

    public void setIssueSeverity(String issueseverity) {
        IssueSeverity = issueseverity;
    }

    public void setIssueConfidence(String issueconfidence) {
        IssueConfidence = issueconfidence;
    }

    public void setIssueDetail(String issuedetail) {
        IssueDetail = issuedetail;
    }

    public void setIssueBackground(String issuebackground) {
        IssueBackground = issuebackground;
    }

    public void setRemediationDetail(String remediationdetail) {
        RemediationDetail = remediationdetail;
    }

    public void setRemediationBackground(String remediationbackground) {
        RemediationBackground = remediationbackground;
    }
    
}
