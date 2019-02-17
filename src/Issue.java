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

import java.util.List;

public class Issue {

    private String Name;
    private boolean Active;
    private int Scanner;
    private String Author;
    private List<String> Payloads;
    private List<String> Encoder;
    private boolean UrlEncode;
    private String CharsToUrlEncode;
    private List<String> Grep;
    private List<String> Tags;
    private boolean PayloadResponse;
    private boolean NotResponse;
    private String TimeOut;
    private boolean isTime;
    private String contentLength;
    private boolean iscontentLength;
    private boolean CaseSensitive;
    private boolean ExcludeHTTP;
    private boolean OnlyHTTP;
    private boolean IsContentType;
    private String ContentType;
    private boolean NegativeCT;
    private boolean IsResponseCode;
    private String ResponseCode;
    private boolean NegativeRC;
    private int MatchType;
    private int RedirType;
    private int MaxRedir;
    private int payloadPosition;
    private String payloadsFile;
    private String grepsFile;
    private String IssueName;
    private String IssueSeverity;
    private String IssueConfidence;
    private String IssueDetail;
    private String RemediationDetail;
    private String IssueBackground;
    private String RemediationBackground;
    private List<Headers> Header;
    private List<String> VariationAttributes;
    private boolean pathDiscovery;

    public Issue() {
        super();
    }

    public Issue(String name, int scanner, boolean active, List payloads, List encoder, String charstourlencode, List grep, List tags, boolean casesensitive, boolean urlencode,
            boolean payloadresponse, boolean notresponse, boolean onlyHTTP, boolean excludeHTTP, boolean iscontenttype, String contenttype, boolean negativect,
            boolean isresponsecode, String responsecode, boolean negativerc, int matchtype, int redirtype, boolean spaceencode, String sencode, String timeout,
            boolean isreplace, String replace1, String replace2, String author, boolean istime, int payloadposition, int maxredir, String payloadsfile, String grepsfile, String issuetype, String issuename, String issueseverity, String issueconfidence,
            String issuedetail, String issuebackground, String remediationdetail, String remediationbackground, boolean iscontentlength, String contentlength, List<Headers> header, List<String> variationAttributes, boolean pathdiscovery) {
        super();
        Name = name;
        Active = active;
        Scanner = scanner;
        Author = author;
        Payloads = payloads;
        Encoder = encoder;
        Grep = grep;
        Tags = tags;
        CaseSensitive = casesensitive;
        PayloadResponse = payloadresponse;
        NotResponse = notresponse;
        ExcludeHTTP = excludeHTTP;
        OnlyHTTP = onlyHTTP;
        IsContentType = iscontenttype;
        ContentType = contenttype;
        NegativeCT = negativect;
        IsResponseCode = isresponsecode;
        ResponseCode = responsecode;
        NegativeRC = negativerc;
        MatchType = matchtype;
        IssueName = issuename;
        IssueSeverity = issueseverity;
        IssueConfidence = issueconfidence;
        IssueDetail = issuedetail;
        IssueBackground = issuebackground;
        RemediationDetail = remediationdetail;
        RemediationBackground = remediationbackground;
        UrlEncode = urlencode;
        CharsToUrlEncode = charstourlencode;
        RedirType = redirtype;
        payloadsFile = payloadsfile;
        grepsFile = grepsfile;
        MaxRedir = maxredir;
        payloadPosition = payloadposition;
        TimeOut = timeout;
        isTime = istime;
        contentLength = contentlength;
        iscontentLength = iscontentlength;
        Header = header;
        VariationAttributes = variationAttributes;
        pathDiscovery = pathdiscovery;

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

    public String getAuthor() {
        return Author;
    }

    public boolean getActive() {
        return Active;
    }

    public int getScanner() {
        return Scanner;
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

    public String getTime() {
        return TimeOut;
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

    public boolean getUrlEncode() {
        return UrlEncode;
    }

    public int getMatchType() {
        return MatchType;
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
    public void setName(String name) {
        Name = name;
    }

    public void setHeader(List<Headers> header) {
        Header = header;
    }

    public void setVariationAttributes(List<String> variationAttributes) {
        VariationAttributes = variationAttributes;
    }

    public void setAuthor(String author) {
        Author = author;
    }

    public void setActive(boolean active) {
        Active = active;
    }

    public void setScanner(int scanner) {
        Scanner = scanner;
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

    public void setTime(String timeout) {
        TimeOut = timeout;
    }

    public void setIsTime(boolean istime) {
        isTime = istime;
    }

    public void setContentLength(String contentlength) {
        contentLength = contentlength;
    }

    public void setIsContentLength(boolean iscontentlength) {
        iscontentLength = iscontentlength;
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
