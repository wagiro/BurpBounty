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
/**
 *
 * @author eduardogarcia
 */
public class Issue {


    private String Name;
    private boolean Active;
    private int Scanner;
    private List<String> Payloads;
    private List<String> Encoder;
    private boolean UrlEncode;
    private String CharsToUrlEncode;
    private List<String> Grep;
    private boolean PayloadResponse;
    private boolean NotResponse;
    private boolean NotCookie;
    private boolean CaseSensitive;
    private boolean ExcludeHTTP;
    private boolean OnlyHTTP;
    private boolean IsContentType;
    private String ContentType;
    private boolean IsResponseCode;
    private String ResponseCode;
    private int MatchType;
    private String IssueName;
    private String IssueType;
    private String IssueSeverity;
    private String IssueConfidence;
    private String IssueDetail;
    private String RemediationDetail;
    private String IssueBackground;
    private String RemediationBackground;
    

    
    public Issue()
    {
        super();
    }
    public Issue(String name, int scanner, boolean active, List payloads, List encoder, String charstourlencode, List grep, boolean casesensitive,boolean urlencode, boolean payloadresponse, boolean notresponse, boolean notcookie, boolean onlyHTTP, boolean excludeHTTP, boolean iscontenttype, String contenttype, boolean isresponsecode, String responsecode, int matchtype, String issuetype, String issuename, String issueseverity, String issueconfidence, String issuedetail, String issuebackground, String remediationdetail, String remediationbackground)
    {
        super();
        Name = name;
        Active = active;
        Scanner = scanner;
        Payloads = payloads;
        Encoder = encoder;
        Grep = grep;
        CaseSensitive = casesensitive;
        PayloadResponse = payloadresponse;
        NotResponse = notresponse;
        NotCookie = notcookie;
        ExcludeHTTP = excludeHTTP;
        OnlyHTTP = onlyHTTP;
        IsContentType = iscontenttype;
        ContentType = contenttype;
        IsResponseCode = isresponsecode;
        ResponseCode = responsecode;
        MatchType = matchtype;
        IssueType = issuetype;
        IssueName = issuename;
        IssueSeverity = issueseverity;
        IssueConfidence = issueconfidence;
        IssueDetail = issuedetail;
        IssueBackground = issuebackground;
        RemediationDetail = remediationdetail;
        RemediationBackground = remediationbackground;
        UrlEncode = urlencode;
        CharsToUrlEncode = charstourlencode;
        
    }

    public String getName()
    {
        return Name;
    }
    
    public boolean getActive()
    {
        return Active;
    }
        
    public int getScanner()
    {
        return Scanner;
    }
    
    public List<String> getPayloads()
    {
        return Payloads;
    }
    
    public List<String> getEncoder()
    {
        return Encoder;
    }
    
    public String getCharsToUrlEncode()
    {
        return CharsToUrlEncode;
    }
        
    public List<String> getGreps()
    {
        return Grep;
    }
    
    public boolean getCaseSensitive()
    {
        return CaseSensitive;
    }
    
    public boolean getPayloadResponse()
    {
        return PayloadResponse;
    }
    
    public boolean getNotResponse()
    {
        return NotResponse;
    }
    
    public boolean getNotCookie()
    {
        return NotCookie;
    }
    
    public boolean getExcludeHTTP()
    {
        return ExcludeHTTP;
    }
    
    public boolean getOnlyHTTP()
    {
        return OnlyHTTP;
    }
    
    public boolean getIsContentType()
    {
        return IsContentType;
    }
    
    public String getContentType()
    {
        return ContentType;
    }
    
    public boolean getIsResponseCode()
    {
        return IsResponseCode;
    }
    
    public String getResponseCode()
    {
        return ResponseCode;
    }
    
    public boolean getUrlEncode()
    {
        return UrlEncode;
    }
        
    public int getMatchType()
    {
        return MatchType;
    }
    
    public String getIssueType()
    {
        return IssueType;
    }
    
    public String getIssueName()
    {
        return IssueName;
    }
    
    public String getIssueSeverity()
    {
        return IssueSeverity;
    }
    
    public String getIssueConfidence()
    {
        return IssueConfidence;
    }
    
    public String getIssueDetail()
    {
        return IssueDetail;
    }
    
    public String getIssueBackground()
    {
        return IssueBackground;
    }
    
    public String getRemediationDetail()
    {
        return RemediationDetail;
    }
    
    public String getRemediationBackground()
    {
        return RemediationBackground;
    }
    
    
    //Set functions
    
    public void setName(String name)
    {
         Name = name;
    }
    
    public void setActive(boolean active)
    {
         Active = active;
    }
        
    public void setScanner(int scanner)
    {
        Scanner = scanner;
    }
    
    public void setPayloads(List<String> payloads)
    {
        Payloads = payloads;
    }
    
    public void setEncoder(List<String> encoder)
    {
         Encoder = encoder;
    }
    
    public void setCharsToUrlEncode(String charstourlencode)
    {
         CharsToUrlEncode = charstourlencode;
    }
    
    public void setGreps(List<String> grep)
    {
        Grep = grep;
    }
    
    
    public void setCaseSensitive(boolean casesensitive)
    {
        CaseSensitive = casesensitive;
    }
    
    public void setPayloadResponse(boolean payloadresponse)
    {
        PayloadResponse = payloadresponse;
    }
    
    public void setNotResponse(boolean notresponse)
    {
        NotResponse = notresponse;
    }
    
    public void setNotCookie(boolean notcookie)
    {
        NotCookie = notcookie;
    }
    
    public void setOnlyHTTP(boolean onlyHTTP)
    {
        OnlyHTTP = onlyHTTP;
    }
    
    public void setExcludeHTTP(boolean excludeHTTP)
    {
        ExcludeHTTP = excludeHTTP;
    }
    
    public void setIsContentType(boolean iscontenttype)
    {
        IsContentType = iscontenttype;
    }
    
    public void setContentType(String contenttype)
    {
        ContentType = contenttype;
    }
    
    public void setIsResponseCode(boolean isresponsecode)
    {
        IsResponseCode = isresponsecode;
    }
    
    public void setResponseCode(String responsecode)
    {
        ResponseCode = responsecode;
    }
    
    public void setUrlEncode(boolean urlencode)
    {
        UrlEncode = urlencode;
    }
    
    public void setMatchType(int matchtype)
    {
        MatchType = matchtype;
    }
    
    public void setIssueType(String issuetype)
    {
        IssueType = issuetype;
    }
    
    public void setIssueName(String issuename)
    {
        IssueName = issuename;
    }
    
    public void setIssueSeverity(String issueseverity)
    {
        IssueSeverity = issueseverity;
    }
    
    public void setIssueConfidence(String issueconfidence)
    {
        IssueConfidence = issueconfidence;
    }
    
    public void setIssueDetail(String issuedetail)
    {
        IssueDetail = issuedetail;
    }
    
    public void setIssueBackground(String issuebackground)
    {
        IssueBackground = issuebackground;
    }
    
    public void setRemediationDetail(String remediationdetail)
    {
        RemediationDetail = remediationdetail;
    }
    
    public void setRemediationBackground(String remediationbackground)
    {
        RemediationBackground = remediationbackground;
    }
}
