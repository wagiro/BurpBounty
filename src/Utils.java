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

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author wagiro
 */
public class Utils {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    JsonArray active_profiles;
    BurpBountyExtension bbe;
    Gson gson;
    CollaboratorData burpCollaboratorData;
    BurpBountyGui bbg;
    JsonArray allprofiles;
    Integer redirtype;
    List<String> rules_done = new ArrayList<>();
    Integer smartscandelay;

    public Utils(BurpBountyExtension bbe, IBurpExtenderCallbacks callbacks, CollaboratorData burpCollaboratorData, JsonArray allprofiles, BurpBountyGui bbg) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        this.burpCollaboratorData = burpCollaboratorData;
        gson = new Gson();
        this.allprofiles = allprofiles;
        this.bbe = bbe;
        this.bbg = bbg;
    }

    public Boolean checkDuplicated(IHttpRequestResponse requestResponse, String issuename, IScannerInsertionPoint insertionPoint) {
        IRequestInfo request = helpers.analyzeRequest(requestResponse);
        String host = request.getUrl().getProtocol() + "://" + request.getUrl().getHost();
        IScanIssue[] issues = callbacks.getScanIssues(host);
        Boolean duplicated = false;

        for (IScanIssue issue : issues) {
            String path = issue.getUrl().getPath();
            String is = issue.getIssueName();
            if (is.equals("BurpBounty - " + issuename) && path.equals(request.getUrl().getPath())) {
                String details = issue.getIssueDetail();
                if (details.contains("Vulnerable parameter")) {
                    String param = details.substring(details.indexOf(": ") + 2, details.indexOf("."));
                    if (param.equals(insertionPoint.getInsertionPointName())) {
                        duplicated = true;
                    }
//                    String param = details.substring(details.indexOf(": ") + 2, details.indexOf("."));
//                    String param2 = insertionPoint.getInsertionPointName()+"_"+String.valueOf(insertionPoint.getInsertionPointType());
//                    //Revisar prque posa el param2 com a artist_0_65 y el param es artist
//                    if (param.equals(insertionPoint.getInsertionPointName()+"_"+String.valueOf(insertionPoint.getInsertionPointType()))) {
//                        duplicated = true;
//                    }
                }
            }
        }

        if (duplicated) {
            return true;
        } else {
            return false;
        }
    }

    public Boolean checkDuplicatedPassiveResponse(IHttpRequestResponse requestResponse, String issuename) {
        IRequestInfo request = helpers.analyzeRequest(requestResponse);
        String host = request.getUrl().getProtocol() + "://" + request.getUrl().getHost();
        IScanIssue[] issues = callbacks.getScanIssues(host);
        Boolean duplicated = false;

        for (IScanIssue issue : issues) {
            String path = issue.getUrl().getPath();
            String is = issue.getIssueName();
            if (is.equals("BurpBounty - " + issuename) && path.equals(request.getUrl().getPath())) {
                duplicated = true;
            }
        }

        if (duplicated) {
            return true;
        } else {
            return false;
        }
    }

    public Boolean checkDuplicatedPassive(IHttpRequestResponse requestResponse, String issuename) {
        IRequestInfo request = helpers.analyzeRequest(requestResponse);
        String host = request.getUrl().getProtocol() + "://" + request.getUrl().getHost();
        IScanIssue[] issues = callbacks.getScanIssues(host);
        Boolean duplicated = false;

        for (IScanIssue issue : issues) {
            String path = issue.getUrl().getPath();
            String is = issue.getIssueName();
            if (is.equals("BurpBounty - " + issuename) && path.equals(request.getUrl().getPath())) {
                duplicated = true;
            }
        }

        if (duplicated) {
            return true;
        } else {
            return false;
        }
    }

    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        List<IScannerInsertionPoint> insertionPoints = new ArrayList();

        try {

            if (baseRequestResponse == null || baseRequestResponse.getRequest() == null || baseRequestResponse.getResponse() == null) {
                return insertionPoints;
            }
            IRequestInfo request = helpers.analyzeRequest(baseRequestResponse);
           
            byte[] req = baseRequestResponse.getRequest();
            if (request.getMethod().equals("GET")) {
                String url = request.getUrl().getHost();
                byte[] match = helpers.stringToBytes("/");
                int len = helpers.bytesToString(baseRequestResponse.getRequest()).indexOf("HTTP");
                int beginAt = 0;

                List<String> params = new ArrayList();
                while (beginAt < len) {
                    beginAt = helpers.indexOf(req, match, false, beginAt, len);
                    if (beginAt == -1) {
                        break;
                    }
                    if (!params.contains(url + ":p4r4m" + beginAt)) {
                        insertionPoints.add(helpers.makeScannerInsertionPoint("p4r4m" + beginAt + "_65", baseRequestResponse.getRequest(), beginAt, helpers.bytesToString(baseRequestResponse.getRequest()).indexOf(" HTTP")));
                        params.add(url + ":p4r4m" + beginAt);
                    }
                    beginAt += match.length;
                }
            }
        } catch (NullPointerException e) {
            return null;
        }
        return insertionPoints;
    }

    public boolean encode(IScannerInsertionPoint insertionPoint, boolean request) {
        byte value = insertionPoint.getInsertionPointType();
        String value2 = insertionPoint.getInsertionPointName();
        if ((value == 0 || value == 34 || value == 33 || value == 37 || value == 65) && !request) {
            return true;
        } else if (value2.endsWith("_0") || value2.endsWith("_34") || value2.endsWith("_33") || value2.endsWith("_37") || value2.endsWith("_65")) {
            return true;
        } else {
            return false;
        }
    }

    public URL getRedirection(IHttpRequestResponse response, IHttpService httpService, Integer redirtype) {

        try {

            URL url = getLocation(httpService, response);

            if (url.toString().contains("burpcollaborator.net")) {
                return url;
            } else if (redirtype == 2) {
                if (url.getHost().contains(httpService.getHost())) {
                    return url;
                }
            } else if (redirtype == 3) {
                boolean isurl = callbacks.isInScope(url);
                if (isurl) {
                    return url;
                }
            } else if (redirtype == 4) {
                return url;
            } else {
                return null;
            }

            return null;
        } catch (NullPointerException | ArrayIndexOutOfBoundsException ex) {
            //Mirar esto genera muchos erroresSystem.out.println("Utils line 1207: " + ex.getMessage());
            return null;
        }
    }

    public URL getLocation(IHttpService httpService, IHttpRequestResponse response) {
        String[] host = null;
        String Location = "";
        URL url;

        try {
            IResponseInfo response_info = helpers.analyzeResponse(response.getResponse());

            for (String header : response_info.getHeaders()) {
                if (header.toUpperCase().startsWith("LOCATION:")) {
                    host = header.split("\\s+");
                    Location = host[1];
                    break;
                }
            }

            if (Location.startsWith("http://") || Location.startsWith("https://")) {
                url = new URL(Location);
                return url;
            } else if (Location.startsWith("/")) {
                url = new URL(httpService.getProtocol() + "://" + httpService.getHost() + Location);
                return url;
            } else {
                url = new URL(httpService.getProtocol() + "://" + httpService.getHost() + "/" + Location);
                return url;
            }

        } catch (MalformedURLException | NullPointerException | ArrayIndexOutOfBoundsException ex) {
            System.out.println("Utils line 1237: " + ex.getMessage());
            return null;
        }
    }

    public byte[] getMatchAndReplace(List<Headers> headers, byte[] checkRequest, String payload, String bchost) {
        String tempRequest = helpers.bytesToString(checkRequest);

        if (!headers.isEmpty()) {
            for (int x = 0; x < headers.size(); x++) {
                String replace = headers.get(x).replace;
                if (headers.get(x).type.equals("Request")) {
                    if (headers.get(x).regex.equals("String")) {
                        if (replace.contains("{PAYLOAD}")) {
                            replace = replace.replace("{PAYLOAD}", payload);
                        }
                        if (replace.contains("{BC}")) {
                            replace = replace.replace("{BC}", bchost);
                        }
                        if (headers.get(x).match.isEmpty()) {
                            tempRequest = tempRequest.replace("\r\n\r\n", "\r\n" + replace + "\r\n\r\n");
                        } else {
                            tempRequest = tempRequest.replace(headers.get(x).match, replace);
                        }
                    } else {
                        if (replace.contains("{PAYLOAD}")) {
                            replace = replace.replaceAll("\\{PAYLOAD\\}", payload);
                        }
                        if (replace.contains("{BC}")) {
                            replace = replace.replaceAll("\\{BC\\}", bchost);
                        }
                        if (headers.get(x).match.isEmpty()) {
                            tempRequest = tempRequest.replaceAll("\\r\\n\\r\\n", "\r\n" + replace + "\r\n\r\n");
                        } else {
                            tempRequest = tempRequest.replaceAll(headers.get(x).match, replace);
                        }
                    }

                }
            }
        }
        return helpers.stringToBytes(tempRequest);
    }

    public int getContentLength(IHttpRequestResponse response) {
        IResponseInfo response_info;
        try {
            response_info = helpers.analyzeResponse(response.getResponse());
        } catch (NullPointerException ex) {
            System.out.println("Utils line 1279: " + ex.getMessage());
            return 0;
        }

        int ContentLength = 0;

        for (String headers : response_info.getHeaders()) {
            if (headers.toUpperCase().startsWith("CONTENT-LENGTH:")) {
                ContentLength = Integer.parseInt(headers.split("\\s+")[1]);
                break;
            }
        }
        return ContentLength;
    }

    public boolean isResponseCode(String responsecodes, boolean negativerc, Integer responsecode) {

        if (responsecodes.isEmpty()) {
            return false;
        }

        List<String> items = Arrays.asList(responsecodes.split("\\s*,\\s*"));
        String code = Integer.toString(responsecode);

        if (items.contains(code)) {
            if (!negativerc) {
                return true;
            } else {
                return false;
            }
        } else {
            if (negativerc) {
                return true;
            } else {
                return false;
            }
        }
    }

    public boolean isContentType(String contenttype, boolean negativect, IResponseInfo r) {
        List<String> HEADERS = r.getHeaders();

        if (contenttype.isEmpty()) {
            return false;
        }

        List<String> items = Arrays.asList(contenttype.toUpperCase().split("\\s*,\\s*"));

        for (String header : HEADERS) {
            if (header.toUpperCase().startsWith("CONTENT-TYPE:")) {
                String content_type = header.substring(header.lastIndexOf(":") + 2).split(";")[0].toUpperCase();
                if (items.contains(content_type)) {
                    if (negativect) {
                        return false;
                    }
                    break;
                } else {
                    if (!negativect) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    public List processPayload(List<String> payloads, List<String> encoders) {
        List pay = new ArrayList();
        for (String payload : payloads) {
            payload = payload.replace("true,", "");

            for (String p : encoders) {
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
            pay.add(payload);
        }

        return pay;
    }

    public static String encodeURL(String s) {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            out.append("%" + Integer.toHexString((int) c));
        }
        return out.toString();
    }

    public static String encodeUnicodeURL(String s) {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            out.append("%u00" + Integer.toHexString((int) c));
        }
        return out.toString();
    }

    public static String encodeHTML(String s) {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            out.append("&#x" + Integer.toHexString((int) c) + ";");
        }
        return out.toString();
    }

    public static String encodeKeyHTML(String s) {
        StringBuffer out = new StringBuffer();
        String key = "\\<\\(\\[\\\\\\^\\-\\=\\$\\!\\|\\]\\)\\?\\*\\+\\.\\>]\\&\\%\\:\\@ ";
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (key.contains(s.substring(i, i + 1))) {
                out.append("&#x" + Integer.toHexString((int) c) + ";");
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    public static String encodeKeyURL(String s) {
        StringBuffer out = new StringBuffer();
        String key = "\\<\\(\\[\\\\\\^\\-\\=\\$\\!\\|\\]\\)\\?\\*\\+\\.\\>]\\&\\%\\:\\@ ";
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (key.contains(s.substring(i, i + 1))) {
                out.append("%" + Integer.toHexString((int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    public static String encodeTheseURL(String s, String characters) {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (characters.indexOf(c) >= 0) {
                out.append("%" + Integer.toHexString((int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

}
