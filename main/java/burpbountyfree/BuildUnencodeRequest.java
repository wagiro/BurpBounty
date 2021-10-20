package burpbountyfree;

import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IScannerInsertionPoint;
import java.util.ArrayList;
import java.util.List;

public class BuildUnencodeRequest {

    private IExtensionHelpers helpers;

    BuildUnencodeRequest(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    byte[] buildUnencodedRequest(IScannerInsertionPoint iScannerInsertionPoint, byte[] payload, List<Headers> headers, String bchost) {
        byte[] canary = buildCanary(payload.length);
        byte[] request = iScannerInsertionPoint.buildRequest(canary);
        int canaryPos = findCanary(canary, request);
        System.arraycopy(payload, 0, request, canaryPos, payload.length);
        byte[] finalRequest = request;

        String tempRequest = helpers.bytesToString(request);
        String stringpayload = helpers.bytesToString(payload);

        if (!headers.isEmpty()) {
            try {
                for (int x = 0; x < headers.size(); x++) {
                    String replace = headers.get(x).replace;
                    if (headers.get(x).type.equals("Request")) {
                        if (headers.get(x).regex.equals("String")) {
                            if (replace.contains("{PAYLOAD}")) {
                                replace = replace.replace("{PAYLOAD}", stringpayload);
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
                                replace = replace.replaceAll("\\{PAYLOAD\\}", stringpayload);
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
            } catch (Exception e) {
//                System.out.println("BuildUnencodeRequest line 898: " + e.getMessage());
//                for (StackTraceElement element : e.getStackTrace()) {
//                    System.out.println(element);
//                }
            }
        }

        if (tempRequest.toLowerCase().contains("Content-Length: ".toLowerCase())) {
            byte[] byteRequest = helpers.stringToBytes(tempRequest);
            IRequestInfo messageInfo = helpers.analyzeRequest(byteRequest);
            int bodyOffset = messageInfo.getBodyOffset();
            List<String> newheaders = messageInfo.getHeaders();
            int actualBody = request.length - bodyOffset;
            for (String header : newheaders) {
                if (header.toLowerCase().startsWith("Content-Length: ".toLowerCase())) {
                    header = "Content-Length: " + actualBody;
                }
            }
            byte[] body = helpers.stringToBytes(tempRequest.substring(bodyOffset, byteRequest.length));
            finalRequest = helpers.buildHttpMessage(newheaders, body);
        }else{
            finalRequest = helpers.stringToBytes(tempRequest);
        }

        return finalRequest;
    }

    private byte[] buildCanary(int payloadLength) {
        byte[] canary = new byte[payloadLength];
        for (int i = 0; i < payloadLength; i++) {
            canary[i] = '$';
        }
        return canary;
    }

    private int findCanary(byte[] canary, byte[] request) {
        int canaryPos = helpers.indexOf(request, canary, false, 0, request.length);
        return canaryPos;
    }

}
