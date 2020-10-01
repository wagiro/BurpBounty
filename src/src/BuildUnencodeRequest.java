package burpbounty;

import burp.IExtensionHelpers;
import burp.IScannerInsertionPoint;
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

        String tempRequest = helpers.bytesToString(request);
        String stringpayload = helpers.bytesToString(payload);

        if (!headers.isEmpty()) {
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
            return helpers.stringToBytes(tempRequest);
        }
        return request;
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