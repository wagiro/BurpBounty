package burpbounty;

import burp.IExtensionHelpers;
import burp.IScannerInsertionPoint;
import java.util.List;
import java.util.Random;

public class BuildUnencodeRequest {

    private Random random = new Random();
    private IExtensionHelpers helpers;

    BuildUnencodeRequest(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    byte[] buildUnencodedRequest(IScannerInsertionPoint iScannerInsertionPoint, byte[] payload, List<Headers> headers) throws Exception {
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
                        if (headers.get(x).match.isEmpty()) {
                            tempRequest = tempRequest.replace("\r\n\r\n", "\r\n" + replace + "\r\n\r\n");
                        } else {
                            tempRequest = tempRequest.replace(headers.get(x).match, replace);
                        }
                    } else {
                        if (replace.contains("{PAYLOAD}")) {
                            replace = replace.replaceAll("\\{PAYLOAD\\}", stringpayload);
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

    private int findCanary(byte[] canary, byte[] request) throws Exception {
        int canaryPos = helpers.indexOf(request, canary, false, 0, request.length);
        if (canaryPos == -1) {
            throw new Exception("Cannot locate canary in request");
        }
        int canaryPos2 = helpers.indexOf(request, canary, false, canaryPos + 1, request.length);
        if (canaryPos2 != -1) {
            throw new Exception("Multiple canary found in request");
        }
        return canaryPos;
    }
}
