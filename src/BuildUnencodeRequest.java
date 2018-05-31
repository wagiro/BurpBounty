package burpbounty;

import burp.IExtensionHelpers;
import burp.IScannerInsertionPoint;
import java.util.Random;

public class BuildUnencodeRequest
{
    private Random random = new Random();
    private IExtensionHelpers helpers;

    BuildUnencodeRequest(IExtensionHelpers helpers)
    {
        this.helpers = helpers;
    }

    byte[] buildUnencodedRequest(IScannerInsertionPoint iScannerInsertionPoint, byte[] payload) throws Exception
    {
        byte[] canary = buildCanary(payload.length);
        byte[] request = iScannerInsertionPoint.buildRequest(canary);
        int canaryPos = findCanary(canary, request);
        System.arraycopy(payload, 0, request, canaryPos, payload.length);
        return request;
    }

    private byte[] buildCanary(int payloadLength)
    {
        byte[] canary = new byte[payloadLength];
        for(int i = 0; i < payloadLength; i++)
        {
            canary[i] = '$';
        }
        return canary;
    }

    private int findCanary(byte[] canary, byte[] request) throws Exception
    {
        int canaryPos = helpers.indexOf(request, canary, false, 0, request.length);
        if(canaryPos == -1)
        {
            throw new Exception("Cannot locate canary in request");
        }
        int canaryPos2 = helpers.indexOf(request, canary, false, canaryPos + 1, request.length);
        if(canaryPos2 != -1)
        {
            throw new Exception("Multiple canary found in request");
        }
        return canaryPos;
    }
}