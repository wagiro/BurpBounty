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
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.IScannerInsertionPointProvider;
import burp.ITab;
import com.google.gson.JsonArray;
import com.google.gson.JsonIOException;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;
import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

public class BurpBountyExtension implements IBurpExtender, ITab, IScannerCheck, IExtensionStateListener, IScannerInsertionPointProvider {

    public static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    List<IBurpCollaboratorClientContext> CollaboratorClientContext;
    private JScrollPane optionsTab;
    private BurpBountyGui panel;
    Issue issue;
    String filename;
    BurpCollaboratorThread BurpCollaborator;
    BurpCollaboratorThread bct;
    CollaboratorData burpCollaboratorData;
    List<byte[]> responses;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Burp Bounty");
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);
        callbacks.registerScannerInsertionPointProvider(this);
        CollaboratorClientContext = new ArrayList();
        burpCollaboratorData = new CollaboratorData(helpers);
        bct = new BurpCollaboratorThread(callbacks, burpCollaboratorData);
        responses = new ArrayList();
        filename = "";

        SwingUtilities.invokeLater(() -> {
            panel = new BurpBountyGui(this);
            optionsTab = new JScrollPane(panel, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            callbacks.addSuiteTab(this);

            callbacks.printOutput("- Burp Bounty v3.0.4beta");
            callbacks.printOutput("- For bugs please on the official github: https://github.com/wagiro/BurpBounty/");
            callbacks.printOutput("- Created by Eduardo Garcia Melia <wagiro@gmail.com>");
            bct.start();

        });

    }

    @Override
    public void extensionUnloaded() {
        bct.doStop();
        callbacks.printOutput("- Burp Bounty extension was unloaded");
    }

    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        List<IScannerInsertionPoint> insertionPoints = new ArrayList();
        IRequestInfo request = helpers.analyzeRequest(baseRequestResponse);

        if (request.getMethod().equals("GET")) {
            byte[] match = helpers.stringToBytes("/");
            byte[] req = baseRequestResponse.getRequest();
            int len = helpers.bytesToString(baseRequestResponse.getRequest()).indexOf("HTTP");
            int beginAt = 0;
            while (beginAt < len) {
                beginAt = helpers.indexOf(req, match, false, beginAt, len);
                if (beginAt == -1) {
                    break;
                }
                insertionPoints.add(helpers.makeScannerInsertionPoint("p4r4m" + beginAt, baseRequestResponse.getRequest(), beginAt, helpers.bytesToString(baseRequestResponse.getRequest()).indexOf(" HTTP")));
                beginAt += match.length;
            }
        }
        return insertionPoints;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        JsonArray data = new JsonArray();
        filename = panel.getFilename();
        FileReader fr;

        try {
            File f = new File(filename);
            if (f.exists() && f.isDirectory()) {
                for (File file : f.listFiles()) {
                    if (file.getName().endsWith("bb")) {
                        fr = new FileReader(file.getAbsolutePath());
                        JsonReader json = new JsonReader(fr);
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());
                    }
                }
            }
        } catch (JsonIOException | JsonSyntaxException | FileNotFoundException e) {
            System.out.println(e.getClass());
        }

        GenericScan as = new GenericScan(callbacks, data, burpCollaboratorData);
        try {
            return as.runAScan(baseRequestResponse, insertionPoint);
        } catch (Exception ex) {
            Logger.getLogger(BurpBountyExtension.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        JsonArray data = new JsonArray();
        filename = panel.getFilename();
        FileReader fr;

        try {
            File f = new File(filename);
            if (f.exists() && f.isDirectory()) {
                for (File file : f.listFiles()) {
                    if (file.getName().endsWith("bb")) {
                        fr = new FileReader(file.getAbsolutePath());
                        JsonReader json = new JsonReader(fr);
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());
                    }
                }
            }
        } catch (JsonIOException | JsonSyntaxException | FileNotFoundException e) {
            System.out.println(e.getClass());
        }

        GenericScan ps = new GenericScan(callbacks, data, burpCollaboratorData);
        try {
            return ps.runPScan(baseRequestResponse);
        } catch (Exception ex) {
            Logger.getLogger(BurpBountyExtension.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }

    @Override
    public String getTabCaption() {
        return "Burp Bounty";
    }

    @Override
    public Component getUiComponent() {
        return optionsTab;
    }
}
