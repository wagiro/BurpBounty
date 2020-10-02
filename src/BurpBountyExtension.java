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
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import java.awt.Component;
import java.awt.Dimension;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

public class BurpBountyExtension implements IBurpExtender, ITab, IScannerCheck, IExtensionStateListener, IScannerInsertionPointProvider {

    public static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    List<IBurpCollaboratorClientContext> CollaboratorClientContext;
    private JScrollPane optionsTab;
    private BurpBountyGui panel;
    ProfilesProperties issue;
    BurpCollaboratorThread BurpCollaborator;
    BurpCollaboratorThread bct;
    CollaboratorData burpCollaboratorData;
    List<byte[]> responses;
    List<String> params;
    Gson gson;
    int scanner;
    JsonArray profiles;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Burp Bounty");
        responses = new ArrayList();
        params = new ArrayList();
        gson = new Gson();
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);
        callbacks.registerScannerInsertionPointProvider(this);
        CollaboratorClientContext = new ArrayList();
        burpCollaboratorData = new CollaboratorData(helpers);
        bct = new BurpCollaboratorThread(callbacks, burpCollaboratorData);
        bct.start();

        SwingUtilities.invokeLater(() -> {
            panel = new BurpBountyGui(this);
            optionsTab = new JScrollPane(panel, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            optionsTab.setPreferredSize(new Dimension(600, 600));
            optionsTab.getVerticalScrollBar().setUnitIncrement(20);
            callbacks.addSuiteTab(this);

            callbacks.printOutput("- Burp Bounty v3.5");
            callbacks.printOutput("- For bugs please on the official github: https://github.com/wagiro/BurpBounty/");
            callbacks.printOutput("- Created by Eduardo Garcia Melia <wagiro@gmail.com>");

        });

    }

    public JsonArray getProfiles() {
        FileReader fr;

        try {
            JsonArray data = new JsonArray();
            File f = new File(panel.profiles_directory);
            if (f.exists() && f.isDirectory()) {
                for (File file : f.listFiles()) {
                    if (file.getName().endsWith(".bb")) {
                        fr = new FileReader(file.getAbsolutePath());
                        JsonReader json = new JsonReader((fr));
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());
                        fr.close();
                    }

                }
            }
            return data;
        } catch (Exception e) {
            callbacks.printError("BurpBountyGui line 1823:" + e.getMessage());
            return null;
        }
    }

    @Override
    public void extensionUnloaded() {
        bct.doStop();
        callbacks.printOutput("- Burp Bounty extension was unloaded");
    }

    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        List<IScannerInsertionPoint> insertionPoints = new ArrayList();

        try {
            IRequestInfo request = helpers.analyzeRequest(baseRequestResponse);

            if (request.getMethod().equals("GET")) {
                String url = request.getUrl().getHost();
                byte[] match = helpers.stringToBytes("/");
                byte[] req = baseRequestResponse.getRequest();
                int len = helpers.bytesToString(baseRequestResponse.getRequest()).indexOf("HTTP");
                int beginAt = 0;

                while (beginAt < len) {
                    beginAt = helpers.indexOf(req, match, false, beginAt, len);
                    if (beginAt == -1) {
                        break;
                    }
                    if (!params.contains(url + ":p4r4m" + beginAt)) {
                        insertionPoints.add(helpers.makeScannerInsertionPoint("p4r4m" + beginAt, baseRequestResponse.getRequest(), beginAt, helpers.bytesToString(baseRequestResponse.getRequest()).indexOf(" HTTP")));
                        params.add(url + ":p4r4m" + beginAt);
                    }
                    beginAt += match.length;
                }
            }
        } catch (NullPointerException e) {
            return insertionPoints;
        }
        return insertionPoints;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        JsonArray allprofiles = getProfiles();
        JsonArray activeprofiles = new JsonArray();
        params = new ArrayList();

        try {
            for (int i = 0; i < allprofiles.size(); i++) {
                Object idata = allprofiles.get(i);
                issue = gson.fromJson(idata.toString(), ProfilesProperties.class);
                scanner = issue.getScanner();

                if (scanner == 1 && issue.getEnabled() && issue.getInsertionPointType().contains(insertionPoint.getInsertionPointType() & 0xFF)) {
                    activeprofiles.add(allprofiles.get(i));
                }

            }
            if (activeprofiles.size() == 0) {
                return null;
            }

            GenericScan as = new GenericScan(this, callbacks, burpCollaboratorData, panel.getProfilesFilename(), allprofiles);

            IBurpCollaboratorClientContext CollaboratorClientContext2 = callbacks.createBurpCollaboratorClientContext();
            burpCollaboratorData.setCollaboratorClientContext(CollaboratorClientContext2);
            String bchost = CollaboratorClientContext2.generatePayload(true);
            return as.runAScan(baseRequestResponse, insertionPoint, activeprofiles, bchost);
        } catch (Exception ex) {
            callbacks.printError("BurpBountyExtension line 174: " + ex.getMessage());
        }
        return null;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        JsonArray allprofiles = getProfiles();
        JsonArray passiveresprofiles = new JsonArray();
        JsonArray passivereqprofiles = new JsonArray();
        List<IScanIssue> issues = new ArrayList();

        for (int i = 0; i < allprofiles.size(); i++) {
            Object idata = allprofiles.get(i);
            issue = gson.fromJson(idata.toString(), ProfilesProperties.class);
            scanner = issue.getScanner();
            if (issue.getEnabled() && scanner == 2) {
                passiveresprofiles.add(allprofiles.get(i));
            } else if (issue.getEnabled() && scanner == 3) {
                passivereqprofiles.add(allprofiles.get(i));
            }
        }

        if (passiveresprofiles.size() > 0) {
            GenericScan ps = new GenericScan(this, callbacks, burpCollaboratorData, panel.getProfilesFilename(), allprofiles);

            try {
                IBurpCollaboratorClientContext CollaboratorClientContext2 = callbacks.createBurpCollaboratorClientContext();
                burpCollaboratorData.setCollaboratorClientContext(CollaboratorClientContext2);
                String bchost = CollaboratorClientContext2.generatePayload(true);
                issues.addAll(ps.runResPScan(baseRequestResponse, passiveresprofiles, bchost));
            } catch (Exception ex) {
                callbacks.printError("BurpBountyExtension line 219: " + ex.getMessage());
            }
        }

        if (passivereqprofiles.size() > 0) {
            GenericScan ps = new GenericScan(this, callbacks, burpCollaboratorData, panel.getProfilesFilename(), allprofiles);

            try {
                IBurpCollaboratorClientContext CollaboratorClientContext2 = callbacks.createBurpCollaboratorClientContext();
                burpCollaboratorData.setCollaboratorClientContext(CollaboratorClientContext2);
                String bchost = CollaboratorClientContext2.generatePayload(true);
                issues.addAll(ps.runReqPScan(baseRequestResponse, passivereqprofiles, bchost));
            } catch (Exception ex) {
                callbacks.printError("BurpBountyExtension line 229: " + ex.getMessage());
            }
        }
        return issues;
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
        return "Scan Check Builder";
    }

    @Override
    public Component getUiComponent() {
        return optionsTab;
    }

}
