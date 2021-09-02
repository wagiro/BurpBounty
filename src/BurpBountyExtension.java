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

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.IScannerInsertionPointProvider;
import burp.ITab;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import java.awt.Dimension;
import javax.swing.ScrollPaneConstants;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

public class BurpBountyExtension implements IBurpExtender, ITab, IScannerCheck, IExtensionStateListener, IScannerInsertionPointProvider, IMessageEditorController {

    public static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JScrollPane optionsTab;
    private BurpBountyGui panel;
    ProfilesProperties issue;
    BurpCollaboratorThread BurpCollaborator;
    BurpCollaboratorThread bct;
    CollaboratorData burpCollaboratorData;
    List<byte[]> responses;
    List<String[]> urls;
    JsonArray profiles;
    JsonArray rules;
    Integer bchost_number = 0;
    Boolean settext = false;
    public IMessageEditor requestViewer;
    public IMessageEditor responseViewer;
    public IHttpRequestResponse currentlyDisplayedItem;
    JsonArray allprofiles = new JsonArray();
    JsonArray activeprofiles = new JsonArray();
    JsonArray passiveresprofiles = new JsonArray();
    JsonArray passivereqprofiles = new JsonArray();
    List<IScanIssue> issues = new ArrayList();
    List<String> params = new ArrayList();
    int scanner = 0;
    Boolean enabled = false;
    List<Integer> insertion_point_type = new ArrayList();
    JsonArray allrules = new JsonArray();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Burp Bounty Free");
        responses = new ArrayList();

        urls = new ArrayList();
        urls.add(new String[]{"testXXYY", "test"});

        try {
            burpCollaboratorData = new CollaboratorData(helpers);
            bct = new BurpCollaboratorThread(callbacks, burpCollaboratorData);
            bct.start();
        } catch (Exception e) {
            System.out.println("BurpBountyExtension line 108:" + e.getMessage());
        }

        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                
                panel = new BurpBountyGui(BurpBountyExtension.this);
                optionsTab = new JScrollPane(panel, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                optionsTab.setPreferredSize(new Dimension(600, 600));
                optionsTab.getVerticalScrollBar().setUnitIncrement(20);
                callbacks.registerScannerCheck(BurpBountyExtension.this);
                callbacks.registerExtensionStateListener(BurpBountyExtension.this);
                callbacks.registerScannerInsertionPointProvider(BurpBountyExtension.this);

                requestViewer = callbacks.createMessageEditor(BurpBountyExtension.this, false);
                responseViewer = callbacks.createMessageEditor(BurpBountyExtension.this, false);

                callbacks.addSuiteTab(BurpBountyExtension.this);

                callbacks.printOutput("- Burp Bounty Free v4.0");
                callbacks.printOutput("- For bugs please on the official github: https://github.com/wagiro/BurpBounty/");
                callbacks.printOutput("- Created and developed by Eduardo Garcia Melia <egarcia@burpbounty.net>");
                callbacks.printOutput("\nBurp Bounty team:");
                callbacks.printOutput("- Eduardo Garcia Melia <egarcia@burpbounty.net>");
                callbacks.printOutput("- Jaime Restrepo <jrestrepo@burpbounty.net>");

            }
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
        Gson gson = new Gson();
        Boolean exist_insertion_point_in_profiles = false;
        try {

            if (baseRequestResponse == null || baseRequestResponse.getRequest() == null) {
                return insertionPoints;
            }

            for (int i = 0; i < activeprofiles.size(); i++) {
                Object idata = activeprofiles.get(i);
                ProfilesProperties profile_property = gson.fromJson(idata.toString(), ProfilesProperties.class);
                for (int insertionPoint : profile_property.getInsertionPointType()) {
                    if (insertionPoint == 65) {
                        exist_insertion_point_in_profiles = true;
                    }

                }
            }
            if (!exist_insertion_point_in_profiles) {
                return insertionPoints;
            }

            IRequestInfo request = helpers.analyzeRequest(baseRequestResponse);

            String url = request.getUrl().getHost();
            byte[] match = helpers.stringToBytes("/");
            byte[] req = baseRequestResponse.getRequest();
            int len = helpers.bytesToString(baseRequestResponse.getRequest()).indexOf(" HTTP");
            int firstSlash = helpers.bytesToString(baseRequestResponse.getRequest()).indexOf(" /");
            int beginAt = 0;
            while (beginAt < len) {
                beginAt = helpers.indexOf(req, match, false, beginAt, len);
                if (beginAt == -1) {
                    break;
                }
                String mark = helpers.bytesToString(baseRequestResponse.getRequest()).substring(firstSlash, beginAt);
                if (!params.contains(url + ":p4r4m" + mark)) {
                    insertionPoints.add(helpers.makeScannerInsertionPoint("p4r4m" + mark, baseRequestResponse.getRequest(), beginAt, len));
                    params.add(url + ":p4r4m" + mark);
                }
                beginAt += match.length;
            }
        } catch (NullPointerException ex) {
            System.out.println("BurpBountyExtension line 167: " + ex.getMessage());//Da Number Format Exception
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
            return insertionPoints;
        }
        return insertionPoints;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

            if (activeprofiles.size() == 0) {
                return issues;
            }

            try {
                ActiveScanner as = new ActiveScanner(this, callbacks, burpCollaboratorData, allprofiles, panel);
                as.runAScan(baseRequestResponse, insertionPoint, activeprofiles, false, false, "", false);
            } catch (Exception ex) {
                System.out.println("BurpBountyExtension line 189: " + ex.getMessage());//Da Number Format Exception
                for (StackTraceElement element : ex.getStackTrace()) {
                    System.out.println(element);
                }
            }
        return issues;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

            if (passiveresprofiles.size() > 0) {
                try {
                    PassiveResponseScanner prs = new PassiveResponseScanner(this, callbacks, burpCollaboratorData, allprofiles, activeprofiles, panel);
                    prs.runResPScan(baseRequestResponse, passiveresprofiles, allrules, urls, false);
                } catch (Exception ex) {
                    System.out.println("BurpBountyExtension line 206: " + ex.getMessage());
                    for (StackTraceElement element : ex.getStackTrace()) {
                        System.out.println(element);
                    }
                }
            }

            if (passivereqprofiles.size() > 0) {

                try {
                    PassiveRequestScanner pqs = new PassiveRequestScanner(this, callbacks, burpCollaboratorData, allprofiles, activeprofiles, panel);
                    pqs.runReqPScan(baseRequestResponse, passivereqprofiles, allrules, urls, false);
                } catch (Exception ex) {
                    System.out.println("BurpBountyExtension line 219: " + ex.getMessage());
                    for (StackTraceElement element : ex.getStackTrace()) {
                        System.out.println(element);
                    }
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
        return "Burp Bounty Free";
    }

    @Override
    public Component getUiComponent() {
        return optionsTab;
    }

    public void setTest(Boolean test) {
        settext = test;
    }

    public void setAllProfiles(JsonArray allProfiles) {
        allprofiles = allProfiles;
        setActiveProfiles(allprofiles);
        setPassiveProfiles(allprofiles);
    }

    public void setActiveProfiles(JsonArray allprofiles) {
        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
        Gson gson = builder.create();
        int scanner = 0;
        ProfilesProperties issue;
        List<Integer> insertion_point_type = new ArrayList();
        Boolean enabled = false;
        activeprofiles = new JsonArray();

        for (int i = 0; i < allprofiles.size(); i++) {
            try {
                Object idata = allprofiles.get(i);
                issue = gson.fromJson(idata.toString(), ProfilesProperties.class);
                scanner = issue.getScanner();
                enabled = issue.getEnabled();
                insertion_point_type = issue.getInsertionPointType();
            } catch (Exception ex) {
                System.out.println("BurpBountyExtension line 399: " + ex.getMessage());
                continue;
            }

            if (scanner == 1 && enabled) {
                activeprofiles.add(allprofiles.get(i));
            }
        }
    }

    public void setPassiveProfiles(JsonArray allprofiles) {
        passiveresprofiles = new JsonArray();
        passivereqprofiles = new JsonArray();
        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
        Gson gson = builder.create();
        int scanner = 0;
        Boolean enabled = false;
        ProfilesProperties issue;

        for (int i = 0; i < allprofiles.size(); i++) {
            try {
                Object idata = allprofiles.get(i);
                issue = gson.fromJson(idata.toString(), ProfilesProperties.class);
                scanner = issue.getScanner();
                enabled = issue.getEnabled();
            } catch (Exception ex) {
                System.out.println("BurpBountyExtension line 341: " + ex.getMessage());
                continue;
            }
            if (enabled && scanner == 2) {
                passiveresprofiles.add(allprofiles.get(i));
            } else if (enabled && scanner == 3) {
                passivereqprofiles.add(allprofiles.get(i));
            }
        }
    }

    public void setRules(JsonArray allRules) {
        allrules = allRules;
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }
}
