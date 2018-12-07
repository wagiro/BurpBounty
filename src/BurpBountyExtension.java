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
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
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
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
/**
 *
 * @author eduardogarcia
 */
public class BurpBountyExtension implements IBurpExtender, ITab, IScannerCheck {

    public static IBurpExtenderCallbacks callbacks;
    List<IBurpCollaboratorClientContext> CollaboratorClientContext = new ArrayList();
    Properties issueProperties = new Properties();
    private JScrollPane optionsTab; 
    private BurpBountyGui panel; 
    Issue issue;
    String filename = "";
    public boolean doStop = false;
    BurpCollaboratorThread BurpCollaborator;
    
    
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.callbacks.setExtensionName("Burp Bounty");
        this.callbacks.registerScannerCheck(this);
        
        SwingUtilities.invokeLater(() -> {
            panel = new BurpBountyGui(this);
            optionsTab = new JScrollPane(panel, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            this.callbacks.addSuiteTab(this);
            
            
            this.callbacks.printOutput("- BurpBounty v3.0.1beta");
            this.callbacks.printOutput("- For bugs please on the official github: https://github.com/wagiro/BurpBounty/");
            this.callbacks.printOutput("- Created by Eduardo Garcia Melia <wagiro@gmail.com>");
       });
        
    }
    
    public void startBCollaborator(){
        BurpCollaborator = new BurpCollaboratorThread(this);
        Thread thread = new Thread(BurpCollaborator);
        thread.start();
    }
    
    
    public void setCollaboratorClientContext(IBurpCollaboratorClientContext bccc){
        BurpCollaborator.CollaboratorClientContext.add(bccc);
        
    }
    
    
    public void setIssueProperties(IHttpRequestResponse requestResponse, String bchost, String issuename,String issuedetail, String issueseverity, String issueconfidence,
        String issuebackground, String remediationdetail, String remediationbackground){
        issueProperties.put("issuename", issuename);
        issueProperties.put("issuedetail", issuedetail);
        issueProperties.put("issueseverity", issueseverity);
        issueProperties.put("issueconfidence", issueconfidence);
        issueProperties.put("issuebackground", issuebackground);
        issueProperties.put("remediationdetail", remediationdetail);
        issueProperties.put("remediationbackground", remediationbackground);
        BurpCollaborator.issues.put(bchost, issueProperties);
        BurpCollaborator.ccrequestResponse.put(bchost, requestResponse);
    }
    
        
    public void doStop() {
        BurpCollaborator.doStop();
    }

    
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        JsonArray data = new JsonArray();
        filename = panel.getFilename();
        FileReader fr;

        try{
            File f = new File(filename);
            if(f.exists() && f.isDirectory()){
                for(File file :f.listFiles()){
                    if(file.getName().endsWith("bb")){
                        fr =  new FileReader(file.getAbsolutePath());
                        JsonReader json = new JsonReader(fr);
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());
                    }
                }
            }
        }catch (JsonIOException | JsonSyntaxException | FileNotFoundException e) {
            System.out.println(e.getClass());
        }        

            
        GenericScan as = new GenericScan(this,data);   
        try {
            return as.runAScan(baseRequestResponse, insertionPoint);
        } catch (Exception ex) {
            Logger.getLogger(BurpBountyExtension.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        
        JsonArray data = new JsonArray();
        filename = panel.getFilename();
        FileReader fr;

        try{
            File f = new File(filename);
            if(f.exists() && f.isDirectory()){
                for(File file :f.listFiles()){
                    if(file.getName().endsWith("bb")){
                        fr =  new FileReader(file.getAbsolutePath());
                        JsonReader json = new JsonReader(fr);
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());
                    }
                }
            }
        }catch (JsonIOException | JsonSyntaxException | FileNotFoundException e) {
            System.out.println(e.getClass());
        }        

            
        GenericScan ps = new GenericScan(this,data);   
        try {
            return ps.runPScan(baseRequestResponse);
        } catch (Exception ex) {
            Logger.getLogger(BurpBountyExtension.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
     
    
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
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
