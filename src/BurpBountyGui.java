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

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultListModel; 
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

/**
 *
 * @author eduardogarcia
 */
public class BurpBountyGui extends javax.swing.JPanel{
    
    /**
     * Creates new form BurpBountyGui
     */
    //Define global variables
    String filename = System.getenv("HOME") + "/.BurpSuite/BurpBounty/profiles/";
    String name;
    String issuetype;
    String issuename;
    String issuedetail;
    String issuebackground;
    String remediationdetail;
    String remediationbackground;
    String charstourlencode;
    int scanner;
    int matchtype;
    String issueseverity;
    String issueconfidence;
    boolean notresponse; 
    boolean casesensitive;
    boolean notcookie;
    boolean payloadenc;
    boolean urlencode;
    boolean isresponsecode;
    boolean iscontenttype;
    List<String> items = new ArrayList();
    DefaultListModel payload = new DefaultListModel();
    DefaultListModel grep = new DefaultListModel();
    DefaultListModel encoder = new DefaultListModel();
    String responsecode;
    String contenttype;
    private IBurpExtenderCallbacks callbacks;
    
   
    public void clear(){
        text1.setText("");

        buttonGroup1.setSelected(radio1.getModel(), false);
        buttonGroup1.setSelected(radio2.getModel(), false);
        grep.removeAllElements();
        payload.removeAllElements();
        encoder.removeAllElements();
        text71.setText("");  
        text72.setText("");
        check8.setSelected(false);
        text5.setText("");
        buttonGroup4.clearSelection();
        check1.setSelected(false);
        check4.setSelected(false);
        check55.setSelected(false);
        check71.setSelected(false);
        check72.setSelected(false);
        text4.setText("");
        textarea1.setText("");
        textarea2.setText("");
        textarea3.setText("");
        textarea4.setText("");
        buttonGroup2.setSelected(radio5.getModel(), false);
        buttonGroup2.setSelected(radio6.getModel(), false);
        buttonGroup2.setSelected(radio7.getModel(), false);
        buttonGroup2.setSelected(radio8.getModel(), false);
        buttonGroup3.setSelected(radio9.getModel(), false);
        buttonGroup3.setSelected(radio10.getModel(), false);
        buttonGroup3.setSelected(radio11.getModel(), false);
        buttonGroup4.setSelected(radio4.getModel(), false);
        buttonGroup4.setSelected(radio3.getModel(), false);
        buttonGroup4.setSelected(radio12.getModel(), false);
        buttonGroup4.setSelected(radio22.getModel(), false);
    }
    
    
    public void setAttackValues(String issue){
        //Set Attack values when select from main combobox
        try{       
            Gson gson = new Gson();
            JsonArray json = initJson();
            Issue i = new Issue();
            
            if (json != null){
                for (JsonElement pa : json) {
                    JsonObject bbObj  = pa.getAsJsonObject();
                    if(bbObj.get("Name").getAsString().equals(issue)){
                        i = gson.fromJson(bbObj.toString(), Issue.class);
                    }

                }
            }       
            
            name = i.getName();
            scanner = i.getScanner();
            casesensitive = i.getCaseSensitive();
            notresponse = i.getNotResponse();
            notcookie = i.getNotCookie();
            matchtype = i.getMatchType();
            issuetype = i.getIssueType();
            issuename = i.getIssueName();
            issueseverity = i.getIssueSeverity();
            issueconfidence = i.getIssueConfidence();
            issuedetail = i.getIssueDetail();
            issuebackground = i.getIssueBackground();
            remediationdetail = i.getRemediationDetail();
            remediationbackground = i.getRemediationBackground();
            urlencode = i.getUrlEncode();
            charstourlencode = i.getCharsToUrlEncode();
            iscontenttype = i.getIsContentType();
            isresponsecode = i.getIsResponseCode();
            contenttype = i.getContentType();
            responsecode = i.getResponseCode();
            
            
            if(name.length() >= 35){
                text1.setText(name.substring(0, 34));
            }else{
                text1.setText(name);
            }
            
            
            if(scanner == 1){
                buttonGroup1.setSelected(radio1.getModel(), true);
            }else if (scanner == 2){
                buttonGroup1.setSelected(radio2.getModel(), true);
            }            
            
            grep.removeAllElements();
            payload.removeAllElements();
            encoder.removeAllElements();
            
            
            
            for(String gs : i.getGreps())
            {
                grep.addElement(gs);
            }
            
            for(String pay : i.getPayloads())
            {
                payload.addElement(pay);
            }
            
            for(String enc : i.getEncoder())
            {
                encoder.addElement(enc);
            }
            
            text71.setText(contenttype);
            text72.setText(responsecode);
            
            check8.setSelected(urlencode);
            text5.setText(charstourlencode);
            
            switch (matchtype) {
                case 1:
                    buttonGroup4.setSelected(radio4.getModel(), true);
                    break;
                case 2:
                    buttonGroup4.setSelected(radio3.getModel(), true);
                    break;
                case 3:
                    buttonGroup4.setSelected(radio12.getModel(), true);
                    break;
                case 4:
                    buttonGroup4.setSelected(radio22.getModel(), true);
                    break;
                default:
                    buttonGroup4.clearSelection();
                    break;
            }
            
            check1.setSelected(casesensitive);
            check4.setSelected(notresponse);
            check55.setSelected(notcookie);
            check71.setSelected(iscontenttype);
            check72.setSelected(isresponsecode);
            text4.setText(issuename);
            textarea1.setText(issuedetail);
            textarea2.setText(issuebackground);
            textarea3.setText(remediationdetail);
            textarea4.setText(remediationbackground);
            text11.setText(filename);

            switch (issueseverity) {
                case "High":
                    buttonGroup2.setSelected(radio5.getModel(), true);
                    break;
                case "Medium":
                    buttonGroup2.setSelected(radio6.getModel(), true);
                    break;
                case "Low":
                    buttonGroup2.setSelected(radio7.getModel(), true);
                    break;
                case "Information":
                    buttonGroup2.setSelected(radio8.getModel(), true);
                    break;
                default:
                    break;
            }

            switch (issueconfidence) {
                case "Certain":
                    buttonGroup3.setSelected(radio9.getModel(), true);
                    break;
                case "Firm":
                    buttonGroup3.setSelected(radio10.getModel(), true);
                    break;
                case "Tentative":
                    buttonGroup3.setSelected(radio11.getModel(), true);
                    break;
                default:
                    break;
            }        
        }catch (Exception e){
            System.out.println(e.getClass());
        }
    }
    
    
    public void saveAttackValues(){
        //Save attack with fields values
        try{
            //get GUI values
            Issue newfile = new Issue();

            if(text1.getText().length() >= 35){
                newfile.setName(text1.getText().substring(0, 34));
            }else{
                newfile.setName(text1.getText());
            }
            
            
            if(radio1.isSelected()){
                newfile.setScanner(1);
            }else if(radio2.isSelected()){
                newfile.setScanner(2);
            }else{
                newfile.setScanner(0);
            }
            
            newfile.setActive(true);
            List encoders = new ArrayList();
            List payloads = new ArrayList();
            List greps = new ArrayList();
            
            for (int i = 0; i < list1.getModel().getSize(); i++) {
                Object item = list1.getModel().getElementAt(i);
                payloads.add(item);
            }
            newfile.setPayloads(payloads);
            

            for (int i = 0; i < list2.getModel().getSize(); i++) {
                Object item = list2.getModel().getElementAt(i);
                greps.add(item);
            }
            newfile.setGreps(greps); 
            
            for (int i = 0; i < list3.getModel().getSize(); i++) {
                Object item = list3.getModel().getElementAt(i);
                encoders.add(item);
            }
            newfile.setEncoder(encoders);
            newfile.setCharsToUrlEncode(text5.getText());
            newfile.setUrlEncode(check8.isSelected());

            newfile.setContentType(text71.getText());
            newfile.setResponseCode(text72.getText());
            
            
            
            
            
            if(radio4.isSelected()){
                newfile.setMatchType(1);
            }else if(radio3.isSelected()){
                newfile.setMatchType(2);
            }else if(radio12.isSelected()){
                newfile.setMatchType(3);
            }else if(radio22.isSelected()){
                newfile.setMatchType(4);
            }else{
                newfile.setMatchType(0);
            }
            
            newfile.setCaseSensitive(check1.isSelected());
            newfile.setNotResponse(check4.isSelected());
            newfile.setNotCookie(check55.isSelected());
            newfile.setIsContentType(check71.isSelected());
            newfile.setIsResponseCode(check72.isSelected());
            newfile.setIssueName(text4.getText());
            newfile.setIssueDetail(textarea1.getText());
            newfile.setIssueBackground(textarea2.getText());
            newfile.setRemediationDetail(textarea3.getText());
            newfile.setRemediationBackground(textarea4.getText());
            
            if(radio5.isSelected()){
                newfile.setIssueSeverity("High");
            }else if(radio6.isSelected()){
                newfile.setIssueSeverity("Medium");
            }else if(radio7.isSelected()){
                newfile.setIssueSeverity("Low");
            }else if(radio8.isSelected()){
                newfile.setIssueSeverity("Information");
            }
            
            if(radio9.isSelected()){
                newfile.setIssueConfidence("Certain");
            }else if(radio10.isSelected()){
                newfile.setIssueConfidence("Firm");
            }else if(radio11.isSelected()){
                newfile.setIssueConfidence("Tentative");
            }
                      
            //Save start
            Gson gson = new Gson();            

            JsonArray ijson = new JsonArray();
            List<Issue> newjson = gson.fromJson(ijson, new TypeToken<List<Issue>>() {}.getType());
            newjson.add(newfile);
            
            String json = gson.toJson(newjson);          
            //Write JSON String to file
            FileOutputStream fileStream;
            if(text1.getText().length() >= 35){
                fileStream = new FileOutputStream(new File(text11.getText()+"/"+text1.getText().substring(0, 34)+".bb"));
            }else{
                fileStream = new FileOutputStream(new File(text11.getText()+"/"+text1.getText())+".bb");
            }
            
            OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");  
            writer.write(json);
            writer.close();
            fileStream.close();
            
        } catch (IOException e){
            e.printStackTrace();
        }
    }
      
    
    public void initCombo(){
        //Init main comboBox with file values
        JsonArray json = initJson();
        combo1.removeAllItems();
        if (json != null){
            //Names for main combo box
            for (JsonElement pa : json) {
                JsonObject bbObj  = pa.getAsJsonObject();
                if(bbObj.get("Active").getAsBoolean()){
                    combo1.addItem(bbObj.get("Name").getAsString());
                }
            }   
        }
    }
    
    
    public JsonArray initJson(){
        //Init json form filename
        FileReader fr;
        
        try{
            JsonArray data = new JsonArray();
            File f = new File(filename);
            if(!f.exists())
                System.out.println("No File/Dir");
            if(f.isDirectory()){// a directory!
                for(File file :f.listFiles()){
                    if(file.getName().endsWith("bb")){
                        fr =  new FileReader(file.getAbsolutePath());
                        JsonReader json = new JsonReader((fr));
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());
                        fr.close();
                    }
                    
                }
            }
            return data;
            
            
            

        }catch (Exception e) {
            System.out.println(e.getClass());
            return null;
        }
    }
    
    
    public String getClipboardContents() {
        //Get clipboard contents for implement grep and match paste button
        String result = "";
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable contents = clipboard.getContents(null);
        boolean hasTransferableText = (contents != null) && contents.isDataFlavorSupported(DataFlavor.stringFlavor);
        
        if (hasTransferableText) {
            try {
                result = (String)contents.getTransferData(DataFlavor.stringFlavor);
            }catch (UnsupportedFlavorException | IOException ex){
                System.out.println(ex);
                ex.printStackTrace();
            }
        }
        return result;
    }
    
    
    public void loadConfigFile(){
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Specify a profiles directory to load"); 
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        int userSelection = fileChooser.showOpenDialog(parentFrame);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileload = fileChooser.getSelectedFile();
            filename = fileload.getAbsolutePath()+"/";
            text11.setText(fileload.getAbsolutePath());
            
            initJson();
            initCombo();            
            this.callbacks.saveExtensionSetting("filename", filename);
            
           }
    }
        
    
    public void loadFile(DefaultListModel list){
        //Load file for implement payloads and match load button
        DefaultListModel List = list;
        String line;
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Specify a file to load");

        int userSelection = fileChooser.showOpenDialog(parentFrame);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileload = fileChooser.getSelectedFile();
            try {
                BufferedReader bufferreader = new BufferedReader(new FileReader(fileload.getAbsolutePath()));
                line = bufferreader.readLine();

                while (line != null) {     
                    List.addElement(line);
                    line = bufferreader.readLine();
                }
                bufferreader.close();
            } catch (FileNotFoundException ex) {
                ex.printStackTrace();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }
    
    
    public String getFilename(){
        return filename;
    }
    
    private void swap(int a, int b) {
        Object aObject = encoder.getElementAt(a);
        Object bObject = encoder.getElementAt(b);
        encoder.set(a, bObject);
        encoder.set(b, aObject);
    }
    
    
    public BurpBountyGui(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        if (callbacks.loadExtensionSetting("filename") != null) {
            filename = callbacks.loadExtensionSetting("filename");
        }
        
       //main
       initComponents();
       initCombo();

    }
 
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        buttonGroup2 = new javax.swing.ButtonGroup();
        buttonGroup3 = new javax.swing.ButtonGroup();
        buttonGroup4 = new javax.swing.ButtonGroup();
        buttonGroup5 = new javax.swing.ButtonGroup();
        buttonGroup6 = new javax.swing.ButtonGroup();
        combo1 = new javax.swing.JComboBox<>();
        jLabel1 = new javax.swing.JLabel();
        text1 = new javax.swing.JTextField();
        jScrollPane2 = new javax.swing.JScrollPane();
        list2 = new javax.swing.JList<>();
        button7 = new javax.swing.JButton();
        button8 = new javax.swing.JButton();
        button9 = new javax.swing.JButton();
        button10 = new javax.swing.JButton();
        button2 = new javax.swing.JButton();
        button3 = new javax.swing.JButton();
        button4 = new javax.swing.JButton();
        button5 = new javax.swing.JButton();
        button6 = new javax.swing.JButton();
        button11 = new javax.swing.JButton();
        textfield1 = new javax.swing.JTextField();
        textfield2 = new javax.swing.JTextField();
        radio1 = new javax.swing.JRadioButton();
        tab5 = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        text4 = new javax.swing.JTextField();
        radio5 = new javax.swing.JRadioButton();
        radio6 = new javax.swing.JRadioButton();
        radio7 = new javax.swing.JRadioButton();
        radio8 = new javax.swing.JRadioButton();
        jLabel7 = new javax.swing.JLabel();
        radio9 = new javax.swing.JRadioButton();
        radio10 = new javax.swing.JRadioButton();
        radio11 = new javax.swing.JRadioButton();
        jPanel2 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        textarea1 = new javax.swing.JTextArea();
        jLabel9 = new javax.swing.JLabel();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane7 = new javax.swing.JScrollPane();
        textarea2 = new javax.swing.JTextArea();
        jLabel13 = new javax.swing.JLabel();
        jPanel5 = new javax.swing.JPanel();
        jScrollPane9 = new javax.swing.JScrollPane();
        textarea4 = new javax.swing.JTextArea();
        jLabel15 = new javax.swing.JLabel();
        jPanel4 = new javax.swing.JPanel();
        jScrollPane8 = new javax.swing.JScrollPane();
        textarea3 = new javax.swing.JTextArea();
        jLabel14 = new javax.swing.JLabel();
        radio2 = new javax.swing.JRadioButton();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        jScrollPane3 = new javax.swing.JScrollPane();
        list1 = new javax.swing.JList<>();
        radio4 = new javax.swing.JRadioButton();
        radio3 = new javax.swing.JRadioButton();
        jLabel12 = new javax.swing.JLabel();
        jButton2 = new javax.swing.JButton();
        jSeparator4 = new javax.swing.JSeparator();
        radio12 = new javax.swing.JRadioButton();
        button44 = new javax.swing.JButton();
        jButton5 = new javax.swing.JButton();
        text11 = new javax.swing.JTextField();
        jPanel6 = new javax.swing.JPanel();
        check4 = new javax.swing.JCheckBox();
        check1 = new javax.swing.JCheckBox();
        check72 = new javax.swing.JCheckBox();
        check71 = new javax.swing.JCheckBox();
        text71 = new javax.swing.JTextField();
        text72 = new javax.swing.JTextField();
        check55 = new javax.swing.JCheckBox();
        jPanel8 = new javax.swing.JPanel();
        jPanel7 = new javax.swing.JPanel();
        text5 = new javax.swing.JTextField();
        check8 = new javax.swing.JCheckBox();
        combo2 = new javax.swing.JComboBox<>();
        jButton6 = new javax.swing.JButton();
        jButton7 = new javax.swing.JButton();
        jButton8 = new javax.swing.JButton();
        jButton9 = new javax.swing.JButton();
        jScrollPane4 = new javax.swing.JScrollPane();
        list3 = new javax.swing.JList<>();
        radio22 = new javax.swing.JRadioButton();
        jButton1 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();

        combo1.setModel(new javax.swing.DefaultComboBoxModel<>());
        combo1.setSize(new java.awt.Dimension(52, 27));
        combo1.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                selectAttack(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Lucida Grande", 0, 15)); // NOI18N
        jLabel1.setText("Select Profile:");

        list2.setModel(grep);
        jScrollPane2.setViewportView(list2);

        button7.setText("Paste");
        button7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pasteGrep(evt);
            }
        });

        button8.setText("Load");
        button8.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadGrep(evt);
            }
        });

        button9.setText("Remove");
        button9.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeGrep(evt);
            }
        });

        button10.setText("Clear");
        button10.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeAllGrep(evt);
            }
        });

        button2.setText("Paste");
        button2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pastePayload(evt);
            }
        });

        button3.setText("Load");
        button3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadPayloads(evt);
            }
        });

        button4.setText("Remove");
        button4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removePayload(evt);
            }
        });

        button5.setText("Clear");
        button5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeAllPayloads(evt);
            }
        });

        button6.setText("Add");
        button6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                setToPayload(evt);
            }
        });

        button11.setText("Add");
        button11.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                setToGrep(evt);
            }
        });

        buttonGroup1.add(radio1);
        radio1.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        radio1.setText("Active");

        jLabel3.setText("Issue Name:");

        jLabel4.setText("Severity:");

        buttonGroup2.add(radio5);
        radio5.setText("High");

        buttonGroup2.add(radio6);
        radio6.setText("Medium");

        buttonGroup2.add(radio7);
        radio7.setText("Low");

        buttonGroup2.add(radio8);
        radio8.setText("Information");

        jLabel7.setText("Confidence:");

        buttonGroup5.add(radio9);
        radio9.setText("Certain");

        buttonGroup5.add(radio10);
        radio10.setText("Firm");

        buttonGroup5.add(radio11);
        radio11.setText("Tentative");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(145, 145, 145)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(radio8)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(radio6)
                                    .addComponent(radio7)
                                    .addComponent(radio5))
                                .addGap(44, 44, 44)
                                .addComponent(jLabel7)
                                .addGap(18, 18, 18)
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(radio9)
                                    .addComponent(radio11)
                                    .addComponent(radio10)))))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(text4, javax.swing.GroupLayout.PREFERRED_SIZE, 412, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(628, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(text4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel7)
                            .addComponent(radio9))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(radio10)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(radio11))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel4)
                            .addComponent(radio5))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(radio6)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(radio7)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(radio8)))
                .addContainerGap(16, Short.MAX_VALUE))
        );

        tab5.addTab("Issue Properties", jPanel1);

        textarea1.setColumns(20);
        textarea1.setRows(5);
        jScrollPane1.setViewportView(textarea1);

        jLabel9.setText("Description:");

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(27, 27, 27)
                .addComponent(jLabel9)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 612, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(534, Short.MAX_VALUE))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel9)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 161, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        tab5.addTab("Issue Detail", jPanel2);

        textarea2.setColumns(20);
        textarea2.setRows(5);
        jScrollPane7.setViewportView(textarea2);

        jLabel13.setText("Description:");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(27, 27, 27)
                .addComponent(jLabel13)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane7, javax.swing.GroupLayout.PREFERRED_SIZE, 612, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(534, Short.MAX_VALUE))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel13)
                    .addComponent(jScrollPane7, javax.swing.GroupLayout.PREFERRED_SIZE, 161, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        tab5.addTab("Issue Background", jPanel3);

        textarea4.setColumns(20);
        textarea4.setRows(5);
        jScrollPane9.setViewportView(textarea4);

        jLabel15.setText("Description:");

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addGap(27, 27, 27)
                .addComponent(jLabel15)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane9, javax.swing.GroupLayout.PREFERRED_SIZE, 612, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(534, Short.MAX_VALUE))
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel15)
                    .addComponent(jScrollPane9, javax.swing.GroupLayout.PREFERRED_SIZE, 161, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        tab5.addTab("Remediation Detail", jPanel5);

        textarea3.setColumns(20);
        textarea3.setRows(5);
        jScrollPane8.setViewportView(textarea3);

        jLabel14.setText("Description:");

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addGap(27, 27, 27)
                .addComponent(jLabel14)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane8, javax.swing.GroupLayout.PREFERRED_SIZE, 612, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(534, Short.MAX_VALUE))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel14)
                    .addComponent(jScrollPane8, javax.swing.GroupLayout.PREFERRED_SIZE, 161, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        tab5.addTab("Remediation Background", jPanel4);

        buttonGroup1.add(radio2);
        radio2.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        radio2.setText("Passive");

        jLabel5.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel5.setText("Payloads");

        jLabel6.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel6.setText("Grep - Match");

        jLabel8.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel8.setText("Select Scanner:");

        list1.setModel(payload);
        jScrollPane3.setViewportView(list1);

        buttonGroup4.add(radio4);
        radio4.setText("Grep simple string");

        buttonGroup4.add(radio3);
        radio3.setText("Grep regex");

        jLabel12.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel12.setText("Name:");

        jButton2.setText("Save");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveAttack(evt);
            }
        });

        buttonGroup4.add(radio12);
        radio12.setText("Grep payload");

        button44.setText("Profiles Manager");
        button44.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ActionProfile(evt);
            }
        });

        jButton5.setText("Profile Directory");
        jButton5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadConfigFile(evt);
            }
        });

        jPanel6.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Grep Options", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.TOP, new java.awt.Font("Lucida Grande", 0, 14))); // NOI18N

        check4.setText("Negative match");

        check1.setText("Case sensitive");

        check72.setText("Response code");

        check71.setText("Content type");

        check55.setText("Not in cookie");

        javax.swing.GroupLayout jPanel8Layout = new javax.swing.GroupLayout(jPanel8);
        jPanel8.setLayout(jPanel8Layout);
        jPanel8Layout.setHorizontalGroup(
            jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 131, Short.MAX_VALUE)
        );
        jPanel8Layout.setVerticalGroup(
            jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 70, Short.MAX_VALUE)
        );

        javax.swing.GroupLayout jPanel6Layout = new javax.swing.GroupLayout(jPanel6);
        jPanel6.setLayout(jPanel6Layout);
        jPanel6Layout.setHorizontalGroup(
            jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel6Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel6Layout.createSequentialGroup()
                        .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(check72)
                            .addComponent(check71))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(text72, javax.swing.GroupLayout.DEFAULT_SIZE, 257, Short.MAX_VALUE)
                            .addComponent(text71)))
                    .addGroup(jPanel6Layout.createSequentialGroup()
                        .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(check4)
                            .addComponent(check1)
                            .addComponent(check55))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 133, Short.MAX_VALUE)
                        .addComponent(jPanel8, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(30, 30, 30))
        );
        jPanel6Layout.setVerticalGroup(
            jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel6Layout.createSequentialGroup()
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel6Layout.createSequentialGroup()
                        .addComponent(check4)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(check1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(check55))
                    .addComponent(jPanel8, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(check71)
                    .addComponent(text71, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(check72)
                    .addComponent(text72, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(0, 75, Short.MAX_VALUE))
        );

        jPanel7.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Payload Encoder Options", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.TOP, new java.awt.Font("Lucida Grande", 0, 14))); // NOI18N

        check8.setText("URL-Encode these characters:");

        combo2.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "URL-encode key characters", "URL-encode all characters", "URL-encode all characters (Unicode)", "HTML-encode key characters", "HTML-encode all characters", "Base64-encode" }));

        jButton6.setText("Add");
        jButton6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton6addEncoder(evt);
            }
        });

        jButton7.setText("Down");
        jButton7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton7downEncoder(evt);
            }
        });

        jButton8.setText("Up");
        jButton8.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton8upEncoder(evt);
            }
        });

        jButton9.setText("Remove");
        jButton9.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton9removeEncoder(evt);
            }
        });

        list3.setModel(encoder);
        jScrollPane4.setViewportView(list3);

        javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
        jPanel7.setLayout(jPanel7Layout);
        jPanel7Layout.setHorizontalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel7Layout.createSequentialGroup()
                        .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jButton9, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jButton6, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jButton8, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jButton7, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(12, 12, 12)
                        .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 288, Short.MAX_VALUE)
                            .addComponent(combo2, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(jPanel7Layout.createSequentialGroup()
                        .addComponent(check8)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(text5)))
                .addContainerGap(20, Short.MAX_VALUE))
        );
        jPanel7Layout.setVerticalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel7Layout.createSequentialGroup()
                        .addComponent(jButton9)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton8)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton7))
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(combo2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton6))
                .addGap(28, 28, 28)
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(check8)
                    .addComponent(text5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(20, Short.MAX_VALUE))
        );

        buttonGroup4.add(radio22);
        radio22.setText("Grep payload without encode");

        jButton1.setText("Profiles Reload");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                profilesReload(evt);
            }
        });

        jButton3.setText("New Profile");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jSeparator4, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(tab5, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
                        .addGap(12, 12, 12))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(button44)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jButton3)
                                .addGap(54, 54, 54)
                                .addComponent(jLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(combo1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jButton2)
                                .addGap(58, 58, 58)
                                .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jButton5)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(text11, javax.swing.GroupLayout.PREFERRED_SIZE, 340, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(button2, javax.swing.GroupLayout.PREFERRED_SIZE, 78, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                            .addComponent(button5, javax.swing.GroupLayout.PREFERRED_SIZE, 78, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(button3, javax.swing.GroupLayout.PREFERRED_SIZE, 78, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(button4, javax.swing.GroupLayout.PREFERRED_SIZE, 78, javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGap(12, 12, 12)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(jLabel5)
                                            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 428, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(button6, javax.swing.GroupLayout.PREFERRED_SIZE, 78, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(jPanel7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(textfield1, javax.swing.GroupLayout.PREFERRED_SIZE, 428, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                        .addComponent(jLabel12)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(text1, javax.swing.GroupLayout.PREFERRED_SIZE, 431, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(button7, javax.swing.GroupLayout.PREFERRED_SIZE, 75, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(button8)
                                    .addComponent(button9, javax.swing.GroupLayout.PREFERRED_SIZE, 75, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(button10, javax.swing.GroupLayout.PREFERRED_SIZE, 75, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(button11))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jPanel6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(textfield2, javax.swing.GroupLayout.PREFERRED_SIZE, 442, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel6)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jLabel8)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(radio1)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(radio2))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 442, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(radio22)
                                            .addComponent(radio12)
                                            .addComponent(radio3)
                                            .addComponent(radio4))))))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
        );

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {button10, button11, button7, button8, button9});

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {button2, button3, button4, button5, button6});

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {jPanel7, jScrollPane3, text1, textfield1});

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {jPanel6, jScrollPane2, textfield2});

        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(combo1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1)
                    .addComponent(jButton2)
                    .addComponent(button44)
                    .addComponent(jButton5)
                    .addComponent(text11, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton1)
                    .addComponent(jButton3))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jSeparator4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(31, 31, 31)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(60, 60, 60)
                                .addComponent(button7)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(button8)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(button9)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(button10))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel8)
                                    .addComponent(radio1)
                                    .addComponent(radio2))
                                .addGap(16, 16, 16)
                                .addComponent(jLabel6)
                                .addGap(1, 1, 1)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(radio4)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(radio3)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(radio12)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(radio22))
                                    .addComponent(jScrollPane2)))))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(25, 25, 25)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(text1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel12))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane3)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(button2)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(button3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(button4)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(button5)))))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(button6)
                            .addComponent(textfield1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(25, 25, 25)
                        .addComponent(jPanel7, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(button11)
                            .addComponent(textfield2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(25, 25, 25)
                        .addComponent(jPanel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addGap(18, 18, 18)
                .addComponent(tab5, javax.swing.GroupLayout.DEFAULT_SIZE, 235, Short.MAX_VALUE)
                .addContainerGap())
        );

        layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jScrollPane2, jScrollPane3});

        layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {textfield1, textfield2});

        layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jPanel6, jPanel7});

    }// </editor-fold>//GEN-END:initComponents

    private void selectAttack(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_selectAttack
        if ((evt.getStateChange() == java.awt.event.ItemEvent.SELECTED)) {
            String name = combo1.getItemAt(combo1.getSelectedIndex());
            setAttackValues(name);   
        }
    }//GEN-LAST:event_selectAttack

    private void setToPayload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_setToPayload
        if(!payload.isEmpty() && payload.firstElement().equals(" ")){
            payload.removeElementAt(0);
            payload.addElement(textfield1.getText());
            textfield1.setText("");
        }else{
            payload.addElement(textfield1.getText());
            textfield1.setText("");
        }
    }//GEN-LAST:event_setToPayload

    private void setToGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_setToGrep
        if(!grep.isEmpty() && grep.firstElement().equals(" ")){
            grep.removeElementAt(0);
            grep.addElement(textfield2.getText());
            textfield2.setText("");
        }else{
            grep.addElement(textfield2.getText());
            textfield2.setText("");
        }
    }//GEN-LAST:event_setToGrep

    private void removePayload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removePayload
        int selectedIndex = list1.getSelectedIndex();
        if (selectedIndex != -1) {
            payload.remove(selectedIndex);
        }
    }//GEN-LAST:event_removePayload

    private void removeGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeGrep
        int selectedIndex = list2.getSelectedIndex();
        if (selectedIndex != -1) {
            grep.remove(selectedIndex);
        }
    }//GEN-LAST:event_removeGrep

    private void removeAllPayloads(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeAllPayloads
        payload.removeAllElements();
    }//GEN-LAST:event_removeAllPayloads

    private void removeAllGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeAllGrep
        grep.removeAllElements();
    }//GEN-LAST:event_removeAllGrep
       
    private void pastePayload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pastePayload

        String element = getClipboardContents();
        String[] lines = element.split("\n");
        for(String line: lines){ 
            payload.addElement(line);
        }
    }//GEN-LAST:event_pastePayload

    private void pasteGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pasteGrep
        String element = getClipboardContents();
        String[] lines = element.split("\n");
        for(String line: lines){ 
            grep.addElement(line);
        }        
    }//GEN-LAST:event_pasteGrep

    private void loadPayloads(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadPayloads
        loadFile(payload);
        
    }//GEN-LAST:event_loadPayloads

    private void loadGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadGrep
        loadFile(grep);
    }//GEN-LAST:event_loadGrep

    private void saveAttack(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveAttack
             saveAttackValues();
             initCombo();
    }//GEN-LAST:event_saveAttack

    private void jButton6addEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton6addEncoder
        if(!encoder.isEmpty() && encoder.firstElement().equals(" ")){
            encoder.removeElementAt(0);
            encoder.addElement(combo2.getSelectedItem().toString());
        }else{
            encoder.addElement(combo2.getSelectedItem().toString());
        }

    }//GEN-LAST:event_jButton6addEncoder

    private void jButton7downEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton7downEncoder
        int selectedIndex = list3.getSelectedIndex();
        if (selectedIndex != encoder.getSize() - 1) {
            swap(selectedIndex,selectedIndex+1);
            list3.setSelectedIndex(selectedIndex+1);
            list3.ensureIndexIsVisible(selectedIndex+1);

        }
    }//GEN-LAST:event_jButton7downEncoder

    private void jButton8upEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton8upEncoder
        int selectedIndex = list3.getSelectedIndex();
        if (selectedIndex != 0) {
            swap(selectedIndex,selectedIndex-1);
            list3.setSelectedIndex(selectedIndex-1);
            list3.ensureIndexIsVisible(selectedIndex-1);

        }

    }//GEN-LAST:event_jButton8upEncoder

    private void jButton9removeEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton9removeEncoder
        int selectedIndex = list3.getSelectedIndex();
        if (selectedIndex != -1) {
            encoder.remove(selectedIndex);
        }
    }//GEN-LAST:event_jButton9removeEncoder

    private void ActionProfile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ActionProfile
        ProfilesManager ap = new ProfilesManager(this);
        int result = JOptionPane.showOptionDialog(this, ap, "Profiles Manager", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, null, null);
        if (result == JOptionPane.OK_OPTION){ 
            initCombo();
            String name = combo1.getItemAt(combo1.getSelectedIndex());
            setAttackValues(name);
        }
    }//GEN-LAST:event_ActionProfile

    private void loadConfigFile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadConfigFile
        loadConfigFile();
    }//GEN-LAST:event_loadConfigFile

    private void profilesReload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_profilesReload
        initCombo();
    }//GEN-LAST:event_profilesReload

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        clear();
    }//GEN-LAST:event_jButton3ActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton button10;
    private javax.swing.JButton button11;
    private javax.swing.JButton button2;
    private javax.swing.JButton button3;
    private javax.swing.JButton button4;
    private javax.swing.JButton button44;
    private javax.swing.JButton button5;
    private javax.swing.JButton button6;
    private javax.swing.JButton button7;
    private javax.swing.JButton button8;
    private javax.swing.JButton button9;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.ButtonGroup buttonGroup2;
    private javax.swing.ButtonGroup buttonGroup3;
    private javax.swing.ButtonGroup buttonGroup4;
    private javax.swing.ButtonGroup buttonGroup5;
    private javax.swing.ButtonGroup buttonGroup6;
    private javax.swing.JCheckBox check1;
    private javax.swing.JCheckBox check4;
    private javax.swing.JCheckBox check55;
    private javax.swing.JCheckBox check71;
    private javax.swing.JCheckBox check72;
    public javax.swing.JCheckBox check8;
    public javax.swing.JComboBox<String> combo1;
    private javax.swing.JComboBox<String> combo2;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton5;
    private javax.swing.JButton jButton6;
    private javax.swing.JButton jButton7;
    private javax.swing.JButton jButton8;
    private javax.swing.JButton jButton9;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JPanel jPanel8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane7;
    private javax.swing.JScrollPane jScrollPane8;
    private javax.swing.JScrollPane jScrollPane9;
    private javax.swing.JSeparator jSeparator4;
    private javax.swing.JList<String> list1;
    private javax.swing.JList<String> list2;
    public javax.swing.JList<String> list3;
    private javax.swing.JRadioButton radio1;
    private javax.swing.JRadioButton radio10;
    private javax.swing.JRadioButton radio11;
    private javax.swing.JRadioButton radio12;
    private javax.swing.JRadioButton radio2;
    private javax.swing.JRadioButton radio22;
    private javax.swing.JRadioButton radio3;
    private javax.swing.JRadioButton radio4;
    private javax.swing.JRadioButton radio5;
    private javax.swing.JRadioButton radio6;
    private javax.swing.JRadioButton radio7;
    private javax.swing.JRadioButton radio8;
    private javax.swing.JRadioButton radio9;
    private javax.swing.JTabbedPane tab5;
    private javax.swing.JTextField text1;
    private javax.swing.JTextField text11;
    private javax.swing.JTextField text4;
    private javax.swing.JTextField text5;
    private javax.swing.JTextField text71;
    private javax.swing.JTextField text72;
    private javax.swing.JTextArea textarea1;
    private javax.swing.JTextArea textarea2;
    private javax.swing.JTextArea textarea3;
    private javax.swing.JTextArea textarea4;
    private javax.swing.JTextField textfield1;
    private javax.swing.JTextField textfield2;
    // End of variables declaration//GEN-END:variables
} 
