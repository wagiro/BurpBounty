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
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.swing.DefaultListModel;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

public class BurpBountyGui extends javax.swing.JPanel {

    private IBurpExtenderCallbacks callbacks;
    public String filename;
    private String name;
    private String issuename;
    private String issuedetail;
    private String issuebackground;
    private String remediationdetail;
    private String remediationbackground;
    private String charstourlencode;
    private int scanner;
    private int matchtype;
    private String issueseverity;
    private String issueconfidence;
    private String responsecode;
    private String contenttype;
    private boolean negativect;
    private boolean negativerc;
    private boolean notresponse;
    private boolean casesensitive;
    private boolean excludeHTTP;
    private boolean onlyHTTP;
    private boolean urlencode;
    private boolean isresponsecode;
    private boolean iscontenttype;
    private int redirtype;
    private int maxRedir;
    private int payloadPosition;
    private String payloadsfile;
    private String grepsfile;
    private String timeOut;
    private String contentLength;
    private String author;
    private DefaultListModel tagmanager;
    private List<Headers> headers;
    private List<String> variationAttributes;
    private List<Integer> insertionPointType;
    private List<String> Tags;
    Boolean pathDiscovery;

    DefaultTableModel model;
    DefaultTableModel model1;
    DefaultTableModel model2;
    DefaultTableModel model4;
    DefaultTableModel model9;
    DefaultTableModel model10;
    DefaultTableModel modeltagmanager;
    String profiles_directory;
    BurpBountyExtension parent;

    public BurpBountyGui(BurpBountyExtension parent) {
        this.callbacks = parent.callbacks;
        this.parent = parent;
        filename = "";
        name = "";
        issuename = "";
        issuedetail = "";
        issuebackground = "";
        remediationdetail = "";
        remediationbackground = "";
        charstourlencode = "";
        scanner = 0;
        matchtype = 0;
        issueseverity = "";
        issueconfidence = "";
        responsecode = "";
        contenttype = "";
        negativect = false;
        negativerc = false;
        notresponse = false;
        casesensitive = false;
        excludeHTTP = false;
        onlyHTTP = false;
        urlencode = false;
        isresponsecode = false;
        iscontenttype = false;
        redirtype = 0;
        maxRedir = 0;
        payloadPosition = 0;
        payloadsfile = "";
        grepsfile = "";
        timeOut = "";
        contentLength = "";
        author = "";
        tagmanager = new DefaultListModel();
        model4 = new DefaultTableModel();
        model9 = new DefaultTableModel();
        model10 = new DefaultTableModel();
        modeltagmanager = new DefaultTableModel();
        headers = new ArrayList();
        variationAttributes = new ArrayList();
        insertionPointType = new ArrayList();

        if (callbacks.loadExtensionSetting("filename") != null) {
            filename = callbacks.loadExtensionSetting("filename");
            profiles_directory = filename + File.separator;
        } else {
            filename = System.getProperty("user.home");
            profiles_directory = filename + File.separator;
        }
        

        model = new DefaultTableModel() {

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                Class clazz = String.class;
                switch (columnIndex) {
                    case 0:
                        clazz = Boolean.class;
                        break;
                }
                return clazz;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };

        model1 = new DefaultTableModel() {

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                Class clazz = String.class;
                switch (columnIndex) {
                    case 0:
                        clazz = Boolean.class;
                        break;
                }
                return clazz;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };

        model2 = new DefaultTableModel() {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                Class clazz = String.class;
                switch (columnIndex) {
                    case 0:
                        clazz = Boolean.class;
                        break;
                }
                return clazz;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };

        //main
        initComponents();
        text11.setText(filename);
        makeTagsFile();
        showTags();
        showProfiles("All");
    }

    public void setActiveAttackValues(String profiles, ActiveProfile profile) {
        //Set Attack values when select from main combobox
        try {
            Gson gson = new Gson();
            JsonArray json = initJson();
            ProfilesProperties profile_property = new ProfilesProperties();

            if (json != null) {
                for (JsonElement pa : json) {
                    JsonObject bbObj = pa.getAsJsonObject();
                    if (bbObj.get("Name").getAsString().equals(profiles)) {
                        profile_property = gson.fromJson(bbObj.toString(), ProfilesProperties.class
                        );
                    }

                }
            }

            name = profile_property.getName();
            scanner = profile_property.getScanner();
            casesensitive = profile_property.getCaseSensitive();
            notresponse = profile_property.getNotResponse();
            matchtype = profile_property.getMatchType();
            issuename = profile_property.getIssueName();
            issueseverity = profile_property.getIssueSeverity();
            issueconfidence = profile_property.getIssueConfidence();
            issuedetail = profile_property.getIssueDetail();
            issuebackground = profile_property.getIssueBackground();
            remediationdetail = profile_property.getRemediationDetail();
            remediationbackground = profile_property.getRemediationBackground();
            urlencode = profile_property.getUrlEncode();
            charstourlencode = profile_property.getCharsToUrlEncode();
            iscontenttype = profile_property.getIsContentType();
            isresponsecode = profile_property.getIsResponseCode();
            contenttype = profile_property.getContentType();
            responsecode = profile_property.getResponseCode();
            excludeHTTP = profile_property.getExcludeHTTP();
            onlyHTTP = profile_property.getOnlyHTTP();
            negativect = profile_property.getNegativeCT();
            negativerc = profile_property.getNegativeRC();
            redirtype = profile_property.getRedirection();
            maxRedir = profile_property.getMaxRedir();
            payloadsfile = profile_property.getpayloadsFile();
            grepsfile = profile_property.getgrepsFile();
            payloadPosition = profile_property.getPayloadPosition();
            timeOut = profile_property.getTime();
            author = profile_property.getAuthor();
            contentLength = profile_property.getContentLength();
            headers = profile_property.getHeader();
            variationAttributes = profile_property.getVariationAttributes();
            insertionPointType = profile_property.getInsertionPointType();

            profile.textauthor.setText(author);
            profile.text1.setText(name);

            if (payloadPosition == 1) {
                buttonGroup9.setSelected(profile.replace.getModel(), true);
            } else if (payloadPosition == 2) {
                buttonGroup9.setSelected(profile.append.getModel(), true);
            }

            profile.grep.removeAllElements();
            profile.payload.removeAllElements();
            profile.encoder.removeAllElements();
            profile.tag.removeAllElements();

            profile.textpayloads.setText(payloadsfile);
            profile.textgreps.setText(grepsfile);

            profile.showGreps(profile_property.getGreps());

            if (!payloadsfile.isEmpty()) {
                loadPath(payloadsfile, profile.payload);
                updatePayloads(payloadsfile, profile_property);

            } else {
                for (String pay : profile_property.getPayloads()) {
                    profile.payload.addElement(pay);
                }
            }

            if (profile_property.getTags() != null) {
                for (String t : profile_property.getTags()) {
                    profile.tag.addElement(t);
                }
            }

            for (String enc : profile_property.getEncoder()) {
                profile.encoder.addElement(enc);
            }

            profile.text71.setText(contenttype);
            profile.text72.setText(responsecode);

            profile.check8.setSelected(urlencode);
            profile.text5.setText(charstourlencode);
            profile.excludehttp.setSelected(excludeHTTP);
            profile.onlyhttp.setSelected(onlyHTTP);

            if (timeOut.equals("0")) {
                profile.texttime.setText("");
            } else {
                profile.texttime.setText(timeOut);
            }

            if (contentLength.equals("0")) {
                profile.textcl.setText("");
            } else {
                profile.textcl.setText(contentLength);
            }

            switch (matchtype) {
                case 1:
                    buttonGroup4.setSelected(profile.radio4.getModel(), true);
                    break;
                case 2:
                    buttonGroup4.setSelected(profile.radio3.getModel(), true);
                    break;
                case 3:
                    buttonGroup4.setSelected(profile.radio12.getModel(), true);
                    break;
                case 4:
                    buttonGroup4.setSelected(profile.radio22.getModel(), true);
                    break;
                case 5:
                    buttonGroup4.setSelected(profile.radiotime.getModel(), true);
                    break;
                case 6:
                    buttonGroup4.setSelected(profile.radiocl.getModel(), true);
                    break;
                case 7:
                    buttonGroup4.setSelected(profile.variationsRadio.getModel(), true);
                    break;
                case 8:
                    buttonGroup4.setSelected(profile.invariationsRadio.getModel(), true);
                    break;
                default:
                    buttonGroup4.clearSelection();
                    break;
            }

            switch (redirtype) {
                case 1:
                    buttonGroup8.setSelected(profile.rb1.getModel(), true);
                    break;
                case 2:
                    buttonGroup8.setSelected(profile.rb2.getModel(), true);
                    break;
                case 3:
                    buttonGroup8.setSelected(profile.rb3.getModel(), true);
                    break;
                case 4:
                    buttonGroup8.setSelected(profile.rb4.getModel(), true);
                    break;
                default:
                    buttonGroup8.clearSelection();
                    break;
            }

            profile.showHeaders(headers);

            setSelectedVariations(false, profile);

            if (variationAttributes.contains("status_code")) {
                profile.status_code.setSelected(true);
            }
            if (variationAttributes.contains("input_image_labels")) {
                profile.input_image_labels.setSelected(true);
            }
            if (variationAttributes.contains("non_hidden_form_input_types")) {
                profile.non_hidden_form_input_types.setSelected(true);
            }
            if (variationAttributes.contains("page_title")) {
                profile.page_title.setSelected(true);
            }
            if (variationAttributes.contains("visible_text")) {
                profile.visible_text.setSelected(true);
            }
            if (variationAttributes.contains("button_submit_labels")) {
                profile.button_submit_labels.setSelected(true);
            }
            if (variationAttributes.contains("div_ids")) {
                profile.div_ids.setSelected(true);
            }
            if (variationAttributes.contains("word_count")) {
                profile.word_count.setSelected(true);
            }
            if (variationAttributes.contains("content_type")) {
                profile.content_type.setSelected(true);
            }
            if (variationAttributes.contains("outbound_edge_tag_names")) {
                profile.outbound_edge_tag_names.setSelected(true);
            }
            if (variationAttributes.contains("whole_body_content")) {
                profile.whole_body_content.setSelected(true);
            }
            if (variationAttributes.contains("etag_header")) {
                profile.etag_header.setSelected(true);
            }
            if (variationAttributes.contains("visible_word_count")) {
                profile.visible_word_count.setSelected(true);
            }
            if (variationAttributes.contains("content_length")) {
                profile.content_length.setSelected(true);
            }
            if (variationAttributes.contains("header_tags")) {
                profile.header_tags.setSelected(true);
            }
            if (variationAttributes.contains("tag_ids")) {
                profile.tag_ids.setSelected(true);
            }
            if (variationAttributes.contains("comments")) {
                profile.comments.setSelected(true);
            }
            if (variationAttributes.contains("line_count")) {
                profile.line_count.setSelected(true);
            }
            if (variationAttributes.contains("set_cookie_names")) {
                profile.set_cookie_names.setSelected(true);
            }
            if (variationAttributes.contains("last_modified_header")) {
                profile.last_modified_header.setSelected(true);
            }
            if (variationAttributes.contains("first_header_tag")) {
                profile.first_header_tag.setSelected(true);
            }
            if (variationAttributes.contains("tag_names")) {
                profile.tag_names.setSelected(true);
            }
            if (variationAttributes.contains("input_submit_labels")) {
                profile.input_submit_labels.setSelected(true);
            }
            if (variationAttributes.contains("outbound_edge_count")) {
                profile.outbound_edge_count.setSelected(true);
            }
            if (variationAttributes.contains("initial_body_content")) {
                profile.initial_body_content.setSelected(true);
            }
            if (variationAttributes.contains("content_location")) {
                profile.content_location.setSelected(true);
            }
            if (variationAttributes.contains("limited_body_content")) {
                profile.limited_body_content.setSelected(true);
            }
            if (variationAttributes.contains("canonical_link")) {
                profile.canonical_link.setSelected(true);
            }
            if (variationAttributes.contains("css_classes")) {
                profile.css_classes.setSelected(true);
            }
            if (variationAttributes.contains("location")) {
                profile.location.setSelected(true);
            }
            if (variationAttributes.contains("anchor_labels")) {
                profile.anchor_labels.setSelected(true);
            }

            profile.setSelectedInsertionPointType(false);

            if (insertionPointType.contains(18)) {
                profile.All.setSelected(true);
            }
            if (insertionPointType.contains(65)) {
                profile.extensionprovided.setSelected(true);
            }
            if (insertionPointType.contains(32)) {
                profile.header.setSelected(true);
            }
            if (insertionPointType.contains(36)) {
                profile.entirebody.setSelected(true);
            }
            if (insertionPointType.contains(7)) {
                profile.paramamf.setSelected(true);
            }
            if (insertionPointType.contains(1)) {
                profile.parambody.setSelected(true);
            }
            if (insertionPointType.contains(2)) {
                profile.paramcookie.setSelected(true);
            }
            if (insertionPointType.contains(6)) {
                profile.paramjson.setSelected(true);
            }
            if (insertionPointType.contains(33)) {
                profile.urlpathfolder.setSelected(true);
            }
            if (insertionPointType.contains(5)) {
                profile.parammultipartattr.setSelected(true);
            }
            if (insertionPointType.contains(35)) {
                profile.paramnamebody.setSelected(true);
            }
            if (insertionPointType.contains(34)) {
                profile.paramnameurl.setSelected(true);
            }
            if (insertionPointType.contains(64)) {
                profile.userprovided.setSelected(true);
            }
            if (insertionPointType.contains(0)) {
                profile.paramurl.setSelected(true);
            }
            if (insertionPointType.contains(3)) {
                profile.paramxml.setSelected(true);
            }
            if (insertionPointType.contains(4)) {
                profile.paramxmlattr.setSelected(true);
            }
            if (insertionPointType.contains(37)) {
                profile.urlpathfilename.setSelected(true);
            }
            if (insertionPointType.contains(127)) {
                profile.unknown.setSelected(true);
            }

            profile.check1.setSelected(casesensitive);
            profile.check4.setSelected(notresponse);
            profile.check71.setSelected(iscontenttype);
            profile.check72.setSelected(isresponsecode);
            profile.negativeCT.setSelected(negativect);
            profile.negativeRC.setSelected(negativerc);
            profile.text4.setText(issuename);
            profile.textarea1.setText(issuedetail);
            profile.textarea2.setText(issuebackground);
            profile.textarea3.setText(remediationdetail);
            profile.textarea4.setText(remediationbackground);
            text11.setText(filename);
            profile.sp1.setValue(maxRedir);

            switch (issueseverity) {
                case "High":
                    buttonGroup2.setSelected(profile.radio5.getModel(), true);
                    break;
                case "Medium":
                    buttonGroup2.setSelected(profile.radio6.getModel(), true);
                    break;
                case "Low":
                    buttonGroup2.setSelected(profile.radio7.getModel(), true);
                    break;
                case "Information":
                    buttonGroup2.setSelected(profile.radio8.getModel(), true);
                    break;
                default:
                    break;
            }

            switch (issueconfidence) {
                case "Certain":
                    buttonGroup3.setSelected(profile.radio9.getModel(), true);
                    break;
                case "Firm":
                    buttonGroup3.setSelected(profile.radio10.getModel(), true);
                    break;
                case "Tentative":
                    buttonGroup3.setSelected(profile.radio11.getModel(), true);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            callbacks.printError("BurpBountyGui line 658:" + e.getMessage());
        }
    }

    public void saveActiveAttackValues(ActiveProfile profile) {
        headers = new ArrayList();
        variationAttributes = new ArrayList();
        insertionPointType = new ArrayList();
        //Save attack with fields values
        try {
            //get GUI values
            ProfilesProperties newfile = new ProfilesProperties();

            if (profile.text1.getText().length() >= 35) {
                newfile.setName(profile.text1.getText().substring(0, 34));
            } else {
                newfile.setName(profile.text1.getText());
            }

            if (profile.textauthor.getText().length() >= 35) {
                newfile.setAuthor(profile.textauthor.getText().substring(0, 34));
            } else {
                newfile.setAuthor(profile.textauthor.getText());
            }

            newfile.setScanner(1);

            if (profile.replace.isSelected()) {
                newfile.setPayloadPosition(1);
            } else if (profile.append.isSelected()) {
                newfile.setPayloadPosition(2);
            } else {
                newfile.setPayloadPosition(1);
            }

            newfile.setEnabled(true);
            List encoders = new ArrayList();
            List payloads = new ArrayList();
            List greps = new ArrayList();
            List tags = new ArrayList();

            newfile.setPayloadsFile(profile.textpayloads.getText());
            for (int i = 0; i < profile.list1.getModel().getSize(); i++) {
                Object item = profile.list1.getModel().getElementAt(i);
                if (!item.toString().isEmpty()) {
                    payloads.add(item.toString().replaceAll("\r", "").replaceAll("\n", ""));
                }
            }
            newfile.setPayloads(payloads);

            newfile.setGrepsFile(profile.textgreps.getText());
            for (int i = 0; i < profile.modelgrep.getRowCount(); i++) {
                if (!profile.modelgrep.getValueAt(i, 2).toString().isEmpty()) {
                    greps.add(profile.modelgrep.getValueAt(i, 0).toString() + "," + profile.modelgrep.getValueAt(i, 1).toString() + "," + profile.modelgrep.getValueAt(i, 2).toString());
                }
            }
            newfile.setGreps(greps);

            for (int row = 0; row < profile.model4.getRowCount(); row++) {
                headers.add(new Headers((String) profile.model4.getValueAt(row, 0), (String) profile.model4.getValueAt(row, 1), (String) profile.model4.getValueAt(row, 2), (String) profile.model4.getValueAt(row, 3)));
            }
            newfile.setHeader(headers);

            for (int i = 0; i < profile.listtag.getModel().getSize(); i++) {
                Object item = profile.listtag.getModel().getElementAt(i);
                if (!item.toString().isEmpty()) {
                    tags.add(item.toString().replaceAll("\r", "").replaceAll("\n", ""));
                }
            }
            if (!tags.contains("All")) {
                tags.add("All");
                newfile.setTags(tags);
            } else {
                newfile.setTags(tags);
            }

            for (int i = 0; i < profile.list3.getModel().getSize(); i++) {
                Object item = profile.list3.getModel().getElementAt(i);
                if (!item.toString().isEmpty()) {
                    encoders.add(item.toString().replaceAll("\r", "").replaceAll("\n", ""));
                }
            }

            newfile.setEncoder(encoders);
            newfile.setCharsToUrlEncode(profile.text5.getText());
            newfile.setUrlEncode(profile.check8.isSelected());
            newfile.setExcludeHTTP(profile.excludehttp.isSelected());
            newfile.setOnlyHTTP(profile.onlyhttp.isSelected());
            newfile.setContentType(profile.text71.getText());
            newfile.setResponseCode(profile.text72.getText());

            if (profile.texttime.getText().isEmpty()) {
                newfile.setTime(profile.texttime.getText());
            } else {
                newfile.setTime(profile.texttime.getText());
            }

            if (profile.textcl.getText().isEmpty()) {
                newfile.setContentLength(profile.textcl.getText());
            } else {
                newfile.setContentLength(profile.textcl.getText());
            }

            if (profile.radio4.isSelected()) {
                newfile.setMatchType(1);
            } else if (profile.radio3.isSelected()) {
                newfile.setMatchType(2);
            } else if (profile.radio12.isSelected()) {
                newfile.setMatchType(3);
            } else if (profile.radio22.isSelected()) {
                newfile.setMatchType(4);
            } else if (profile.radiotime.isSelected()) {
                newfile.setMatchType(5);
            } else if (profile.radiocl.isSelected()) {
                newfile.setMatchType(6);
            } else if (profile.variationsRadio.isSelected()) {
                newfile.setMatchType(7);
            } else if (profile.invariationsRadio.isSelected()) {
                newfile.setMatchType(8);
            } else {
                newfile.setMatchType(0);
            }

            if (profile.rb1.isSelected()) {
                newfile.setRedirType(1);
            } else if (profile.rb2.isSelected()) {
                newfile.setRedirType(2);
            } else if (profile.rb3.isSelected()) {
                newfile.setRedirType(3);
            } else if (profile.rb4.isSelected()) {
                newfile.setRedirType(4);
            } else {
                newfile.setRedirType(0);
            }

            if (profile.status_code.isSelected()) {
                variationAttributes.add("status_code");
            }
            if (profile.input_image_labels.isSelected()) {
                variationAttributes.add("input_image_labels");
            }
            if (profile.non_hidden_form_input_types.isSelected()) {
                variationAttributes.add("non_hidden_form_input_types");
            }
            if (profile.page_title.isSelected()) {
                variationAttributes.add("page_title");
            }
            if (profile.visible_text.isSelected()) {
                variationAttributes.add("visible_text");
            }
            if (profile.button_submit_labels.isSelected()) {
                variationAttributes.add("button_submit_labels");
            }
            if (profile.div_ids.isSelected()) {
                variationAttributes.add("div_ids");
            }
            if (profile.word_count.isSelected()) {
                variationAttributes.add("word_count");
            }
            if (profile.content_type.isSelected()) {
                variationAttributes.add("content_type");
            }
            if (profile.outbound_edge_tag_names.isSelected()) {
                variationAttributes.add("outbound_edge_tag_names");
            }
            if (profile.whole_body_content.isSelected()) {
                variationAttributes.add("whole_body_content");
            }
            if (profile.etag_header.isSelected()) {
                variationAttributes.add("etag_header");
            }
            if (profile.visible_word_count.isSelected()) {
                variationAttributes.add("visible_word_count");
            }
            if (profile.content_length.isSelected()) {
                variationAttributes.add("content_length");
            }
            if (profile.header_tags.isSelected()) {
                variationAttributes.add("header_tags");
            }
            if (profile.tag_ids.isSelected()) {
                variationAttributes.add("tag_ids");
            }
            if (profile.comments.isSelected()) {
                variationAttributes.add("comments");
            }
            if (profile.line_count.isSelected()) {
                variationAttributes.add("line_count");
            }
            if (profile.set_cookie_names.isSelected()) {
                variationAttributes.add("set_cookie_names");
            }
            if (profile.last_modified_header.isSelected()) {
                variationAttributes.add("last_modified_header");
            }
            if (profile.first_header_tag.isSelected()) {
                variationAttributes.add("first_header_tag");
            }
            if (profile.tag_names.isSelected()) {
                variationAttributes.add("tag_names");
            }
            if (profile.input_submit_labels.isSelected()) {
                variationAttributes.add("input_submit_labels");
            }
            if (profile.outbound_edge_count.isSelected()) {
                variationAttributes.add("outbound_edge_count");
            }
            if (profile.initial_body_content.isSelected()) {
                variationAttributes.add("initial_body_content");
            }
            if (profile.content_location.isSelected()) {
                variationAttributes.add("content_location");
            }
            if (profile.limited_body_content.isSelected()) {
                variationAttributes.add("limited_body_content");
            }
            if (profile.canonical_link.isSelected()) {
                variationAttributes.add("canonical_link");
            }
            if (profile.css_classes.isSelected()) {
                variationAttributes.add("css_classes");
            }
            if (profile.location.isSelected()) {
                variationAttributes.add("location");
            }
            if (profile.anchor_labels.isSelected()) {
                variationAttributes.add("anchor_labels");
            }

            newfile.setVariationAttributes(variationAttributes);

            if (profile.All.isSelected()) {
                insertionPointType.add(18);
                insertionPointType.add(65);
                insertionPointType.add(32);
                insertionPointType.add(36);
                insertionPointType.add(7);
                insertionPointType.add(1);
                insertionPointType.add(2);
                insertionPointType.add(6);
                insertionPointType.add(33);
                insertionPointType.add(5);
                insertionPointType.add(35);
                insertionPointType.add(34);
                insertionPointType.add(64);
                insertionPointType.add(0);
                insertionPointType.add(3);
                insertionPointType.add(4);
                insertionPointType.add(37);
                insertionPointType.add(127);
            }

            if (profile.extensionprovided.isSelected()) {
                insertionPointType.add(65);
            }
            if (profile.header.isSelected()) {
                insertionPointType.add(32);
            }
            if (profile.entirebody.isSelected()) {
                insertionPointType.add(36);
            }
            if (profile.paramamf.isSelected()) {
                insertionPointType.add(7);
            }
            if (profile.parambody.isSelected()) {
                insertionPointType.add(1);
            }
            if (profile.paramcookie.isSelected()) {
                insertionPointType.add(2);
            }
            if (profile.paramjson.isSelected()) {
                insertionPointType.add(6);
            }
            if (profile.urlpathfolder.isSelected()) {
                insertionPointType.add(33);
            }
            if (profile.parammultipartattr.isSelected()) {
                insertionPointType.add(5);
            }
            if (profile.paramnamebody.isSelected()) {
                insertionPointType.add(35);
            }
            if (profile.paramnameurl.isSelected()) {
                insertionPointType.add(34);
            }
            if (profile.userprovided.isSelected()) {
                insertionPointType.add(64);
            }
            if (profile.paramurl.isSelected()) {
                insertionPointType.add(0);
            }
            if (profile.paramxml.isSelected()) {
                insertionPointType.add(3);
            }
            if (profile.paramxmlattr.isSelected()) {
                insertionPointType.add(4);
            }
            if (profile.urlpathfilename.isSelected()) {
                insertionPointType.add(37);
            }
            if (profile.unknown.isSelected()) {
                insertionPointType.add(127);
            }
            if (insertionPointType.isEmpty()) {
                insertionPointType.add(18);
                insertionPointType.add(65);
                insertionPointType.add(32);
                insertionPointType.add(36);
                insertionPointType.add(7);
                insertionPointType.add(1);
                insertionPointType.add(2);
                insertionPointType.add(6);
                insertionPointType.add(33);
                insertionPointType.add(5);
                insertionPointType.add(35);
                insertionPointType.add(34);
                insertionPointType.add(64);
                insertionPointType.add(0);
                insertionPointType.add(3);
                insertionPointType.add(4);
                insertionPointType.add(37);
                insertionPointType.add(127);
            } else {
                newfile.setInsertionPointType(insertionPointType);
            }

            newfile.setCaseSensitive(profile.check1.isSelected());
            newfile.setNotResponse(profile.check4.isSelected());
            newfile.setIsContentType(profile.check71.isSelected());
            newfile.setIsResponseCode(profile.check72.isSelected());
            newfile.setNegativeCT(profile.negativeCT.isSelected());
            newfile.setNegativeRC(profile.negativeRC.isSelected());
            newfile.setIssueName(profile.text4.getText());
            newfile.setIssueDetail(profile.textarea1.getText());
            newfile.setIssueBackground(profile.textarea2.getText());
            newfile.setRemediationDetail(profile.textarea3.getText());
            newfile.setRemediationBackground(profile.textarea4.getText());
            newfile.setMaxRedir((Integer) profile.sp1.getValue());

            if (profile.radio5.isSelected()) {
                newfile.setIssueSeverity("High");
            } else if (profile.radio6.isSelected()) {
                newfile.setIssueSeverity("Medium");
            } else if (profile.radio7.isSelected()) {
                newfile.setIssueSeverity("Low");
            } else if (profile.radio8.isSelected()) {
                newfile.setIssueSeverity("Information");
            } else {
                newfile.setIssueSeverity("");
            }

            if (profile.radio9.isSelected()) {
                newfile.setIssueConfidence("Certain");
            } else if (profile.radio10.isSelected()) {
                newfile.setIssueConfidence("Firm");
            } else if (profile.radio11.isSelected()) {
                newfile.setIssueConfidence("Tentative");
            } else {
                newfile.setIssueConfidence("");
            }

            //Save start
            Gson gson = new Gson();

            JsonArray ijson = new JsonArray();
            List<ProfilesProperties> newjson = gson.fromJson(ijson, new TypeToken<List<ProfilesProperties>>() {
            }.getType());
            newjson.add(newfile);

            String json = gson.toJson(newjson);

            //Write JSON String to file
            FileOutputStream fileStream;

            if (profile.text1.getText().length() >= 35) {
                fileStream = new FileOutputStream(new File(profiles_directory + profile.text1.getText().substring(0, 34).concat(".bb")));
            } else {
                fileStream = new FileOutputStream(new File(profiles_directory + profile.text1.getText().concat(".bb")));
            }

            OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
            writer.write(json);
            writer.close();
            fileStream.close();

        } catch (IOException e) {
            callbacks.printError("BurpBountyGui line 1027:");
        }
    }

    public void setResponseAttackValues(String profiles, ResponseProfile profile) {
        //Set Attack values when select from main combobox
        try {
            Gson gson = new Gson();
            JsonArray json = initJson();
            ProfilesProperties profile_property = new ProfilesProperties();

            if (json != null) {
                for (JsonElement pa : json) {
                    JsonObject bbObj = pa.getAsJsonObject();
                    if (bbObj.get("Name").getAsString().equals(profiles)) {
                        profile_property = gson.fromJson(bbObj.toString(), ProfilesProperties.class
                        );
                    }

                }
            }

            name = profile_property.getName();
            scanner = profile_property.getScanner();
            casesensitive = profile_property.getCaseSensitive();
            notresponse = profile_property.getNotResponse();
            matchtype = profile_property.getMatchType();
            issuename = profile_property.getIssueName();
            issueseverity = profile_property.getIssueSeverity();
            issueconfidence = profile_property.getIssueConfidence();
            issuedetail = profile_property.getIssueDetail();
            issuebackground = profile_property.getIssueBackground();
            remediationdetail = profile_property.getRemediationDetail();
            remediationbackground = profile_property.getRemediationBackground();
            iscontenttype = profile_property.getIsContentType();
            isresponsecode = profile_property.getIsResponseCode();
            contenttype = profile_property.getContentType();
            responsecode = profile_property.getResponseCode();
            excludeHTTP = profile_property.getExcludeHTTP();
            onlyHTTP = profile_property.getOnlyHTTP();
            negativect = profile_property.getNegativeCT();
            negativerc = profile_property.getNegativeRC();
            redirtype = profile_property.getRedirection();
            maxRedir = profile_property.getMaxRedir();
            payloadsfile = profile_property.getpayloadsFile();
            grepsfile = profile_property.getgrepsFile();
            payloadPosition = profile_property.getPayloadPosition();
            timeOut = profile_property.getTime();
            author = profile_property.getAuthor();
            contentLength = profile_property.getContentLength();
            headers = profile_property.getHeader();
            variationAttributes = profile_property.getVariationAttributes();
            insertionPointType = profile_property.getInsertionPointType();

            profile.textauthor.setText(author);
            profile.text1.setText(name);

            if (profile_property.getTags() != null) {
                for (String t : profile_property.getTags()) {
                    profile.tag.addElement(t);
                }
            }

            profile.showGreps(profile_property.getGreps());

            profile.text71.setText(contenttype);
            profile.text72.setText(responsecode);

            profile.excludehttp.setSelected(excludeHTTP);
            profile.onlyhttp.setSelected(onlyHTTP);

            switch (matchtype) {
                case 1:
                    buttonGroup4.setSelected(profile.radio4.getModel(), true);
                    break;
                case 2:
                    buttonGroup4.setSelected(profile.radio3.getModel(), true);
                    break;
                default:
                    buttonGroup4.clearSelection();
                    break;
            }

            switch (redirtype) {
                case 1:
                    buttonGroup8.setSelected(profile.rb1.getModel(), true);
                    break;
                case 2:
                    buttonGroup8.setSelected(profile.rb2.getModel(), true);
                    break;
                case 3:
                    buttonGroup8.setSelected(profile.rb3.getModel(), true);
                    break;
                case 4:
                    buttonGroup8.setSelected(profile.rb4.getModel(), true);
                    break;
                default:
                    buttonGroup8.clearSelection();
                    break;
            }

            profile.check1.setSelected(casesensitive);
            profile.check4.setSelected(notresponse);
            profile.check71.setSelected(iscontenttype);
            profile.check72.setSelected(isresponsecode);
            profile.negativeCT.setSelected(negativect);
            profile.negativeRC.setSelected(negativerc);
            profile.text4.setText(issuename);
            profile.textarea1.setText(issuedetail);
            profile.textarea2.setText(issuebackground);
            profile.textarea3.setText(remediationdetail);
            profile.textarea4.setText(remediationbackground);
            text11.setText(filename);
            profile.sp1.setValue(maxRedir);

            switch (issueseverity) {
                case "High":
                    buttonGroup2.setSelected(profile.radio5.getModel(), true);
                    break;
                case "Medium":
                    buttonGroup2.setSelected(profile.radio6.getModel(), true);
                    break;
                case "Low":
                    buttonGroup2.setSelected(profile.radio7.getModel(), true);
                    break;
                case "Information":
                    buttonGroup2.setSelected(profile.radio8.getModel(), true);
                    break;
                default:
                    break;
            }

            switch (issueconfidence) {
                case "Certain":
                    buttonGroup3.setSelected(profile.radio9.getModel(), true);
                    break;
                case "Firm":
                    buttonGroup3.setSelected(profile.radio10.getModel(), true);
                    break;
                case "Tentative":
                    buttonGroup3.setSelected(profile.radio11.getModel(), true);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            callbacks.printError("BurpBountyGui line 1180:" + e.getMessage());
        }
    }

    public void saveResponseAttackValues(ResponseProfile profile) {
        variationAttributes = new ArrayList();
        insertionPointType = new ArrayList();
        //Save attack with fields values
        try {
            //get GUI values
            ProfilesProperties newfile = new ProfilesProperties();

            if (profile.text1.getText().length() >= 35) {
                newfile.setName(profile.text1.getText().substring(0, 34));
            } else {
                newfile.setName(profile.text1.getText());
            }

            if (profile.textauthor.getText().length() >= 35) {
                newfile.setAuthor(profile.textauthor.getText().substring(0, 34));
            } else {
                newfile.setAuthor(profile.textauthor.getText());
            }

            newfile.setScanner(2);

            newfile.setEnabled(true);
            List greps = new ArrayList();
            List tags = new ArrayList();

            newfile.setGrepsFile(profile.textgreps.getText());
            String a = profile.textgreps.getText();
            for (int i = 0; i < profile.modelgrep.getRowCount(); i++) {
                if (!profile.modelgrep.getValueAt(i, 2).toString().isEmpty()) {
                    greps.add(profile.modelgrep.getValueAt(i, 0).toString() + "," + profile.modelgrep.getValueAt(i, 1).toString() + "," + profile.modelgrep.getValueAt(i, 2).toString());
                }
            }
            newfile.setGreps(greps);

            for (int i = 0; i < profile.listtag.getModel().getSize(); i++) {
                Object item = profile.listtag.getModel().getElementAt(i);
                if (!item.toString().isEmpty()) {
                    tags.add(item.toString().replaceAll("\r", "").replaceAll("\n", ""));
                }
            }
            if (!tags.contains("All")) {
                tags.add("All");
                newfile.setTags(tags);
            } else {
                newfile.setTags(tags);
            }

            if (profile.radio4.isSelected()) {
                newfile.setMatchType(1);
            } else if (profile.radio3.isSelected()) {
                newfile.setMatchType(2);
            } else {
                newfile.setMatchType(0);
            }

            newfile.setExcludeHTTP(profile.excludehttp.isSelected());
            newfile.setOnlyHTTP(profile.onlyhttp.isSelected());
            newfile.setContentType(profile.text71.getText());
            newfile.setResponseCode(profile.text72.getText());

            if (profile.rb1.isSelected()) {
                newfile.setRedirType(1);
            } else if (profile.rb2.isSelected()) {
                newfile.setRedirType(2);
            } else if (profile.rb3.isSelected()) {
                newfile.setRedirType(3);
            } else if (profile.rb4.isSelected()) {
                newfile.setRedirType(4);
            } else {
                newfile.setRedirType(0);
            }

            newfile.setVariationAttributes(variationAttributes);

            newfile.setInsertionPointType(insertionPointType);

            newfile.setCaseSensitive(profile.check1.isSelected());
            newfile.setNotResponse(profile.check4.isSelected());
            newfile.setIsContentType(profile.check71.isSelected());
            newfile.setIsResponseCode(profile.check72.isSelected());
            newfile.setNegativeCT(profile.negativeCT.isSelected());
            newfile.setNegativeRC(profile.negativeRC.isSelected());
            newfile.setIssueName(profile.text4.getText());
            newfile.setIssueDetail(profile.textarea1.getText());
            newfile.setIssueBackground(profile.textarea2.getText());
            newfile.setRemediationDetail(profile.textarea3.getText());
            newfile.setRemediationBackground(profile.textarea4.getText());
            newfile.setMaxRedir((Integer) profile.sp1.getValue());

            if (profile.radio5.isSelected()) {
                newfile.setIssueSeverity("High");
            } else if (profile.radio6.isSelected()) {
                newfile.setIssueSeverity("Medium");
            } else if (profile.radio7.isSelected()) {
                newfile.setIssueSeverity("Low");
            } else if (profile.radio8.isSelected()) {
                newfile.setIssueSeverity("Information");
            } else {
                newfile.setIssueSeverity("");
            }

            if (profile.radio9.isSelected()) {
                newfile.setIssueConfidence("Certain");
            } else if (profile.radio10.isSelected()) {
                newfile.setIssueConfidence("Firm");
            } else if (profile.radio11.isSelected()) {
                newfile.setIssueConfidence("Tentative");
            } else {
                newfile.setIssueConfidence("");
            }

            //Save start
            Gson gson = new Gson();

            JsonArray ijson = new JsonArray();
            List<ProfilesProperties> newjson = gson.fromJson(ijson, new TypeToken<List<ProfilesProperties>>() {
            }.getType());
            newjson.add(newfile);

            String json = gson.toJson(newjson);

            //Write JSON String to file
            FileOutputStream fileStream;

            if (profile.text1.getText().length() >= 35) {
                fileStream = new FileOutputStream(new File(profiles_directory + profile.text1.getText().substring(0, 34).concat(".bb")));
            } else {
                fileStream = new FileOutputStream(new File(profiles_directory + profile.text1.getText().concat(".bb")));
            }

            OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
            writer.write(json);
            writer.close();
            fileStream.close();

        } catch (IOException e) {
            callbacks.printError("BurpBountyGui line 1323:");
        }
    }

    public void setRequestAttackValues(String profiles, RequestProfile profile) {
        //Set Attack values when select from main combobox
        try {
            Gson gson = new Gson();
            JsonArray json = initJson();
            ProfilesProperties profile_property = new ProfilesProperties();

            if (json != null) {
                for (JsonElement pa : json) {
                    JsonObject bbObj = pa.getAsJsonObject();
                    if (bbObj.get("Name").getAsString().equals(profiles)) {
                        profile_property = gson.fromJson(bbObj.toString(), ProfilesProperties.class
                        );
                    }

                }
            }

            name = profile_property.getName();
            scanner = profile_property.getScanner();
            casesensitive = profile_property.getCaseSensitive();
            notresponse = profile_property.getNotResponse();
            matchtype = profile_property.getMatchType();
            issuename = profile_property.getIssueName();
            issueseverity = profile_property.getIssueSeverity();
            issueconfidence = profile_property.getIssueConfidence();
            issuedetail = profile_property.getIssueDetail();
            issuebackground = profile_property.getIssueBackground();
            remediationdetail = profile_property.getRemediationDetail();
            remediationbackground = profile_property.getRemediationBackground();
            iscontenttype = profile_property.getIsContentType();
            isresponsecode = profile_property.getIsResponseCode();
            contenttype = profile_property.getContentType();
            responsecode = profile_property.getResponseCode();
            excludeHTTP = profile_property.getExcludeHTTP();
            onlyHTTP = profile_property.getOnlyHTTP();
            negativect = profile_property.getNegativeCT();
            negativerc = profile_property.getNegativeRC();
            redirtype = profile_property.getRedirection();
            maxRedir = profile_property.getMaxRedir();
            payloadsfile = profile_property.getpayloadsFile();
            grepsfile = profile_property.getgrepsFile();
            payloadPosition = profile_property.getPayloadPosition();
            timeOut = profile_property.getTime();
            author = profile_property.getAuthor();
            contentLength = profile_property.getContentLength();
            headers = profile_property.getHeader();
            variationAttributes = profile_property.getVariationAttributes();
            insertionPointType = profile_property.getInsertionPointType();

            profile.textauthor.setText(author);
            profile.text1.setText(name);

            profile.grep.removeAllElements();
            profile.tag.removeAllElements();

            profile.textgreps.setText(grepsfile);

            profile.showGreps(profile_property.getGreps());

            if (profile_property.getTags() != null) {
                for (String t : profile_property.getTags()) {
                    profile.tag.addElement(t);
                }
            }

            switch (matchtype) {
                case 1:
                    buttonGroup4.setSelected(profile.radio4.getModel(), true);
                    break;
                case 2:
                    buttonGroup4.setSelected(profile.radio3.getModel(), true);
                    break;
                default:
                    buttonGroup4.clearSelection();
                    break;
            }

            profile.check1.setSelected(casesensitive);
            profile.check4.setSelected(notresponse);
            profile.text4.setText(issuename);
            profile.textarea1.setText(issuedetail);
            profile.textarea2.setText(issuebackground);
            profile.textarea3.setText(remediationdetail);
            profile.textarea4.setText(remediationbackground);
            text11.setText(filename);

            switch (issueseverity) {
                case "High":
                    buttonGroup2.setSelected(profile.radio5.getModel(), true);
                    break;
                case "Medium":
                    buttonGroup2.setSelected(profile.radio6.getModel(), true);
                    break;
                case "Low":
                    buttonGroup2.setSelected(profile.radio7.getModel(), true);
                    break;
                case "Information":
                    buttonGroup2.setSelected(profile.radio8.getModel(), true);
                    break;
                default:
                    break;
            }

            switch (issueconfidence) {
                case "Certain":
                    buttonGroup3.setSelected(profile.radio9.getModel(), true);
                    break;
                case "Firm":
                    buttonGroup3.setSelected(profile.radio10.getModel(), true);
                    break;
                case "Tentative":
                    buttonGroup3.setSelected(profile.radio11.getModel(), true);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            callbacks.printError("BurpBountyGui line 1823:" + e.getMessage());
        }
    }

    public void saveRequestAttackValues(RequestProfile profile) {
        variationAttributes = new ArrayList();
        insertionPointType = new ArrayList();
        //Save attack with fields values
        try {
            //get GUI values
            ProfilesProperties newfile = new ProfilesProperties();

            if (profile.text1.getText().length() >= 35) {
                newfile.setName(profile.text1.getText().substring(0, 34));
            } else {
                newfile.setName(profile.text1.getText());
            }

            if (profile.textauthor.getText().length() >= 35) {
                newfile.setAuthor(profile.textauthor.getText().substring(0, 34));
            } else {
                newfile.setAuthor(profile.textauthor.getText());
            }

            newfile.setScanner(3);

            newfile.setEnabled(true);
            List greps = new ArrayList();
            List tags = new ArrayList();

            newfile.setGrepsFile(profile.textgreps.getText());

            for (int i = 0; i < profile.modelgrep.getRowCount(); i++) {
                if (!profile.modelgrep.getValueAt(i, 3).toString().isEmpty()) {
                    greps.add(profile.modelgrep.getValueAt(i, 0).toString() + "," + profile.modelgrep.getValueAt(i, 1).toString() + "," + profile.modelgrep.getValueAt(i, 2).toString() + "," + profile.modelgrep.getValueAt(i, 3).toString() + "," + profile.modelgrep.getValueAt(i, 4).toString());
                }
            }
            newfile.setGreps(greps);

            for (int i = 0; i < profile.listtag.getModel().getSize(); i++) {
                Object item = profile.listtag.getModel().getElementAt(i);
                if (!item.toString().isEmpty()) {
                    tags.add(item.toString().replaceAll("\r", "").replaceAll("\n", ""));
                }
            }
            if (!tags.contains("All")) {
                tags.add("All");
                newfile.setTags(tags);
            } else {
                newfile.setTags(tags);
            }

            if (profile.radio4.isSelected()) {
                newfile.setMatchType(1);
            } else if (profile.radio3.isSelected()) {
                newfile.setMatchType(2);
            } else {
                newfile.setMatchType(0);
            }

            newfile.setVariationAttributes(variationAttributes);

            newfile.setCaseSensitive(profile.check1.isSelected());
            newfile.setNotResponse(profile.check4.isSelected());
            newfile.setIssueName(profile.text4.getText());
            newfile.setIssueDetail(profile.textarea1.getText());
            newfile.setIssueBackground(profile.textarea2.getText());
            newfile.setRemediationDetail(profile.textarea3.getText());
            newfile.setRemediationBackground(profile.textarea4.getText());

            if (profile.radio5.isSelected()) {
                newfile.setIssueSeverity("High");
            } else if (profile.radio6.isSelected()) {
                newfile.setIssueSeverity("Medium");
            } else if (profile.radio7.isSelected()) {
                newfile.setIssueSeverity("Low");
            } else if (profile.radio8.isSelected()) {
                newfile.setIssueSeverity("Information");
            } else {
                newfile.setIssueSeverity("");
            }

            if (profile.radio9.isSelected()) {
                newfile.setIssueConfidence("Certain");
            } else if (profile.radio10.isSelected()) {
                newfile.setIssueConfidence("Firm");
            } else if (profile.radio11.isSelected()) {
                newfile.setIssueConfidence("Tentative");
            } else {
                newfile.setIssueConfidence("");
            }

            //Save start
            Gson gson = new Gson();

            JsonArray ijson = new JsonArray();
            List<ProfilesProperties> newjson = gson.fromJson(ijson, new TypeToken<List<ProfilesProperties>>() {
            }.getType());
            newjson.add(newfile);

            String json = gson.toJson(newjson);

            //Write JSON String to file
            FileOutputStream fileStream;

            if (profile.text1.getText().length() >= 35) {
                fileStream = new FileOutputStream(new File(profiles_directory + profile.text1.getText().substring(0, 34).concat(".bb")));
            } else {
                fileStream = new FileOutputStream(new File(profiles_directory + profile.text1.getText().concat(".bb")));
            }

            OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
            writer.write(json);
            writer.close();
            fileStream.close();

        } catch (IOException e) {
            callbacks.printError("BurpBountyGui line 1571:");
        }
    }

    public void setSelectedVariations(boolean state, ActiveProfile profile) {
        profile.status_code.setSelected(state);
        profile.input_image_labels.setSelected(state);
        profile.non_hidden_form_input_types.setSelected(state);
        profile.page_title.setSelected(state);
        profile.visible_text.setSelected(state);
        profile.button_submit_labels.setSelected(state);
        profile.div_ids.setSelected(state);
        profile.word_count.setSelected(state);
        profile.content_type.setSelected(state);
        profile.outbound_edge_tag_names.setSelected(state);
        profile.whole_body_content.setSelected(state);
        profile.etag_header.setSelected(state);
        profile.visible_word_count.setSelected(state);
        profile.content_length.setSelected(state);
        profile.header_tags.setSelected(state);
        profile.tag_ids.setSelected(state);
        profile.comments.setSelected(state);
        profile.line_count.setSelected(state);
        profile.set_cookie_names.setSelected(state);
        profile.last_modified_header.setSelected(state);
        profile.first_header_tag.setSelected(state);
        profile.tag_names.setSelected(state);
        profile.input_submit_labels.setSelected(state);
        profile.outbound_edge_count.setSelected(state);
        profile.initial_body_content.setSelected(state);
        profile.content_location.setSelected(state);
        profile.limited_body_content.setSelected(state);
        profile.canonical_link.setSelected(state);
        profile.css_classes.setSelected(state);
        profile.location.setSelected(state);
        profile.anchor_labels.setSelected(state);
    }

    public void updatePayloads(String file, ProfilesProperties issue) {

        //Load file for implement payloads
        List payloads = new ArrayList();
        String line;
        File fileload = new File(file);

        try {
            BufferedReader bufferreader = new BufferedReader(new FileReader(fileload.getAbsolutePath()));
            line = bufferreader.readLine();

            while (line != null) {
                payloads.add(line);
                line = bufferreader.readLine();
            }
            bufferreader.close();

            issue.setPayloads(payloads);

            Gson gson = new Gson();
            String strJson = gson.toJson(issue);
            FileWriter writer = null;

            writer = new FileWriter(profiles_directory + issue.getName().concat(".bb"));
            writer.write("[" + strJson + "]");

            writer.close();
        } catch (FileNotFoundException ex) {
            callbacks.printError("BurpBountyGui line 1639:");
        } catch (IOException ex) {
            callbacks.printError("BurpBountyGui line 1042:");
        }
    }

    public void updateGreps(String file, ProfilesProperties issue) {

        //Load file for implement payloads
        List greps = new ArrayList();
        String line;
        File fileload = new File(file);

        try {
            BufferedReader bufferreader = new BufferedReader(new FileReader(fileload.getAbsolutePath()));
            line = bufferreader.readLine();

            while (line != null) {
                greps.add(line);
                line = bufferreader.readLine();
            }
            bufferreader.close();

            issue.setGreps(greps);

            Gson gson = new Gson();
            String strJson = gson.toJson(issue);
            FileWriter writer = null;

            writer = new FileWriter(profiles_directory + issue.getName().concat(".bb"));
            writer.write("[" + strJson + "]");

            writer.close();
        } catch (FileNotFoundException ex) {
            callbacks.printError("BurpBountyGui line 1675:" + ex.getMessage());
        } catch (IOException ex) {
            callbacks.printError("BurpBountyGui line 1078:" + ex.getMessage());
        }
    }

  

    private List<String> readFile(String filename) {
        List<String> records = new ArrayList();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filename));
            String line;
            while ((line = reader.readLine()) != null) {
                records.add(line);
            }
            reader.close();
        } catch (Exception e) {
            System.out.println("BurpBountyGui line 1882:" + e.getMessage());
        }
        return records;
    }

    public JsonArray initJson() {
        //Init json form filename
        FileReader fr;

        try {
            JsonArray data = new JsonArray();
            File f = new File(profiles_directory);
            if (f.exists() && f.isDirectory()) {
                for (File file : f.listFiles()) {
                    if (file.getName().endsWith(".bb")) {
                        fr = new FileReader(file.getAbsolutePath());
                        JsonReader json = new JsonReader((fr));
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());
                        fr.close();
                        json.close();
                    }

                }
            }
            return data;
        } catch (Exception e) {
            callbacks.printError("BurpBountyGui line 1823:" + e.getMessage());
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
                result = (String) contents.getTransferData(DataFlavor.stringFlavor);
            } catch (UnsupportedFlavorException | IOException ex) {
                callbacks.printError("BurpBountyGui line 1866:" + ex.getMessage());
            }
        }
        return result;
    }

    public void loadConfigFile() {
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Specify a base directory to load");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        int userSelection = fileChooser.showOpenDialog(parentFrame);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileload = fileChooser.getSelectedFile();
            profiles_directory = fileload.toString() + File.separator;
            String file = fileload.getAbsolutePath() + File.separator;

            text11.setText(file);

            makeTagsFile();
            showTags();
            showProfiles("All");
            this.callbacks.saveExtensionSetting("filename", file);

        }
    }

    public void loadPath(String file, DefaultListModel list) {
        //Load file for implement payloads
        DefaultListModel List = list;
        String line;
        File fileload = new File(file);

        try {
            BufferedReader bufferreader = new BufferedReader(new FileReader(fileload.getAbsolutePath()));
            line = bufferreader.readLine();

            while (line != null) {
                List.addElement(line);
                line = bufferreader.readLine();
            }
            bufferreader.close();
        } catch (FileNotFoundException ex) {
            callbacks.printError("BurpBountyGui line 1912:" + ex.getMessage());
        } catch (IOException ex) {
            callbacks.printError("BurpBountyGui line 1815:" + ex.getMessage());
        }
    }

    public void setEnableDisableProfile(String enable, JTable table) {

        Gson gson = new Gson();

        JsonArray json2 = new JsonArray();
        List<ProfilesProperties> newjson = gson.fromJson(json2, new TypeToken<List<ProfilesProperties>>() {
        }.getType());

        int[] rows = table.getSelectedRows();

        for (Integer row : rows) {
            try {
                String profile_name = table.getValueAt(row, 1).toString();
                JsonArray data = new JsonArray();
                JsonReader json = new JsonReader(new FileReader(profiles_directory.concat(profile_name.concat(".bb"))));
                JsonParser parser = new JsonParser();
                data.addAll(parser.parse(json).getAsJsonArray());

                Object idata = data.get(0);
                ProfilesProperties profile_properties = gson.fromJson(idata.toString(), ProfilesProperties.class
                );

                if (enable.contains("Yes")) {
                    profile_properties.setEnabled(true);
                } else {
                    profile_properties.setEnabled(false);
                }
                newjson.clear();
                newjson.add(profile_properties);
                FileOutputStream fileStream = new FileOutputStream(profiles_directory.concat(profile_name.concat(".bb")));
                String fjson = gson.toJson(newjson);
                OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
                writer.write(fjson);
                writer.close();
                json.close();

            } catch (IOException e) {
                callbacks.printError("BurpBountyGui line 1956:" + e.getMessage());
            }
        }
        showProfiles("All");
    }

    public void setEnableDisableAllProfiles(String enable) {

        Gson gson = new Gson();
        File f = new File(profiles_directory);

        JsonArray json2 = new JsonArray();
        List<ProfilesProperties> newjson = gson.fromJson(json2, new TypeToken<List<ProfilesProperties>>() {
        }.getType());

        File[] files = f.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                if (name.toLowerCase().endsWith(".bb")) {
                    return true;
                } else {
                    return false;
                }
            }
        });

        if (f.exists() && f.isDirectory()) {
            for (File file : files) {
                try {
                    JsonArray data = new JsonArray();
                    JsonReader json = new JsonReader(new FileReader(file.getAbsolutePath()));
                    JsonParser parser = new JsonParser();
                    data.addAll(parser.parse(json).getAsJsonArray());

                    Object idata = data.get(0);
                    ProfilesProperties profile_properties = gson.fromJson(idata.toString(), ProfilesProperties.class
                    );
                    if (enable.contains("Yes")) {
                        profile_properties.setEnabled(true);
                    } else {
                        profile_properties.setEnabled(false);
                    }
                    newjson.clear();
                    newjson.add(profile_properties);
                    FileOutputStream fileStream = new FileOutputStream(file.getAbsoluteFile());
                    String fjson = gson.toJson(newjson);
                    OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
                    writer.write(fjson);
                    writer.close();
                    json.close();
                } catch (IOException e) {
                    callbacks.printError("BurpBountyGui line 207:" + e.getMessage());
                }
            }
        }
        showProfiles("All");
    }

    public void deleteTagProfiles(String tag) {

        Gson gson = new Gson();
        File f = new File(profiles_directory);

        JsonArray json2 = new JsonArray();
        List<ProfilesProperties> newjson = gson.fromJson(json2, new TypeToken<List<ProfilesProperties>>() {
        }.getType());

        File[] files = f.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                if (name.toLowerCase().endsWith(".bb")) {
                    return true;
                } else {
                    return false;
                }
            }
        });

        if (f.exists() && f.isDirectory()) {
            for (File file : files) {
                try {
                    JsonArray data = new JsonArray();
                    JsonReader json = new JsonReader(new FileReader(file.getAbsolutePath()));
                    JsonParser parser = new JsonParser();
                    data.addAll(parser.parse(json).getAsJsonArray());

                    Object idata = data.get(0);
                    ProfilesProperties profile_properties = gson.fromJson(idata.toString(), ProfilesProperties.class
                    );
                    List<String> tags = profile_properties.getTags();
                    List<String> finaltags = new ArrayList();
                    if (tags != null) {
                        for (String dtag : tags) {
                            if (!dtag.equals(tag)) {
                                finaltags.add(dtag);
                            }
                        }
                    }
                    profile_properties.setTags(finaltags);
                    newjson.clear();
                    newjson.add(profile_properties);
                    FileOutputStream fileStream = new FileOutputStream(file.getAbsoluteFile());
                    String fjson = gson.toJson(newjson);
                    OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
                    writer.write(fjson);
                    writer.close();
                    json.close();
                } catch (IOException e) {
                    callbacks.printError("BurpBountyGui line 2065:" + e.getMessage());
                }
            }
        }
        showProfiles("All");
    }

    public void makeTagsFile() {

        Gson gson = new Gson();
        File f = new File(profiles_directory);

        File[] files = f.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                if (name.toLowerCase().endsWith(".bb")) {
                    return true;
                } else {
                    return false;
                }
            }
        });

        List<String> tags = new ArrayList();
        if (f.exists() && f.isDirectory()) {
            for (File file : files) {
                try {
                    JsonArray data = new JsonArray();
                    JsonReader json = new JsonReader(new FileReader(file.getAbsolutePath()));
                    JsonParser parser = new JsonParser();
                    data.addAll(parser.parse(json).getAsJsonArray());

                    Object idata = data.get(0);
                    ProfilesProperties profile_properties = gson.fromJson(idata.toString(), ProfilesProperties.class
                    );
                    if (profile_properties.getTags() != null) {
                        tags.addAll(profile_properties.getTags());
                    }
                    json.close();
                } catch (IOException e) {
                    System.out.println("BurpBountyGui line 2107:" + e.getMessage());
                }

            }

            Set<String> singles = new TreeSet<>();
            Set<String> multiples = new TreeSet<>();

            for (String x : tags) {
                if (!multiples.contains(x)) {
                    if (singles.contains(x)) {
                        singles.remove(x);
                        multiples.add(x);
                    } else {
                        singles.add(x);
                    }
                }
            }

            tags.clear();
            tags.addAll(singles);
            tags.addAll(multiples);
            File file = new File(profiles_directory + File.separator + "tags.txt");
            if (!file.exists()) {
                file.getParentFile().mkdirs();
            }

            List<String> existenttags = readFile(profiles_directory + File.separator + "tags.txt");
            for (String tag : tags) {
                if (!existenttags.contains(tag)) {
                    addNewTag(tag);

                }
            }
        } else {
            System.out.println("Profile directory don't exist");
        }
    }

    public class profilesModelListener implements TableModelListener {

        @Override
        public void tableChanged(TableModelEvent e) {
            int row = e.getFirstRow();
            int column = e.getColumn();
            TableModel model = (TableModel) e.getSource();

            if (column == 0) {
                Boolean checked = (Boolean) model.getValueAt(row, column);

                if (checked) {
                    try {
                        Gson gson = new Gson();
                        JsonArray json2 = new JsonArray();
                        List<ProfilesProperties> newjson = gson.fromJson(json2, new TypeToken<List<ProfilesProperties>>() {
                        }.getType());

                        String profile_name = model.getValueAt(row, 1).toString();

                        JsonArray data = new JsonArray();
                        JsonReader json = new JsonReader(new FileReader(profiles_directory.concat(profile_name.concat(".bb"))));
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());

                        Object idata = data.get(0);
                        ProfilesProperties profile_properties = gson.fromJson(idata.toString(), ProfilesProperties.class
                        );

                        profile_properties.setEnabled(true);

                        newjson.clear();
                        newjson.add(profile_properties);
                        FileOutputStream fileStream = new FileOutputStream(profiles_directory.concat(profile_name.concat(".bb")));
                        String fjson = gson.toJson(newjson);
                        OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
                        writer.write(fjson);
                        writer.close();
                        json.close();

                    } catch (IOException ex) {
                        callbacks.printError("BurpBountyGui line 1956:" + ex.getMessage());
                    }
                } else {
                    try {
                        Gson gson = new Gson();
                        JsonArray json2 = new JsonArray();
                        List<ProfilesProperties> newjson = gson.fromJson(json2, new TypeToken<List<ProfilesProperties>>() {
                        }.getType());
                        String profile_name = model.getValueAt(row, 1).toString();
                        JsonArray data = new JsonArray();
                        JsonReader json = new JsonReader(new FileReader(profiles_directory.concat(profile_name.concat(".bb"))));
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());

                        Object idata = data.get(0);
                        ProfilesProperties profile_properties = gson.fromJson(idata.toString(), ProfilesProperties.class
                        );

                        profile_properties.setEnabled(false);

                        newjson.clear();
                        newjson.add(profile_properties);
                        FileOutputStream fileStream = new FileOutputStream(profiles_directory.concat(profile_name.concat(".bb")));
                        String fjson = gson.toJson(newjson);
                        OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
                        writer.write(fjson);
                        writer.close();
                        json.close();

                    } catch (IOException ex) {
                        callbacks.printError("BurpBountyGui line 1956:" + ex.getMessage());
                    }
                }
            }

        }
    }

    public void showProfiles(String Tag) {
        JsonArray json = initJson();
        Gson gson = new Gson();
        ProfilesProperties profile_property;
        //model for active profiles
        model.setNumRows(0);
        model.setColumnCount(0);
        model.addColumn("Enabled");
        model.addColumn("Profile Name");
        model.addColumn("Author's Twitter");

        table3.getColumnModel().getColumn(0).setPreferredWidth(75);
        table3.getColumnModel().getColumn(0).setMaxWidth(75);
        table3.getColumnModel().getColumn(2).setPreferredWidth(150);
        table3.getColumnModel().getColumn(2).setMaxWidth(150);
        table3.getColumnModel().getColumn(1).setPreferredWidth(850);

        TableRowSorter<TableModel> sorter = new TableRowSorter<>(table3.getModel());
        table3.setRowSorter(sorter);
        table3.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table3.getModel().addTableModelListener(new profilesModelListener());

        //model for passive response
        model1.setNumRows(0);
        model1.setColumnCount(0);
        model1.addColumn("Enabled");
        model1.addColumn("Profile Name");
        model1.addColumn("Author's Twitter");

        table1.getColumnModel().getColumn(0).setPreferredWidth(75);
        table1.getColumnModel().getColumn(0).setMaxWidth(75);
        table1.getColumnModel().getColumn(2).setPreferredWidth(150);
        table1.getColumnModel().getColumn(2).setMaxWidth(150);
        table1.getColumnModel().getColumn(1).setPreferredWidth(850);

        TableRowSorter<TableModel> sorter1 = new TableRowSorter<>(table1.getModel());
        table1.setRowSorter(sorter1);
        table1.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table1.getModel().addTableModelListener(new profilesModelListener());

        //model for passive request
        model2.setNumRows(0);
        model2.setColumnCount(0);
        model2.addColumn("Enabled");
        model2.addColumn("Profile Name");
        model2.addColumn("Author's Twitter");

        table2.getColumnModel().getColumn(0).setPreferredWidth(75);
        table2.getColumnModel().getColumn(0).setMaxWidth(75);
        table2.getColumnModel().getColumn(2).setPreferredWidth(150);
        table2.getColumnModel().getColumn(2).setMaxWidth(150);
        table2.getColumnModel().getColumn(1).setPreferredWidth(850);

        TableRowSorter<TableModel> sorter2 = new TableRowSorter<>(table2.getModel());
        table2.setRowSorter(sorter2);
        table2.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table2.getModel().addTableModelListener(new profilesModelListener());

        if (json != null) {
            for (JsonElement pa : json) {
                JsonObject bbObj = pa.getAsJsonObject();
                profile_property = gson.fromJson(bbObj.toString(), ProfilesProperties.class
                );

                if (Tag.equals("All")) {
                    if (profile_property.getScanner() == 1) {
                        model.addRow(new Object[]{profile_property.getEnabled(), profile_property.getName(), profile_property.getAuthor()});
                    } else if (profile_property.getScanner() == 2) {
                        model2.addRow(new Object[]{profile_property.getEnabled(), profile_property.getName(), profile_property.getAuthor()});
                    } else if (profile_property.getScanner() == 3) {
                        model1.addRow(new Object[]{profile_property.getEnabled(), profile_property.getName(), profile_property.getAuthor()});

                    }

                } else {

                    try {
                        for (String tag : profile_property.getTags()) {
                            if (tag.equals(Tag) || Tag.isEmpty() || Tag.equals("All")) {
                                if (profile_property.getScanner() == 1) {
                                    model.addRow(new Object[]{profile_property.getEnabled(), profile_property.getName(), profile_property.getAuthor()});
                                } else if (profile_property.getScanner() == 2) {
                                    model2.addRow(new Object[]{profile_property.getEnabled(), profile_property.getName(), profile_property.getAuthor()});
                                } else if (profile_property.getScanner() == 3) {
                                    model1.addRow(new Object[]{profile_property.getEnabled(), profile_property.getName(), profile_property.getAuthor()});

                                }

                            }
                        }
                    } catch (NullPointerException e) {
                        if (profile_property.getScanner() == 1) {
                            model.addRow(new Object[]{profile_property.getEnabled(), profile_property.getName(), profile_property.getAuthor()});
                        } else if (profile_property.getScanner() == 2) {
                            model2.addRow(new Object[]{profile_property.getEnabled(), profile_property.getName(), profile_property.getAuthor()});
                        } else if (profile_property.getScanner() == 3) {
                            model1.addRow(new Object[]{profile_property.getEnabled(), profile_property.getName(), profile_property.getAuthor()});

                        }

                    }
                }
            }
        }
    }

    public void deleteProfile(JTable table) {

        Gson gson = new Gson();
        File f = new File(profiles_directory);

        File[] files = f.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                if (name.toLowerCase().endsWith(".bb")) {
                    return true;
                } else {
                    return false;
                }
            }
        });

        int[] rows = table.getSelectedRows();
        if (f.exists() && f.isDirectory()) {
            for (File file : files) {
                for (Integer row : rows) {
                    try {
                        JsonArray data = new JsonArray();
                        JsonReader json = new JsonReader(new FileReader(file.getAbsolutePath()));
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());

                        Object idata = data.get(0);
                        ProfilesProperties i = gson.fromJson(idata.toString(), ProfilesProperties.class
                        );
                        String pname = table.getValueAt(row, 1).toString();

                        if (pname.equals(i.getName())) {
                            json.close();
                            file.delete();
                            break;
                        }
                    } catch (IOException e) {
                        callbacks.printError("BurpBountyGui line 2490:" + e.getMessage());
                    }
                }
            }
        }
        showProfiles("All");
    }

    public String getProfilesFilename() {

        return profiles_directory;
    }

    public String getFilename() {

        return filename;
    }

    public void addNewTag(String str) {
        if (!str.isEmpty()) {
            try {
                BufferedWriter out = new BufferedWriter(new FileWriter(profiles_directory.concat("tags.txt"), true));
                out.write(str.concat("\n"));
                out.close();
            } catch (IOException e) {
                System.out.println("BurpBountyGui line 2497:" + e.getMessage());
            }
        }
    }

    public void removeTag(String tag) {
        String file = profiles_directory.concat("tags.txt");
        try {

            File inFile = new File(file);

            if (!inFile.isFile()) {
                callbacks.printError("BurpBountyGui line 2509:");
                return;
            }

            //Construct the new file that will later be renamed to the original filename.
            File tempFile = new File(inFile.getAbsolutePath().concat(".tmp"));

            BufferedReader br = new BufferedReader(new FileReader(file));
            PrintWriter pw = new PrintWriter(new FileWriter(tempFile));

            String line = null;

            //Read from the original file and write to the new
            //unless content matches data to be removed.
            while ((line = br.readLine()) != null) {

                if (!line.trim().equals(tag)) {
                    pw.println(line);
                    pw.flush();
                }
            }
            pw.close();
            br.close();

            //Delete the original file
            if (!inFile.delete()) {
                callbacks.printError("Could not delete file, line 2535");
                return;
            }

            //Rename the new file to the filename the original file had.
            if (!tempFile.renameTo(inFile)) {
                callbacks.printError("Could not rename file line 2541");
            }

        } catch (FileNotFoundException ex) {
            callbacks.printError("BurpBountyGui line 2559:" + ex.getMessage());
        } catch (IOException ex) {
            callbacks.printError("BurpBountyGui line 2562:" + ex.getMessage());
        }
    }

    public void showTags() {

        List<String> tags = readFile(profiles_directory.concat("tags.txt"));

        newTagCombo2.removeAllItems();
        tagmanager.removeAllElements();
        if (!tags.contains("All")) {
            tags.add("All");
        }
        for (String tag : tags) {
            newTagCombo2.addItem(tag);
            tagmanager.addElement(tag);
        }
        newTagCombo2.setSelectedItem("All");
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
        buttonGroup7 = new javax.swing.ButtonGroup();
        buttonGroup8 = new javax.swing.ButtonGroup();
        buttonGroup9 = new javax.swing.ButtonGroup();
        jCheckBoxMenuItem1 = new javax.swing.JCheckBoxMenuItem();
        jMenuItem1 = new javax.swing.JMenuItem();
        jPopupMenu1 = new javax.swing.JPopupMenu();
        jMenuItem2 = new javax.swing.JMenuItem();
        jMenuItem3 = new javax.swing.JMenuItem();
        jPopupMenu2 = new javax.swing.JPopupMenu();
        jMenuItem4 = new javax.swing.JMenuItem();
        jMenuItem5 = new javax.swing.JMenuItem();
        jPopupMenu3 = new javax.swing.JPopupMenu();
        jMenuItem6 = new javax.swing.JMenuItem();
        jMenuItem7 = new javax.swing.JMenuItem();
        jTabbedPane2 = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jPanel6 = new javax.swing.JPanel();
        jLabel43 = new javax.swing.JLabel();
        jLabel44 = new javax.swing.JLabel();
        jLabel45 = new javax.swing.JLabel();
        newTagCombo2 = new javax.swing.JComboBox<>();
        jtabpane = new javax.swing.JTabbedPane();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane5 = new javax.swing.JScrollPane();
        table3 = new javax.swing.JTable();
        jButton16 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        button13 = new javax.swing.JButton();
        jPanel5 = new javax.swing.JPanel();
        jScrollPane6 = new javax.swing.JScrollPane();
        table1 = new javax.swing.JTable();
        jButton17 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        button14 = new javax.swing.JButton();
        jPanel7 = new javax.swing.JPanel();
        jScrollPane10 = new javax.swing.JScrollPane();
        table2 = new javax.swing.JTable();
        jButton18 = new javax.swing.JButton();
        jButton4 = new javax.swing.JButton();
        button15 = new javax.swing.JButton();
        jPanel4 = new javax.swing.JPanel();
        jLabel50 = new javax.swing.JLabel();
        jLabel51 = new javax.swing.JLabel();
        jButton5 = new javax.swing.JButton();
        jButton1 = new javax.swing.JButton();
        text11 = new javax.swing.JTextField();
        jSeparator13 = new javax.swing.JSeparator();
        jScrollPane13 = new javax.swing.JScrollPane();
        listtagmanager = new javax.swing.JList<>();
        jButton12 = new javax.swing.JButton();
        jButton11 = new javax.swing.JButton();
        jLabel48 = new javax.swing.JLabel();
        jLabel49 = new javax.swing.JLabel();
        jPanel8 = new javax.swing.JPanel();
        jLabel53 = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();

        jCheckBoxMenuItem1.setSelected(true);
        jCheckBoxMenuItem1.setText("jCheckBoxMenuItem1");

        jMenuItem1.setText("jMenuItem1");

        jMenuItem2.setText("Enable");
        jMenuItem2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem2ActionPerformed(evt);
            }
        });
        jPopupMenu1.add(jMenuItem2);

        jMenuItem3.setText("Disable");
        jMenuItem3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem3ActionPerformed(evt);
            }
        });
        jPopupMenu1.add(jMenuItem3);

        jMenuItem4.setText("Enable");
        jMenuItem4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem4ActionPerformed(evt);
            }
        });
        jPopupMenu2.add(jMenuItem4);

        jMenuItem5.setText("Disable");
        jMenuItem5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem5ActionPerformed(evt);
            }
        });
        jPopupMenu2.add(jMenuItem5);

        jMenuItem6.setText("Enable");
        jMenuItem6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem6ActionPerformed(evt);
            }
        });
        jPopupMenu3.add(jMenuItem6);

        jMenuItem7.setText("Disable");
        jMenuItem7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem7ActionPerformed(evt);
            }
        });
        jPopupMenu3.add(jMenuItem7);

        setAutoscrolls(true);

        jTabbedPane2.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                showprofiles(evt);
            }
        });

        jPanel1.setAutoscrolls(true);

        jPanel6.setEnabled(false);

        jLabel43.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel43.setForeground(new java.awt.Color(255, 102, 51));
        jLabel43.setText("Profile Manager");

        jLabel44.setText("In this section you can manage the profiles. ");

        jLabel45.setText("Filter by Tag");

        newTagCombo2.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                selectTag(evt);
            }
        });
        newTagCombo2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newTagCombo2ActionPerformed(evt);
            }
        });

        jtabpane.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N

        table3.setAutoCreateRowSorter(true);
        table3.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        table3.setModel(model);
        table3.getTableHeader().setReorderingAllowed(false);
        table3.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                table3MousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                table3MouseReleased(evt);
            }
        });
        jScrollPane5.setViewportView(table3);

        jButton16.setText("Add");
        jButton16.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addActiveProfile(evt);
            }
        });

        jButton2.setText("Edit");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editActiveProfile(evt);
            }
        });

        button13.setText("Remove");
        button13.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeProfiles(evt);
            }
        });

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButton2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(button13, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButton16, javax.swing.GroupLayout.PREFERRED_SIZE, 103, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(997, Short.MAX_VALUE))
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel3Layout.createSequentialGroup()
                    .addGap(133, 133, 133)
                    .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 967, Short.MAX_VALUE)
                    .addContainerGap()))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jButton16)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(button13)
                .addContainerGap(506, Short.MAX_VALUE))
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 614, Short.MAX_VALUE))
        );

        jtabpane.addTab("     Active Profiles     ", jPanel3);

        table1.setAutoCreateRowSorter(true);
        table1.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        table1.setModel(model1);
        table1.setRowSorter(null);
        table1.getTableHeader().setReorderingAllowed(false);
        table1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                table1MousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                table1MouseReleased(evt);
            }
        });
        jScrollPane6.setViewportView(table1);

        jButton17.setText("Add");
        jButton17.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addRequestProfile(evt);
            }
        });

        jButton3.setText("Edit");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editRequestProfile(evt);
            }
        });

        button14.setText("Remove");
        button14.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeProfiles(evt);
            }
        });

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButton3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(button14, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButton17, javax.swing.GroupLayout.PREFERRED_SIZE, 103, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(997, Short.MAX_VALUE))
            .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel5Layout.createSequentialGroup()
                    .addGap(133, 133, 133)
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 967, Short.MAX_VALUE)
                    .addContainerGap()))
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jButton17)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(button14)
                .addContainerGap(506, Short.MAX_VALUE))
            .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 614, Short.MAX_VALUE))
        );

        jtabpane.addTab("   Passive Request Profiles   ", jPanel5);

        table2.setAutoCreateRowSorter(true);
        table2.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        table2.setModel(model2);
        table2.setRowSorter(null);
        table2.getTableHeader().setReorderingAllowed(false);
        table2.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                table2MousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                table2MouseReleased(evt);
            }
        });
        jScrollPane10.setViewportView(table2);

        jButton18.setText("Add");
        jButton18.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addResponseProfile(evt);
            }
        });

        jButton4.setText("Edit");
        jButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editResponseProfile(evt);
            }
        });

        button15.setText("Remove");
        button15.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeProfiles(evt);
            }
        });

        javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
        jPanel7.setLayout(jPanel7Layout);
        jPanel7Layout.setHorizontalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButton4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(button15, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButton18, javax.swing.GroupLayout.PREFERRED_SIZE, 103, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(997, Short.MAX_VALUE))
            .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel7Layout.createSequentialGroup()
                    .addGap(133, 133, 133)
                    .addComponent(jScrollPane10, javax.swing.GroupLayout.DEFAULT_SIZE, 967, Short.MAX_VALUE)
                    .addContainerGap()))
        );
        jPanel7Layout.setVerticalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jButton18)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(button15)
                .addContainerGap(506, Short.MAX_VALUE))
            .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jScrollPane10, javax.swing.GroupLayout.DEFAULT_SIZE, 614, Short.MAX_VALUE))
        );

        jtabpane.addTab("   Passive Response Profiles   ", jPanel7);

        javax.swing.GroupLayout jPanel6Layout = new javax.swing.GroupLayout(jPanel6);
        jPanel6.setLayout(jPanel6Layout);
        jPanel6Layout.setHorizontalGroup(
            jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel6Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jtabpane, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                    .addGroup(jPanel6Layout.createSequentialGroup()
                        .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel43)
                            .addComponent(jLabel44, javax.swing.GroupLayout.PREFERRED_SIZE, 575, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
            .addGroup(jPanel6Layout.createSequentialGroup()
                .addGap(380, 380, 380)
                .addComponent(jLabel45)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(newTagCombo2, javax.swing.GroupLayout.PREFERRED_SIZE, 325, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        jPanel6Layout.setVerticalGroup(
            jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel6Layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addComponent(jLabel43)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel44)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(newTagCombo2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel45))
                .addGap(18, 18, 18)
                .addComponent(jtabpane, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                .addContainerGap())
        );

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(jPanel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(jPanel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        jTabbedPane2.addTab("     Profiles     ", jPanel1);

        jLabel50.setText("In this section specify the base profiles directory. ");

        jLabel51.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel51.setForeground(new java.awt.Color(255, 102, 51));
        jLabel51.setText("Directory");

        jButton5.setText("Directory");
        jButton5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadConfigFile(evt);
            }
        });

        jButton1.setText("Reload");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                profilesReload(evt);
            }
        });

        text11.setToolTipText("");

        listtagmanager.setModel(tagmanager);
        jScrollPane13.setViewportView(listtagmanager);

        jButton12.setText("Remove");
        jButton12.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeTagManager(evt);
            }
        });

        jButton11.setText("Add");
        jButton11.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newTag(evt);
            }
        });

        jLabel48.setText("In this section you can manage the tags.");

        jLabel49.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel49.setForeground(new java.awt.Color(255, 102, 51));
        jLabel49.setText("Tags Manager");

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jSeparator13)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel50, javax.swing.GroupLayout.PREFERRED_SIZE, 575, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel48, javax.swing.GroupLayout.PREFERRED_SIZE, 575, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel51)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jButton5, javax.swing.GroupLayout.DEFAULT_SIZE, 108, Short.MAX_VALUE)
                                    .addComponent(jButton1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(text11, javax.swing.GroupLayout.PREFERRED_SIZE, 700, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jLabel49)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jButton11, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(jButton12, javax.swing.GroupLayout.PREFERRED_SIZE, 105, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jScrollPane13, javax.swing.GroupLayout.PREFERRED_SIZE, 700, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(0, 297, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addComponent(jLabel51)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel50)
                .addGap(25, 25, 25)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton5)
                    .addComponent(text11, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton1)
                .addGap(18, 18, 18)
                .addComponent(jSeparator13, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel49)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel48)
                .addGap(25, 25, 25)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(jButton11)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton12))
                    .addComponent(jScrollPane13, javax.swing.GroupLayout.PREFERRED_SIZE, 205, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(329, Short.MAX_VALUE))
        );

        jPanel4Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jButton1, jButton5});

        jTabbedPane2.addTab("     Options     ", jPanel4);

        jLabel53.setFont(new java.awt.Font("Lucida Grande", 1, 18)); // NOI18N
        jLabel53.setForeground(new java.awt.Color(255, 102, 51));
        jLabel53.setText("About");

        jLabel1.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
        jLabel1.setText("<html>Burp Bounty is a web application vulnerability scanner. This Burp Suite extension allows you, in a quick and simple way, to improve the active <br/>and passive burpsuite scanner by means of personalized rules through a very intuitive graphical interface.Through an advanced search of<br/> patterns and an improvement of the payload to send, we can create our own issue profiles both in the active scanner and in the passive.</html>");

        jLabel3.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(255, 102, 51));
        jLabel3.setText("<html>More info at: <a href=\\\"\\\">https://burpbounty.net</a></html>");
        jLabel3.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jLabel3gowebBurp(evt);
            }
        });

        jLabel6.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(255, 102, 51));
        jLabel6.setText("<html>Burp Bounty version 3.6</html>");

        jLabel7.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        jLabel7.setForeground(new java.awt.Color(255, 102, 51));
        jLabel7.setText("<html>Same scanner, different vulnerabilities</html>");

        jLabel2.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
        jLabel2.setText("<html>If you need more power, I invite you to try the new Burp Bounty Pro, which gives you more power and automation during your manual pentests.</html>");

        javax.swing.GroupLayout jPanel8Layout = new javax.swing.GroupLayout(jPanel8);
        jPanel8.setLayout(jPanel8Layout);
        jPanel8Layout.setHorizontalGroup(
            jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel8Layout.createSequentialGroup()
                .addGroup(jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel8Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel53)
                            .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel8Layout.createSequentialGroup()
                        .addGap(42, 42, 42)
                        .addGroup(jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 354, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 394, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 394, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(230, Short.MAX_VALUE))
        );
        jPanel8Layout.setVerticalGroup(
            jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel8Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel53)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(31, 31, 31)
                .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 37, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(473, Short.MAX_VALUE))
        );

        jTabbedPane2.addTab("     About     ", jPanel8);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jTabbedPane2)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jTabbedPane2)
        );
    }// </editor-fold>//GEN-END:initComponents

    private void showprofiles(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_showprofiles
//        if (jTabbedPane2.isShowing()) {
//            showProfiles("All");
//            showTags();
//        }
    }//GEN-LAST:event_showprofiles

    private void profilesReload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_profilesReload
        //checkProfilesProperties();
        String fileload = text11.getText();

        profiles_directory = fileload + File.separator;

        makeTagsFile();
        showTags();
        showProfiles("All");
        this.callbacks.saveExtensionSetting("filename", fileload);
    }//GEN-LAST:event_profilesReload

    private void loadConfigFile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadConfigFile
        loadConfigFile();
        //checkProfilesProperties();
    }//GEN-LAST:event_loadConfigFile

    private void removeTagManager(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeTagManager
        int selectedIndex = listtagmanager.getSelectedIndex();
        String tag = "";
        if (selectedIndex != -1) {
            tag = tagmanager.get(selectedIndex).toString();
            if (!tag.equals("All")) {
                tagmanager.remove(selectedIndex);
                deleteTagProfiles(tag);
                removeTag(tag);
                showTags();
            }
        }
    }//GEN-LAST:event_removeTagManager

    private void removeProfiles(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeProfiles
        int activePane = jtabpane.getSelectedIndex();

        if (activePane == 0) {
            deleteProfile(table3);
        } else if (activePane == 1) {
            deleteProfile(table1);
        } else if (activePane == 2) {
            deleteProfile(table2);
        }
    }//GEN-LAST:event_removeProfiles

    private void newTagCombo2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newTagCombo2ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_newTagCombo2ActionPerformed

    private void selectTag(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_selectTag
        if ((evt.getStateChange() == java.awt.event.ItemEvent.SELECTED)) {
            showProfiles(newTagCombo2.getItemAt(newTagCombo2.getSelectedIndex()));
        }
    }//GEN-LAST:event_selectTag

    private void newTag(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newTag
        Integer result;
        NewTag nt = new NewTag();
        JOptionPane jopane1 = new JOptionPane(nt, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
        JDialog dialog = jopane1.createDialog(this, "New Tag");
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
        Object selectedValue = jopane1.getValue();

        if (selectedValue != null) {
            result = ((Integer) selectedValue).intValue();

            if (result == JOptionPane.OK_OPTION) {
                addNewTag(nt.newTagtext.getText());
                showTags();
            }
        }
    }//GEN-LAST:event_newTag


    private void addActiveProfile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addActiveProfile

        Integer result;
        ActiveProfile profile = new ActiveProfile(callbacks);
        JOptionPane jopane1 = new JOptionPane(profile, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);

        JDialog dialog = jopane1.createDialog(jopane1, "Add New Active Profile");

        dialog.setSize(new Dimension(900, 760));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
        Object selectedValue = jopane1.getValue();

        if (selectedValue != null) {
            result = ((Integer) selectedValue).intValue();

            if (result == JOptionPane.OK_OPTION) {
                if (!profile.text1.getText().isEmpty()) {
                    saveActiveAttackValues(profile);
                    showProfiles("All");
                    showTags();
                }

            }
        }
    }//GEN-LAST:event_addActiveProfile


    private void table3MouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_table3MouseReleased
        if (evt.isPopupTrigger()) {
            jPopupMenu1.show(table3, evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_table3MouseReleased

    private void table3MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_table3MousePressed
        if (evt.isPopupTrigger()) {
            jPopupMenu1.show(table3, evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_table3MousePressed

    private void jMenuItem2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem2ActionPerformed
        setEnableDisableProfile("Yes", table3);
    }//GEN-LAST:event_jMenuItem2ActionPerformed

    private void jMenuItem3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem3ActionPerformed
        setEnableDisableProfile("No", table3);
    }//GEN-LAST:event_jMenuItem3ActionPerformed

    private void jMenuItem4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem4ActionPerformed
        setEnableDisableProfile("Yes", table1);
    }//GEN-LAST:event_jMenuItem4ActionPerformed

    private void jMenuItem5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem5ActionPerformed
        setEnableDisableProfile("No", table1);
    }//GEN-LAST:event_jMenuItem5ActionPerformed

    private void jMenuItem6ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem6ActionPerformed
        setEnableDisableProfile("Yes", table2);
    }//GEN-LAST:event_jMenuItem6ActionPerformed

    private void jMenuItem7ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem7ActionPerformed
        setEnableDisableProfile("No", table2);
    }//GEN-LAST:event_jMenuItem7ActionPerformed

    private void table1MouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_table1MouseReleased
        if (evt.isPopupTrigger()) {
            jPopupMenu2.show(table1, evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_table1MouseReleased

    private void table1MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_table1MousePressed
        if (evt.isPopupTrigger()) {
            jPopupMenu2.show(table1, evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_table1MousePressed

    private void table2MouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_table2MouseReleased
        if (evt.isPopupTrigger()) {
            jPopupMenu3.show(table2, evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_table2MouseReleased

    private void table2MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_table2MousePressed
        if (evt.isPopupTrigger()) {
            jPopupMenu3.show(table2, evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_table2MousePressed

    private void editActiveProfile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editActiveProfile
        Integer result;

        String profile_name = table3.getValueAt(table3.getSelectedRow(), 1).toString();

        ActiveProfile profile = new ActiveProfile(callbacks);
        JOptionPane jopane1 = new JOptionPane(profile, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);

        JDialog dialog = jopane1.createDialog(jopane1, "Edit Active Profile");

        dialog.setSize(new Dimension(900, 760));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(null);
        profile.text1.setEditable(false);

        setActiveAttackValues(profile_name, profile);

        dialog.setVisible(true);
        Object selectedValue = jopane1.getValue();

        if (selectedValue != null) {
            result = ((Integer) selectedValue).intValue();

            if (result == JOptionPane.OK_OPTION) {

                saveActiveAttackValues(profile);
                showProfiles("All");
                showTags();
            }
        }
    }//GEN-LAST:event_editActiveProfile

    private void addRequestProfile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addRequestProfile
        Integer result;
        RequestProfile profile = new RequestProfile(callbacks);
        JOptionPane jopane1 = new JOptionPane(profile, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);

        JDialog dialog = jopane1.createDialog(jopane1, "Add New Passive Request Profile");

        dialog.setSize(new Dimension(900, 760));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
        Object selectedValue = jopane1.getValue();

        if (selectedValue != null) {
            result = ((Integer) selectedValue).intValue();

            if (result == JOptionPane.OK_OPTION) {
                if (!profile.text1.getText().isEmpty()) {
                    saveRequestAttackValues(profile);
                    showProfiles("All");
                    showTags();
                }
            }
        }
    }//GEN-LAST:event_addRequestProfile

    private void editRequestProfile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editRequestProfile
        Integer result;

        String profile_name = table1.getValueAt(table1.getSelectedRow(), 1).toString();

        RequestProfile profile = new RequestProfile(callbacks);
        JOptionPane jopane1 = new JOptionPane(profile, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);

        JDialog dialog = jopane1.createDialog(jopane1, "Edit Passive Request Profile");

        dialog.setSize(new Dimension(900, 760));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(null);
        profile.text1.setEditable(false);

        setRequestAttackValues(profile_name, profile);

        dialog.setVisible(true);
        Object selectedValue = jopane1.getValue();

        if (selectedValue != null) {
            result = ((Integer) selectedValue).intValue();

            if (result == JOptionPane.OK_OPTION) {

                saveRequestAttackValues(profile);
                showProfiles("All");
                showTags();
            }
        }
    }//GEN-LAST:event_editRequestProfile

    private void addResponseProfile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addResponseProfile
        Integer result;
        ResponseProfile profile = new ResponseProfile(callbacks);
        JOptionPane jopane1 = new JOptionPane(profile, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);

        JDialog dialog = jopane1.createDialog(jopane1, "Add New Passive Response Profile");

        dialog.setSize(new Dimension(900, 760));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
        Object selectedValue = jopane1.getValue();

        if (selectedValue != null) {
            result = ((Integer) selectedValue).intValue();

            if (result == JOptionPane.OK_OPTION) {
                if (!profile.text1.getText().isEmpty()) {
                    saveResponseAttackValues(profile);
                    showProfiles("All");
                    showTags();
                }
            }
        }
    }//GEN-LAST:event_addResponseProfile

    private void editResponseProfile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editResponseProfile
        Integer result;
        String profile_name = table2.getValueAt(table2.getSelectedRow(), 1).toString();

        ResponseProfile profile = new ResponseProfile(callbacks);
        JOptionPane jopane1 = new JOptionPane(profile, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);

        JDialog dialog = jopane1.createDialog(jopane1, "Edit Passive Response Profile");

        dialog.setSize(new Dimension(900, 760));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(null);
        profile.text1.setEditable(false);

        setResponseAttackValues(profile_name, profile);

        dialog.setVisible(true);
        Object selectedValue = jopane1.getValue();

        if (selectedValue != null) {
            result = ((Integer) selectedValue).intValue();

            if (result == JOptionPane.OK_OPTION) {

                saveResponseAttackValues(profile);
                showProfiles("All");
                showTags();
            }
        }
    }//GEN-LAST:event_editResponseProfile

    private void jLabel3gowebBurp(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel3gowebBurp
        try {
            Desktop.getDesktop().browse(new URI("https://burpbounty.net"));
        } catch (URISyntaxException | IOException e) {
            callbacks.printError("Active profile line 3178 Help web not opened: " + e);
        }
    }//GEN-LAST:event_jLabel3gowebBurp


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton button13;
    private javax.swing.JButton button14;
    private javax.swing.JButton button15;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.ButtonGroup buttonGroup2;
    private javax.swing.ButtonGroup buttonGroup3;
    private javax.swing.ButtonGroup buttonGroup4;
    private javax.swing.ButtonGroup buttonGroup5;
    private javax.swing.ButtonGroup buttonGroup6;
    private javax.swing.ButtonGroup buttonGroup7;
    private javax.swing.ButtonGroup buttonGroup8;
    private javax.swing.ButtonGroup buttonGroup9;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton11;
    private javax.swing.JButton jButton12;
    private javax.swing.JButton jButton16;
    private javax.swing.JButton jButton17;
    private javax.swing.JButton jButton18;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JButton jButton5;
    private javax.swing.JCheckBoxMenuItem jCheckBoxMenuItem1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel43;
    private javax.swing.JLabel jLabel44;
    private javax.swing.JLabel jLabel45;
    private javax.swing.JLabel jLabel48;
    private javax.swing.JLabel jLabel49;
    private javax.swing.JLabel jLabel50;
    private javax.swing.JLabel jLabel51;
    private javax.swing.JLabel jLabel53;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JMenuItem jMenuItem2;
    private javax.swing.JMenuItem jMenuItem3;
    private javax.swing.JMenuItem jMenuItem4;
    private javax.swing.JMenuItem jMenuItem5;
    private javax.swing.JMenuItem jMenuItem6;
    private javax.swing.JMenuItem jMenuItem7;
    public javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel3;
    public javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    public javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JPanel jPanel8;
    private javax.swing.JPopupMenu jPopupMenu1;
    private javax.swing.JPopupMenu jPopupMenu2;
    private javax.swing.JPopupMenu jPopupMenu3;
    private javax.swing.JScrollPane jScrollPane10;
    private javax.swing.JScrollPane jScrollPane13;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JSeparator jSeparator13;
    public javax.swing.JTabbedPane jTabbedPane2;
    private javax.swing.JTabbedPane jtabpane;
    public javax.swing.JList<String> listtagmanager;
    private javax.swing.JComboBox<String> newTagCombo2;
    private javax.swing.JTable table1;
    private javax.swing.JTable table2;
    private javax.swing.JTable table3;
    public javax.swing.JTextField text11;
    // End of variables declaration//GEN-END:variables
}
