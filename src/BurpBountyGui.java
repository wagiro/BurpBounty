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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultCellEditor;
import javax.swing.DefaultListModel;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

public class BurpBountyGui extends javax.swing.JPanel {

    private IBurpExtenderCallbacks callbacks;
    private String filename;
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
    private String Author;
    private DefaultListModel payload;
    private DefaultListModel grep;
    private DefaultListModel encoder;
    private DefaultListModel tag;
    private DefaultListModel tagmanager;
    private List<Headers> Header;
    private List<String> variationAttributes;
    private Boolean pathDiscovery;

    DefaultTableModel model;
    DefaultTableModel model1;
    DefaultTableModel model2;
    DefaultTableModel model4;

    public BurpBountyGui(BurpBountyExtension parent) {
        this.callbacks = parent.callbacks;
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
        Author = "";
        payload = new DefaultListModel();
        grep = new DefaultListModel();
        encoder = new DefaultListModel();
        tag = new DefaultListModel();
        tagmanager = new DefaultListModel();
        model4 = new DefaultTableModel();
        Header = new ArrayList();
        variationAttributes = new ArrayList();
        pathDiscovery = false;

        if (callbacks.loadExtensionSetting("filename") != null) {
            filename = callbacks.loadExtensionSetting("filename");
        } else {
            filename = System.getProperty("user.dir") + "/";
        }
        model = new DefaultTableModel() {

            @Override
            public boolean isCellEditable(int row, int column) {
                //all cells false
                return false;
            }
        };

        model1 = new DefaultTableModel() {

            @Override
            public boolean isCellEditable(int row, int column) {
                //all cells false
                return false;
            }
        };

        model2 = new DefaultTableModel() {

            @Override
            public boolean isCellEditable(int row, int column) {
                //all cells false
                return false;
            }
        };

        //main
        initComponents();
        initCombo();
        text11.setText(filename);
        makeTagsFile();
        showProfiles("All");
        showHeaders(Header);
    }

    public void clear() {
        text1.setText("");
        grep.removeAllElements();
        payload.removeAllElements();
        encoder.removeAllElements();
        tag.removeAllElements();
        text71.setText("");
        text72.setText("");
        check8.setSelected(false);
        text5.setText("");
        buttonGroup1.clearSelection();
        buttonGroup4.clearSelection();
        buttonGroup2.clearSelection();
        buttonGroup3.clearSelection();
        buttonGroup5.clearSelection();
        buttonGroup8.clearSelection();
        buttonGroup9.clearSelection();
        check1.setSelected(false);
        check4.setSelected(false);
        check71.setSelected(false);
        check72.setSelected(false);
        excludehttp.setSelected(false);
        onlyhttp.setSelected(false);
        negativeCT.setSelected(false);
        negativeRC.setSelected(false);
        text4.setText("");
        textarea1.setText("");
        textarea2.setText("");
        textarea3.setText("");
        textarea4.setText("");
        sp1.setValue(0);
        textpayloads.setText("");
        textgreps.setText("");
        texttime.setText("");
        textauthor.setText("");
        textcl.setText("");
        setSelectedVariations(false);
        pathdiscovery.setSelected(false);

    }

    public void setAttackValues(String issue) {
        //Set Attack values when select from main combobox
        try {
            Gson gson = new Gson();
            JsonArray json = initJson();
            Issue i = new Issue();

            if (json != null) {
                for (JsonElement pa : json) {
                    JsonObject bbObj = pa.getAsJsonObject();
                    if (bbObj.get("Name").getAsString().equals(issue)) {
                        i = gson.fromJson(bbObj.toString(), Issue.class);
                    }

                }
            }

            variationAttributes.clear();
            name = i.getName();
            scanner = i.getScanner();
            casesensitive = i.getCaseSensitive();
            notresponse = i.getNotResponse();
            matchtype = i.getMatchType();
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
            excludeHTTP = i.getExcludeHTTP();
            onlyHTTP = i.getOnlyHTTP();
            negativect = i.getNegativeCT();
            negativerc = i.getNegativeRC();
            redirtype = i.getRedirection();
            maxRedir = i.getMaxRedir();
            payloadsfile = i.getpayloadsFile();
            grepsfile = i.getgrepsFile();
            payloadPosition = i.getPayloadPosition();
            timeOut = i.getTime();
            Author = i.getAuthor();
            contentLength = i.getContentLength();
            Header = i.getHeader();
            variationAttributes = i.getVariationAttributes();
            pathDiscovery = i.getPathDiscover();

            if (payloadsfile == null) {
                payloadsfile = "";
            }
            if (grepsfile == null) {
                grepsfile = "";
            }
            if (Author == null) {
                Author = "";
            }
            if (contentLength == null) {
                contentLength = "";
            }
            if (name == null) {
                name = "";
            }
            if (issuename == null) {
                issuename = "";
            }
            if (issuedetail == null) {
                issuedetail = "";
            }
            if (issuebackground == null) {
                issuebackground = "";
            }
            if (remediationdetail == null) {
                remediationdetail = "";
            }
            if (remediationbackground == null) {
                remediationbackground = "";
            }
            if (charstourlencode == null) {
                charstourlencode = "";
            }
            if (issueseverity == null) {
                issueseverity = "";
            }
            if (issueconfidence == null) {
                issueconfidence = "";
            }
            if (responsecode == null) {
                responsecode = "";
            }
            if (contenttype == null) {
                contenttype = "";
            }
            if (timeOut == null) {
                timeOut = "";
            }
            if (Header == null) {
                Header = new ArrayList();
            }
            if (variationAttributes == null) {
                variationAttributes = new ArrayList();
            }

            if (pathDiscovery == null) {
                pathDiscovery = false;
            }

            if (Author.length() >= 35) {
                textauthor.setText(Author.substring(0, 34));
            } else {
                textauthor.setText(Author);
            }

            if (name.length() >= 35) {
                text1.setText(name.substring(0, 34));
            } else {
                text1.setText(name);
            }

            if (scanner == 1) {
                buttonGroup1.setSelected(radio1.getModel(), true);
            } else if (scanner == 2) {
                buttonGroup1.setSelected(radio2.getModel(), true);
            } else if (scanner == 3) {
                buttonGroup1.setSelected(radioPR.getModel(), true);
            }

            if (payloadPosition == 1) {
                buttonGroup9.setSelected(replace.getModel(), true);
            } else if (payloadPosition == 2) {
                buttonGroup9.setSelected(append.getModel(), true);
            }

            grep.removeAllElements();
            payload.removeAllElements();
            encoder.removeAllElements();
            tag.removeAllElements();
            textpayloads.setText(payloadsfile);
            textgreps.setText(grepsfile);

            if (!grepsfile.isEmpty()) {
                loadPath(grepsfile, grep);
                updateGreps(grepsfile, i);

            } else {
                for (String gs : i.getGreps()) {
                    grep.addElement(gs);
                }
            }

            if (!payloadsfile.isEmpty()) {
                loadPath(payloadsfile, payload);
                updatePayloads(payloadsfile, i);

            } else {
                for (String pay : i.getPayloads()) {
                    payload.addElement(pay);
                }
            }

            if (i.getTags() != null) {
                for (String t : i.getTags()) {
                    tag.addElement(t);
                }
            }

            for (String enc : i.getEncoder()) {
                encoder.addElement(enc);
            }

            pathdiscovery.setSelected(pathDiscovery);

            text71.setText(contenttype);
            text72.setText(responsecode);

            check8.setSelected(urlencode);
            text5.setText(charstourlencode);
            excludehttp.setSelected(excludeHTTP);
            onlyhttp.setSelected(onlyHTTP);
            if (timeOut.equals("0")) {
                texttime.setText("");
            } else {
                texttime.setText(timeOut);
            }

            if (contentLength.equals("0")) {
                textcl.setText("");
            } else {
                textcl.setText(contentLength);
            }

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
                case 5:
                    buttonGroup4.setSelected(radiotime.getModel(), true);
                    break;
                case 6:
                    buttonGroup4.setSelected(radiocl.getModel(), true);
                    break;
                case 7:
                    buttonGroup4.setSelected(variationsRadio.getModel(), true);
                    break;
                case 8:
                    buttonGroup4.setSelected(invariationsRadio.getModel(), true);
                    break;
                default:
                    buttonGroup4.clearSelection();
                    break;
            }

            switch (redirtype) {
                case 1:
                    buttonGroup8.setSelected(rb1.getModel(), true);
                    break;
                case 2:
                    buttonGroup8.setSelected(rb2.getModel(), true);
                    break;
                case 3:
                    buttonGroup8.setSelected(rb3.getModel(), true);
                    break;
                case 4:
                    buttonGroup8.setSelected(rb4.getModel(), true);
                    break;
                default:
                    buttonGroup8.clearSelection();
                    break;
            }

            showHeaders(Header);
            setSelectedVariations(false);

            if (variationAttributes.contains("status_code")) {
                status_code.setSelected(true);
            }
            if (variationAttributes.contains("input_image_labels")) {
                input_image_labels.setSelected(true);
            }
            if (variationAttributes.contains("non_hidden_form_input_types")) {
                non_hidden_form_input_types.setSelected(true);
            }
            if (variationAttributes.contains("page_title")) {
                page_title.setSelected(true);
            }
            if (variationAttributes.contains("visible_text")) {
                visible_text.setSelected(true);
            }
            if (variationAttributes.contains("button_submit_labels")) {
                button_submit_labels.setSelected(true);
            }
            if (variationAttributes.contains("div_ids")) {
                div_ids.setSelected(true);
            }
            if (variationAttributes.contains("word_count")) {
                word_count.setSelected(true);
            }
            if (variationAttributes.contains("content_type")) {
                content_type.setSelected(true);
            }
            if (variationAttributes.contains("outbound_edge_tag_names")) {
                outbound_edge_tag_names.setSelected(true);
            }
            if (variationAttributes.contains("whole_body_content")) {
                whole_body_content.setSelected(true);
            }
            if (variationAttributes.contains("etag_header")) {
                etag_header.setSelected(true);
            }
            if (variationAttributes.contains("visible_word_count")) {
                visible_word_count.setSelected(true);
            }
            if (variationAttributes.contains("content_length")) {
                content_length.setSelected(true);
            }
            if (variationAttributes.contains("header_tags")) {
                header_tags.setSelected(true);
            }
            if (variationAttributes.contains("tag_ids")) {
                tag_ids.setSelected(true);
            }
            if (variationAttributes.contains("comments")) {
                comments.setSelected(true);
            }
            if (variationAttributes.contains("line_count")) {
                line_count.setSelected(true);
            }
            if (variationAttributes.contains("set_cookie_names")) {
                set_cookie_names.setSelected(true);
            }
            if (variationAttributes.contains("last_modified_header")) {
                last_modified_header.setSelected(true);
            }
            if (variationAttributes.contains("first_header_tag")) {
                first_header_tag.setSelected(true);
            }
            if (variationAttributes.contains("tag_names")) {
                tag_names.setSelected(true);
            }
            if (variationAttributes.contains("input_submit_labels")) {
                input_submit_labels.setSelected(true);
            }
            if (variationAttributes.contains("outbound_edge_count")) {
                outbound_edge_count.setSelected(true);
            }
            if (variationAttributes.contains("initial_body_content")) {
                initial_body_content.setSelected(true);
            }
            if (variationAttributes.contains("content_location")) {
                content_location.setSelected(true);
            }
            if (variationAttributes.contains("limited_body_content")) {
                limited_body_content.setSelected(true);
            }
            if (variationAttributes.contains("canonical_link")) {
                canonical_link.setSelected(true);
            }
            if (variationAttributes.contains("css_classes")) {
                css_classes.setSelected(true);
            }
            if (variationAttributes.contains("location")) {
                location.setSelected(true);
            }
            if (variationAttributes.contains("anchor_labels")) {
                anchor_labels.setSelected(true);
            }

            check1.setSelected(casesensitive);
            check4.setSelected(notresponse);
            check71.setSelected(iscontenttype);
            check72.setSelected(isresponsecode);
            negativeCT.setSelected(negativect);
            negativeRC.setSelected(negativerc);
            text4.setText(issuename);
            textarea1.setText(issuedetail);
            textarea2.setText(issuebackground);
            textarea3.setText(remediationdetail);
            textarea4.setText(remediationbackground);
            text11.setText(filename);
            sp1.setValue(maxRedir);

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
        } catch (Exception e) {
            System.out.println(e.getClass());
        }
    }

    public void saveAttackValues() {
        Header = new ArrayList();
        variationAttributes = new ArrayList();
        //Save attack with fields values
        try {
            //get GUI values
            Issue newfile = new Issue();

            if (text1.getText().length() >= 35) {
                newfile.setName(text1.getText().substring(0, 34));
            } else {
                newfile.setName(text1.getText());
            }

            if (textauthor.getText().length() >= 35) {
                newfile.setAuthor(textauthor.getText().substring(0, 34));
            } else {
                newfile.setAuthor(textauthor.getText());
            }

            if (radio1.isSelected()) {
                newfile.setScanner(1);
            } else if (radio2.isSelected()) {
                newfile.setScanner(2);
            } else if (radioPR.isSelected()) {
                newfile.setScanner(3);
            } else {
                newfile.setScanner(0);
            }

            if (replace.isSelected()) {
                newfile.setPayloadPosition(1);
            } else if (append.isSelected()) {
                newfile.setPayloadPosition(2);
            } else {
                newfile.setPayloadPosition(1);
            }

            newfile.setActive(true);
            List encoders = new ArrayList();
            List payloads = new ArrayList();
            List greps = new ArrayList();
            List tags = new ArrayList();

            newfile.setPayloadsFile(textpayloads.getText());
            for (int i = 0; i < list1.getModel().getSize(); i++) {
                Object item = list1.getModel().getElementAt(i);
                payloads.add(item);
            }
            newfile.setPayloads(payloads);

            newfile.setGrepsFile(textgreps.getText());
            for (int i = 0; i < list2.getModel().getSize(); i++) {
                Object item = list2.getModel().getElementAt(i);
                greps.add(item);
            }
            newfile.setGreps(greps);

            for (int row = 0; row < model4.getRowCount(); row++) {
                Header.add(new Headers((String) model4.getValueAt(row, 0), (String) model4.getValueAt(row, 1), (String) model4.getValueAt(row, 2), (String) model4.getValueAt(row, 3), (String) model4.getValueAt(row, 4)));
            }
            newfile.setHeader(Header);

            for (int i = 0; i < listtag.getModel().getSize(); i++) {
                Object item = listtag.getModel().getElementAt(i);
                tags.add(item);
            }
            newfile.setTags(tags);

            for (int i = 0; i < list3.getModel().getSize(); i++) {
                Object item = list3.getModel().getElementAt(i);
                encoders.add(item);
            }

            newfile.setEncoder(encoders);
            newfile.setCharsToUrlEncode(text5.getText());
            newfile.setUrlEncode(check8.isSelected());
            newfile.setExcludeHTTP(excludehttp.isSelected());
            newfile.setOnlyHTTP(onlyhttp.isSelected());
            newfile.setContentType(text71.getText());
            newfile.setResponseCode(text72.getText());
            newfile.setPathDiscovery(pathdiscovery.isSelected());

            if (texttime.getText().isEmpty()) {
                newfile.setTime(texttime.getText());
            } else {
                newfile.setTime(texttime.getText());
            }

            if (textcl.getText().isEmpty()) {
                newfile.setContentLength(textcl.getText());
            } else {
                newfile.setContentLength(textcl.getText());
            }

            if (radio4.isSelected()) {
                newfile.setMatchType(1);
            } else if (radio3.isSelected()) {
                newfile.setMatchType(2);
            } else if (radio12.isSelected()) {
                newfile.setMatchType(3);
            } else if (radio22.isSelected()) {
                newfile.setMatchType(4);
            } else if (radiotime.isSelected()) {
                newfile.setMatchType(5);
            } else if (radiocl.isSelected()) {
                newfile.setMatchType(6);
            } else if (variationsRadio.isSelected()) {
                newfile.setMatchType(7);
            } else if (invariationsRadio.isSelected()) {
                newfile.setMatchType(8);
            } else {
                newfile.setMatchType(0);
            }

            if (rb1.isSelected()) {
                newfile.setRedirType(1);
            } else if (rb2.isSelected()) {
                newfile.setRedirType(2);
            } else if (rb3.isSelected()) {
                newfile.setRedirType(3);
            } else if (rb4.isSelected()) {
                newfile.setRedirType(4);
            } else {
                newfile.setRedirType(0);
            }

            if (status_code.isSelected()) {
                variationAttributes.add("status_code");
            }
            if (input_image_labels.isSelected()) {
                variationAttributes.add("input_image_labels");
            }
            if (non_hidden_form_input_types.isSelected()) {
                variationAttributes.add("non_hidden_form_input_types");
            }
            if (page_title.isSelected()) {
                variationAttributes.add("page_title");
            }
            if (visible_text.isSelected()) {
                variationAttributes.add("visible_text");
            }
            if (button_submit_labels.isSelected()) {
                variationAttributes.add("button_submit_labels");
            }
            if (div_ids.isSelected()) {
                variationAttributes.add("div_ids");
            }
            if (word_count.isSelected()) {
                variationAttributes.add("word_count");
            }
            if (content_type.isSelected()) {
                variationAttributes.add("content_type");
            }
            if (outbound_edge_tag_names.isSelected()) {
                variationAttributes.add("outbound_edge_tag_names");
            }
            if (whole_body_content.isSelected()) {
                variationAttributes.add("whole_body_content");
            }
            if (etag_header.isSelected()) {
                variationAttributes.add("etag_header");
            }
            if (visible_word_count.isSelected()) {
                variationAttributes.add("visible_word_count");
            }
            if (content_length.isSelected()) {
                variationAttributes.add("content_length");
            }
            if (header_tags.isSelected()) {
                variationAttributes.add("header_tags");
            }
            if (tag_ids.isSelected()) {
                variationAttributes.add("tag_ids");
            }
            if (comments.isSelected()) {
                variationAttributes.add("comments");
            }
            if (line_count.isSelected()) {
                variationAttributes.add("line_count");
            }
            if (set_cookie_names.isSelected()) {
                variationAttributes.add("set_cookie_names");
            }
            if (last_modified_header.isSelected()) {
                variationAttributes.add("last_modified_header");
            }
            if (first_header_tag.isSelected()) {
                variationAttributes.add("first_header_tag");
            }
            if (tag_names.isSelected()) {
                variationAttributes.add("tag_names");
            }
            if (input_submit_labels.isSelected()) {
                variationAttributes.add("input_submit_labels");
            }
            if (outbound_edge_count.isSelected()) {
                variationAttributes.add("outbound_edge_count");
            }
            if (initial_body_content.isSelected()) {
                variationAttributes.add("initial_body_content");
            }
            if (content_location.isSelected()) {
                variationAttributes.add("content_location");
            }
            if (limited_body_content.isSelected()) {
                variationAttributes.add("limited_body_content");
            }
            if (canonical_link.isSelected()) {
                variationAttributes.add("canonical_link");
            }
            if (css_classes.isSelected()) {
                variationAttributes.add("css_classes");
            }
            if (location.isSelected()) {
                variationAttributes.add("location");
            }
            if (anchor_labels.isSelected()) {
                variationAttributes.add("anchor_labels");
            }

            newfile.setVariationAttributes(variationAttributes);

            newfile.setCaseSensitive(check1.isSelected());
            newfile.setNotResponse(check4.isSelected());
            newfile.setIsContentType(check71.isSelected());
            newfile.setIsResponseCode(check72.isSelected());
            newfile.setNegativeCT(negativeCT.isSelected());
            newfile.setNegativeRC(negativeRC.isSelected());
            newfile.setIssueName(text4.getText());
            newfile.setIssueDetail(textarea1.getText());
            newfile.setIssueBackground(textarea2.getText());
            newfile.setRemediationDetail(textarea3.getText());
            newfile.setRemediationBackground(textarea4.getText());
            newfile.setMaxRedir((Integer) sp1.getValue());

            if (radio5.isSelected()) {
                newfile.setIssueSeverity("High");
            } else if (radio6.isSelected()) {
                newfile.setIssueSeverity("Medium");
            } else if (radio7.isSelected()) {
                newfile.setIssueSeverity("Low");
            } else if (radio8.isSelected()) {
                newfile.setIssueSeverity("Information");
            }

            if (radio9.isSelected()) {
                newfile.setIssueConfidence("Certain");
            } else if (radio10.isSelected()) {
                newfile.setIssueConfidence("Firm");
            } else if (radio11.isSelected()) {
                newfile.setIssueConfidence("Tentative");
            }

            //Save start
            Gson gson = new Gson();

            JsonArray ijson = new JsonArray();
            List<Issue> newjson = gson.fromJson(ijson, new TypeToken<List<Issue>>() {
            }.getType());
            newjson.add(newfile);

            String json = gson.toJson(newjson);

            //Write JSON String to file
            FileOutputStream fileStream;

            if (text1.getText().length() >= 35) {
                fileStream = new FileOutputStream(new File(text11.getText() + "/" + text1.getText().substring(0, 34) + ".bb"));
            } else {
                fileStream = new FileOutputStream(new File(text11.getText() + "/" + text1.getText()) + ".bb");
            }

            OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
            writer.write(json);
            writer.close();
            fileStream.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void setSelectedVariations(boolean state) {
        status_code.setSelected(state);
        input_image_labels.setSelected(state);
        non_hidden_form_input_types.setSelected(state);
        page_title.setSelected(state);
        visible_text.setSelected(state);
        button_submit_labels.setSelected(state);
        div_ids.setSelected(state);
        word_count.setSelected(state);
        content_type.setSelected(state);
        outbound_edge_tag_names.setSelected(state);
        whole_body_content.setSelected(state);
        etag_header.setSelected(state);
        visible_word_count.setSelected(state);
        content_length.setSelected(state);
        header_tags.setSelected(state);
        tag_ids.setSelected(state);
        comments.setSelected(state);
        line_count.setSelected(state);
        set_cookie_names.setSelected(state);
        last_modified_header.setSelected(state);
        first_header_tag.setSelected(state);
        tag_names.setSelected(state);
        input_submit_labels.setSelected(state);
        outbound_edge_count.setSelected(state);
        initial_body_content.setSelected(state);
        content_location.setSelected(state);
        limited_body_content.setSelected(state);
        canonical_link.setSelected(state);
        css_classes.setSelected(state);
        location.setSelected(state);
        anchor_labels.setSelected(state);
    }

    public void setEnabledVariations(boolean state) {
        Attributes.setEnabled(state);
        status_code.setEnabled(state);
        input_image_labels.setEnabled(state);
        non_hidden_form_input_types.setEnabled(state);
        page_title.setEnabled(state);
        visible_text.setEnabled(state);
        button_submit_labels.setEnabled(state);
        div_ids.setEnabled(state);
        word_count.setEnabled(state);
        content_type.setEnabled(state);
        outbound_edge_tag_names.setEnabled(state);
        whole_body_content.setEnabled(state);
        etag_header.setEnabled(state);
        visible_word_count.setEnabled(state);
        content_length.setEnabled(state);
        header_tags.setEnabled(state);
        tag_ids.setEnabled(state);
        comments.setEnabled(state);
        line_count.setEnabled(state);
        set_cookie_names.setEnabled(state);
        last_modified_header.setEnabled(state);
        first_header_tag.setEnabled(state);
        tag_names.setEnabled(state);
        input_submit_labels.setEnabled(state);
        outbound_edge_count.setEnabled(state);
        initial_body_content.setEnabled(state);
        content_location.setEnabled(state);
        limited_body_content.setEnabled(state);
        canonical_link.setEnabled(state);
        css_classes.setEnabled(state);
        location.setEnabled(state);
        anchor_labels.setEnabled(state);
    }

    public void setEnabledVarious(boolean state) {
        jLabel31.setEnabled(state);
        jLabel30.setEnabled(state);
        check4.setEnabled(state);
        check1.setEnabled(state);
        excludehttp.setEnabled(state);
        onlyhttp.setEnabled(state);
        check71.setEnabled(state);
        check72.setEnabled(state);
        text71.setEnabled(state);
        text72.setEnabled(state);
        negativeCT.setEnabled(state);
        negativeRC.setEnabled(state);
        rb1.setEnabled(state);
        rb2.setEnabled(state);
        rb3.setEnabled(state);
        rb4.setEnabled(state);
        jLabel6.setEnabled(state);
        jLabel2.setEnabled(state);
        sp1.setEnabled(state);
        jLabel28.setEnabled(state);
        jLabel29.setEnabled(state);
        jLabel25.setEnabled(state);
        jLabel24.setEnabled(state);
        button8.setEnabled(state);
        textgreps.setEnabled(state);
        button9.setEnabled(state);
        button10.setEnabled(state);
        button11.setEnabled(state);
        button7.setEnabled(state);
        list2.setEnabled(state);
        textfield2.setEnabled(state);
    }

    public void updatePayloads(String file, Issue issue) {

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
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        issue.setPayloads(payloads);

        Gson gson = new Gson();
        String strJson = gson.toJson(issue);
        FileWriter writer = null;
        try {
            writer = new FileWriter(text11.getText() + "/" + issue.getName() + ".bb");
            writer.write("[" + strJson + "]");
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void updateGreps(String file, Issue issue) {

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
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        issue.setGreps(greps);

        Gson gson = new Gson();
        String strJson = gson.toJson(issue);
        FileWriter writer = null;
        try {
            writer = new FileWriter(text11.getText() + "/" + issue.getName() + ".bb");
            writer.write("[" + strJson + "]");
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void initCombo() {
        //Init main comboBox with file values
        JsonArray json = initJson();
        combo1.removeAllItems();
        if (json != null) {
            //Names for main combo box
            for (JsonElement pa : json) {
                JsonObject bbObj = pa.getAsJsonObject();
                if (bbObj.get("Active").getAsBoolean()) {
                    combo1.addItem(bbObj.get("Name").getAsString());
                }
            }
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
            return records;
        } catch (Exception e) {
            System.err.format("Exception occurred trying to read '%s'.", filename);
            e.printStackTrace();
            return null;
        }
    }

    public JsonArray initJson() {
        //Init json form filename
        FileReader fr;

        try {
            JsonArray data = new JsonArray();
            File f = new File(filename);
            if (f.exists() && f.isDirectory()) {
                for (File file : f.listFiles()) {
                    if (file.getName().endsWith("bb")) {
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
                result = (String) contents.getTransferData(DataFlavor.stringFlavor);
            } catch (UnsupportedFlavorException | IOException ex) {
                System.out.println(ex);
                ex.printStackTrace();
            }
        }
        return result;
    }

    public void loadConfigFile() {
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Specify a profiles directory to load");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        int userSelection = fileChooser.showOpenDialog(parentFrame);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileload = fileChooser.getSelectedFile();
            filename = fileload.getAbsolutePath() + "/";
            text11.setText(fileload.getAbsolutePath());

            initJson();
            initCombo();
            this.callbacks.saveExtensionSetting("filename", filename);

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
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public void loadPayloadsFile(DefaultListModel list) {
        //Load file for implement payloads and match load button
        DefaultListModel List = list;
        String line;
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Specify a file to load");

        int userSelection = fileChooser.showOpenDialog(parentFrame);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileload = fileChooser.getSelectedFile();
            textpayloads.setText(fileload.getAbsolutePath());
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

    public void loadGrepsFile(DefaultListModel list) {
        //Load file for implement payloads and match load button
        DefaultListModel List = list;
        String line;
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Specify a file to load");

        int userSelection = fileChooser.showOpenDialog(parentFrame);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileload = fileChooser.getSelectedFile();
            textgreps.setText(fileload.getAbsolutePath());
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

    public void setEnableDisableProfile(String enable, int tableIndex) {

        Gson gson = new Gson();
        File f = new File(filename);

        JsonArray json2 = new JsonArray();
        List<Issue> newjson = gson.fromJson(json2, new TypeToken<List<Issue>>() {
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

        JTable finalTable = new JTable();

        if (tableIndex == 0) {
            finalTable = table;
        } else if (tableIndex == 1) {
            finalTable = table1;
        } else if (tableIndex == 2) {
            finalTable = table2;
        }

        int[] rows = finalTable.getSelectedRows();

        if (f.exists() && f.isDirectory()) {
            for (File file : files) {
                for (Integer row : rows) {
                    try {
                        JsonArray data = new JsonArray();
                        JsonReader json = new JsonReader(new FileReader(file.getAbsolutePath()));
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());

                        Object idata = data.get(0);
                        Issue i = gson.fromJson(idata.toString(), Issue.class);
                        String pname = finalTable.getValueAt(row, 0).toString();

                        if (pname.equals(i.getName())) {
                            if (enable.contains("Yes")) {
                                i.setActive(true);
                                finalTable.setValueAt("Yes", row, 1);
                            } else {
                                i.setActive(false);
                                finalTable.setValueAt("No", row, 1);
                            }
                            newjson.clear();
                            newjson.add(i);
                            FileOutputStream fileStream = new FileOutputStream(file.getAbsoluteFile());
                            String fjson = gson.toJson(newjson);
                            OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
                            writer.write(fjson);
                            writer.close();
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    public void setEnableDisableAllProfiles(String enable) {

        Gson gson = new Gson();
        File f = new File(filename);

        JsonArray json2 = new JsonArray();
        List<Issue> newjson = gson.fromJson(json2, new TypeToken<List<Issue>>() {
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
                    Issue i = gson.fromJson(idata.toString(), Issue.class);
                    if (enable.contains("Yes")) {
                        i.setActive(true);
                    } else {
                        i.setActive(false);
                    }
                    newjson.clear();
                    newjson.add(i);
                    FileOutputStream fileStream = new FileOutputStream(file.getAbsoluteFile());
                    String fjson = gson.toJson(newjson);
                    OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
                    writer.write(fjson);
                    writer.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        String name = newTagCombo2.getItemAt(newTagCombo2.getSelectedIndex());
        showProfiles(name);
    }

    public void deleteTagProfiles(String tag) {

        Gson gson = new Gson();
        File f = new File(filename);

        JsonArray json2 = new JsonArray();
        List<Issue> newjson = gson.fromJson(json2, new TypeToken<List<Issue>>() {
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
                    Issue i = gson.fromJson(idata.toString(), Issue.class);
                    List<String> tags = i.getTags();
                    List<String> finaltags = new ArrayList();
                    if (tags != null) {
                        for (String dtag : tags) {
                            if (!dtag.equals(tag)) {
                                finaltags.add(dtag);
                            }
                        }
                    }
                    i.setTags(finaltags);
                    newjson.clear();
                    newjson.add(i);
                    FileOutputStream fileStream = new FileOutputStream(file.getAbsoluteFile());
                    String fjson = gson.toJson(newjson);
                    OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
                    writer.write(fjson);
                    writer.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        String name = newTagCombo2.getItemAt(newTagCombo2.getSelectedIndex());
        showProfiles(name);
    }

    public void makeTagsFile() {

        Gson gson = new Gson();
        File f = new File(filename);

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
                    Issue i = gson.fromJson(idata.toString(), Issue.class);
                    if (i.getTags() != null) {
                        tags.addAll(i.getTags());
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }

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
        File file = new File(filename + "tags.txt");
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException ex) {
                Logger.getLogger(BurpBountyGui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        List<String> existenttags = readFile(filename + "tags.txt");
        for (String tag : tags) {
            if (!existenttags.contains(tag)) {
                addNewTag(tag);
            }
        }
    }

    public void showProfiles(String Tag) {
        JsonArray json = initJson();
        //model for active profiles
        model.setNumRows(0);
        model.setColumnCount(0);
        model.addColumn("Profile");
        model.addColumn("Enabled");
        model.addColumn("Authors Twitter");

        table.getColumnModel().getColumn(0).setPreferredWidth(400);
        table.getColumnModel().getColumn(1).setPreferredWidth(5);
        table.getColumnModel().getColumn(2).setPreferredWidth(70);
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(table.getModel());
        table.setRowSorter(sorter);
        List<RowSorter.SortKey> sortKeys = new ArrayList<>();

        sortKeys.add(new RowSorter.SortKey(0, SortOrder.ASCENDING));
        sorter.setSortKeys(sortKeys);
        sorter.sort();

        //model for passive response
        model1.setNumRows(0);
        model1.setColumnCount(0);
        model1.addColumn("Profile");
        model1.addColumn("Enabled");
        model1.addColumn("Authors Twitter");

        table1.getColumnModel().getColumn(0).setPreferredWidth(400);
        table1.getColumnModel().getColumn(1).setPreferredWidth(5);
        table1.getColumnModel().getColumn(2).setPreferredWidth(70);
        TableRowSorter<TableModel> sorter1 = new TableRowSorter<>(table1.getModel());
        table1.setRowSorter(sorter1);
        List<RowSorter.SortKey> sortKeys1 = new ArrayList<>();

        sortKeys1.add(new RowSorter.SortKey(0, SortOrder.ASCENDING));
        sorter1.setSortKeys(sortKeys1);
        sorter1.sort();

        //model for passive request
        model2.setNumRows(0);
        model2.setColumnCount(0);
        model2.addColumn("Profile");
        model2.addColumn("Enabled");
        model2.addColumn("Authors Twitter");

        table2.getColumnModel().getColumn(0).setPreferredWidth(400);
        table2.getColumnModel().getColumn(1).setPreferredWidth(5);
        table2.getColumnModel().getColumn(2).setPreferredWidth(70);
        TableRowSorter<TableModel> sorter2 = new TableRowSorter<>(table2.getModel());
        table2.setRowSorter(sorter2);
        List<RowSorter.SortKey> sortKeys2 = new ArrayList<>();

        sortKeys2.add(new RowSorter.SortKey(0, SortOrder.ASCENDING));
        sorter2.setSortKeys(sortKeys2);
        sorter2.sort();

        String author = "";

        if (json != null) {
            for (JsonElement pa : json) {
                JsonObject bbObj = pa.getAsJsonObject();
                if (bbObj.has("Author")) {
                    author = bbObj.get("Author").getAsString();
                }
                JsonArray Tags = new JsonArray();
                if (bbObj.has("Tags")) {
                    Tags = bbObj.get("Tags").getAsJsonArray();
                    if (!Tags.toString().contains("All")) {
                        Tags.add("All");
                    }
                } else {
                    Tags.add("All");
                }
                for (JsonElement t : Tags) {
                    if (t.getAsString().equals(Tag)) {
                        if (bbObj.get("Scanner").getAsInt() == 1) {
                            if (bbObj.get("Active").getAsBoolean()) {
                                model.addRow(new Object[]{bbObj.get("Name").getAsString(), "Yes", author});
                            } else {
                                model.addRow(new Object[]{bbObj.get("Name").getAsString(), "No", author});
                            }
                            author = "";
                        } else if (bbObj.get("Scanner").getAsInt() == 2) {
                            if (bbObj.get("Active").getAsBoolean()) {
                                model1.addRow(new Object[]{bbObj.get("Name").getAsString(), "Yes", author});
                            } else {
                                model1.addRow(new Object[]{bbObj.get("Name").getAsString(), "No", author});
                            }
                            author = "";
                        } else if (bbObj.get("Scanner").getAsInt() == 3) {
                            if (bbObj.get("Active").getAsBoolean()) {
                                model2.addRow(new Object[]{bbObj.get("Name").getAsString(), "Yes", author});
                            } else {
                                model2.addRow(new Object[]{bbObj.get("Name").getAsString(), "No", author});
                            }
                            author = "";

                        }
                    }
                }
            }
        }
    }

    public void showHeaders(List<Headers> Header) {
        //model for active profiles
        model4.setNumRows(0);
        model4.setColumnCount(0);
        model4.addColumn("Item");
        model4.addColumn("Match");
        model4.addColumn("Replace");
        model4.addColumn("Type");
        model4.addColumn("Comment");

        table4.getColumnModel().getColumn(0).setPreferredWidth(140);
        table4.getColumnModel().getColumn(1).setPreferredWidth(400);
        table4.getColumnModel().getColumn(2).setPreferredWidth(450);
        table4.getColumnModel().getColumn(3).setPreferredWidth(120);
        table4.getColumnModel().getColumn(4).setPreferredWidth(250);
        JComboBox jcb = new JComboBox();
        jcb.addItem("Payload");
        jcb.addItem("Request");
        JComboBox jcb1 = new JComboBox();
        jcb1.addItem("String");
        jcb1.addItem("Regex");
        table4.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(jcb));
        table4.getColumnModel().getColumn(3).setCellEditor(new DefaultCellEditor(jcb1));
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(table4.getModel());
        table4.setRowSorter(sorter);
        List<RowSorter.SortKey> sortKeys = new ArrayList<>();

        sortKeys.add(new RowSorter.SortKey(0, SortOrder.DESCENDING));
        sorter.setSortKeys(sortKeys);
        sorter.sort();

        for (int i = 0; i < Header.size(); i++) {
            model4.addRow(new Object[]{Header.get(i).type, Header.get(i).match, Header.get(i).replace, Header.get(i).regex, Header.get(i).comment});
        }
    }

    public void deleteProfile(int tableIndex) {

        Gson gson = new Gson();
        File f = new File(filename);

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

        JTable finalTable = new JTable();

        if (tableIndex == 0) {
            finalTable = table;
        } else if (tableIndex == 1) {
            finalTable = table1;
        } else if (tableIndex == 2) {
            finalTable = table2;
        }

        int[] rows = finalTable.getSelectedRows();
        if (f.exists() && f.isDirectory()) {
            for (File file : files) {
                for (Integer row : rows) {
                    try {
                        JsonArray data = new JsonArray();
                        JsonReader json = new JsonReader(new FileReader(file.getAbsolutePath()));
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());

                        Object idata = data.get(0);
                        Issue i = gson.fromJson(idata.toString(), Issue.class);
                        String pname = finalTable.getValueAt(row, 0).toString();

                        if (pname.equals(i.getName())) {
                            file.delete();
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        showProfiles("All");
    }

    public String getFilename() {

        return filename;
    }

    public void swap(int a, int b) {
        Object aObject = encoder.getElementAt(a);
        Object bObject = encoder.getElementAt(b);
        encoder.set(a, bObject);
        encoder.set(b, aObject);
    }

    public void addNewTag(String str) {
        try {
            BufferedWriter out = new BufferedWriter(new FileWriter(filename + "tags.txt", true));
            out.write(str + "\n");
            out.close();
        } catch (IOException e) {
            System.out.println("exception occoured" + e);
        }
    }

    public void removeTag(String tag) {
        String file = filename + "tags.txt";
        try {

            File inFile = new File(file);

            if (!inFile.isFile()) {
                System.out.println("Parameter is not an existing file");
                return;
            }

            //Construct the new file that will later be renamed to the original filename.
            File tempFile = new File(inFile.getAbsolutePath() + ".tmp");

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
                System.out.println("Could not delete file");
                return;
            }

            //Rename the new file to the filename the original file had.
            if (!tempFile.renameTo(inFile)) {
                System.out.println("Could not rename file");
            }

        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public void showTags() {
        File file = new File(filename + "tags.txt");
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException ex) {
                Logger.getLogger(BurpBountyGui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        List<String> tags = readFile(filename + "tags.txt");
        newTagCombo.removeAllItems();
        newTagCombo2.removeAllItems();
        tagmanager.removeAllElements();
        newTagCombo2.addItem("All");
        for (String tag : tags) {
            newTagCombo.addItem(tag);
            newTagCombo2.addItem(tag);
            tagmanager.addElement(tag);
        }
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
        jButton5 = new javax.swing.JButton();
        text11 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        jTabbedPane2 = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        combo1 = new javax.swing.JComboBox<>();
        jButton2 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        text1 = new javax.swing.JTextField();
        jLabel18 = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        textauthor = new javax.swing.JTextField();
        jLabel8 = new javax.swing.JLabel();
        radio2 = new javax.swing.JRadioButton();
        radioPR = new javax.swing.JRadioButton();
        radio1 = new javax.swing.JRadioButton();
        headerstab = new javax.swing.JTabbedPane();
        jPanel10 = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        jScrollPane3 = new javax.swing.JScrollPane();
        list1 = new javax.swing.JList<>();
        button2 = new javax.swing.JButton();
        textpayloads = new javax.swing.JTextField();
        button3 = new javax.swing.JButton();
        button4 = new javax.swing.JButton();
        button5 = new javax.swing.JButton();
        button6 = new javax.swing.JButton();
        textfield1 = new javax.swing.JTextField();
        jLabel19 = new javax.swing.JLabel();
        append = new javax.swing.JRadioButton();
        replace = new javax.swing.JRadioButton();
        jLabel10 = new javax.swing.JLabel();
        check8 = new javax.swing.JCheckBox();
        text5 = new javax.swing.JTextField();
        jScrollPane4 = new javax.swing.JScrollPane();
        list3 = new javax.swing.JList<>();
        jButton9 = new javax.swing.JButton();
        jButton8 = new javax.swing.JButton();
        jButton7 = new javax.swing.JButton();
        jButton6 = new javax.swing.JButton();
        combo2 = new javax.swing.JComboBox<>();
        jSeparator2 = new javax.swing.JSeparator();
        jLabel22 = new javax.swing.JLabel();
        jLabel23 = new javax.swing.JLabel();
        jLabel52 = new javax.swing.JLabel();
        jLabel53 = new javax.swing.JLabel();
        button18 = new javax.swing.JButton();
        jScrollPane14 = new javax.swing.JScrollPane();
        table4 = new javax.swing.JTable();
        button19 = new javax.swing.JButton();
        jSeparator3 = new javax.swing.JSeparator();
        jSeparator4 = new javax.swing.JSeparator();
        jLabel54 = new javax.swing.JLabel();
        jLabel55 = new javax.swing.JLabel();
        pathdiscovery = new javax.swing.JCheckBox();
        jPanel11 = new javax.swing.JPanel();
        button8 = new javax.swing.JButton();
        button9 = new javax.swing.JButton();
        button10 = new javax.swing.JButton();
        textgreps = new javax.swing.JTextField();
        button11 = new javax.swing.JButton();
        textfield2 = new javax.swing.JTextField();
        jScrollPane2 = new javax.swing.JScrollPane();
        list2 = new javax.swing.JList<>();
        button7 = new javax.swing.JButton();
        radio12 = new javax.swing.JRadioButton();
        radio4 = new javax.swing.JRadioButton();
        radio3 = new javax.swing.JRadioButton();
        radio22 = new javax.swing.JRadioButton();
        check4 = new javax.swing.JCheckBox();
        check1 = new javax.swing.JCheckBox();
        excludehttp = new javax.swing.JCheckBox();
        onlyhttp = new javax.swing.JCheckBox();
        check71 = new javax.swing.JCheckBox();
        check72 = new javax.swing.JCheckBox();
        texttime = new javax.swing.JTextField();
        text72 = new javax.swing.JTextField();
        text71 = new javax.swing.JTextField();
        negativeCT = new javax.swing.JCheckBox();
        negativeRC = new javax.swing.JCheckBox();
        jLabel16 = new javax.swing.JLabel();
        jLabel24 = new javax.swing.JLabel();
        jLabel25 = new javax.swing.JLabel();
        jLabel26 = new javax.swing.JLabel();
        jLabel27 = new javax.swing.JLabel();
        jLabel28 = new javax.swing.JLabel();
        jLabel29 = new javax.swing.JLabel();
        jSeparator5 = new javax.swing.JSeparator();
        jLabel30 = new javax.swing.JLabel();
        jLabel31 = new javax.swing.JLabel();
        jSeparator6 = new javax.swing.JSeparator();
        rb1 = new javax.swing.JRadioButton();
        rb2 = new javax.swing.JRadioButton();
        rb3 = new javax.swing.JRadioButton();
        rb4 = new javax.swing.JRadioButton();
        jLabel2 = new javax.swing.JLabel();
        sp1 = new javax.swing.JSpinner();
        radiotime = new javax.swing.JRadioButton();
        jLabel6 = new javax.swing.JLabel();
        jSeparator11 = new javax.swing.JSeparator();
        jLabel42 = new javax.swing.JLabel();
        radiocl = new javax.swing.JRadioButton();
        textcl = new javax.swing.JTextField();
        variationsRadio = new javax.swing.JRadioButton();
        invariationsRadio = new javax.swing.JRadioButton();
        Attributes = new javax.swing.JPanel();
        status_code = new javax.swing.JCheckBox();
        input_image_labels = new javax.swing.JCheckBox();
        non_hidden_form_input_types = new javax.swing.JCheckBox();
        page_title = new javax.swing.JCheckBox();
        visible_text = new javax.swing.JCheckBox();
        button_submit_labels = new javax.swing.JCheckBox();
        div_ids = new javax.swing.JCheckBox();
        word_count = new javax.swing.JCheckBox();
        content_type = new javax.swing.JCheckBox();
        outbound_edge_tag_names = new javax.swing.JCheckBox();
        location = new javax.swing.JCheckBox();
        css_classes = new javax.swing.JCheckBox();
        last_modified_header = new javax.swing.JCheckBox();
        set_cookie_names = new javax.swing.JCheckBox();
        line_count = new javax.swing.JCheckBox();
        comments = new javax.swing.JCheckBox();
        tag_ids = new javax.swing.JCheckBox();
        header_tags = new javax.swing.JCheckBox();
        content_length = new javax.swing.JCheckBox();
        visible_word_count = new javax.swing.JCheckBox();
        whole_body_content = new javax.swing.JCheckBox();
        etag_header = new javax.swing.JCheckBox();
        first_header_tag = new javax.swing.JCheckBox();
        tag_names = new javax.swing.JCheckBox();
        input_submit_labels = new javax.swing.JCheckBox();
        outbound_edge_count = new javax.swing.JCheckBox();
        content_location = new javax.swing.JCheckBox();
        initial_body_content = new javax.swing.JCheckBox();
        limited_body_content = new javax.swing.JCheckBox();
        canonical_link = new javax.swing.JCheckBox();
        anchor_labels = new javax.swing.JCheckBox();
        jSeparator12 = new javax.swing.JSeparator();
        jPanel12 = new javax.swing.JPanel();
        jLabel32 = new javax.swing.JLabel();
        jLabel33 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        radio5 = new javax.swing.JRadioButton();
        radio6 = new javax.swing.JRadioButton();
        radio7 = new javax.swing.JRadioButton();
        radio8 = new javax.swing.JRadioButton();
        jLabel7 = new javax.swing.JLabel();
        radio9 = new javax.swing.JRadioButton();
        radio10 = new javax.swing.JRadioButton();
        radio11 = new javax.swing.JRadioButton();
        text4 = new javax.swing.JTextField();
        jSeparator7 = new javax.swing.JSeparator();
        jLabel34 = new javax.swing.JLabel();
        jLabel35 = new javax.swing.JLabel();
        jScrollPane7 = new javax.swing.JScrollPane();
        textarea2 = new javax.swing.JTextArea();
        jLabel13 = new javax.swing.JLabel();
        jLabel36 = new javax.swing.JLabel();
        jLabel37 = new javax.swing.JLabel();
        jSeparator8 = new javax.swing.JSeparator();
        jLabel38 = new javax.swing.JLabel();
        jLabel39 = new javax.swing.JLabel();
        jSeparator9 = new javax.swing.JSeparator();
        jScrollPane1 = new javax.swing.JScrollPane();
        textarea1 = new javax.swing.JTextArea();
        jLabel9 = new javax.swing.JLabel();
        jScrollPane8 = new javax.swing.JScrollPane();
        textarea3 = new javax.swing.JTextArea();
        jLabel14 = new javax.swing.JLabel();
        jLabel40 = new javax.swing.JLabel();
        jLabel41 = new javax.swing.JLabel();
        jSeparator10 = new javax.swing.JSeparator();
        jScrollPane9 = new javax.swing.JScrollPane();
        textarea4 = new javax.swing.JTextArea();
        jLabel15 = new javax.swing.JLabel();
        jPanel3 = new javax.swing.JPanel();
        removetag = new javax.swing.JButton();
        addTag = new javax.swing.JButton();
        newTagCombo = new javax.swing.JComboBox<>();
        jScrollPane11 = new javax.swing.JScrollPane();
        listtag = new javax.swing.JList<>();
        jLabel46 = new javax.swing.JLabel();
        jLabel47 = new javax.swing.JLabel();
        newTagb = new javax.swing.JButton();
        jPanel2 = new javax.swing.JPanel();
        jLabel43 = new javax.swing.JLabel();
        jLabel44 = new javax.swing.JLabel();
        jLabel45 = new javax.swing.JLabel();
        newTagCombo2 = new javax.swing.JComboBox<>();
        jtabpane = new javax.swing.JTabbedPane();
        jScrollPane5 = new javax.swing.JScrollPane();
        table = new javax.swing.JTable();
        jScrollPane6 = new javax.swing.JScrollPane();
        table1 = new javax.swing.JTable();
        jScrollPane10 = new javax.swing.JScrollPane();
        table2 = new javax.swing.JTable();
        button1 = new javax.swing.JButton();
        button12 = new javax.swing.JButton();
        button13 = new javax.swing.JButton();
        jButton4 = new javax.swing.JButton();
        jButton10 = new javax.swing.JButton();
        jPanel4 = new javax.swing.JPanel();
        jLabel48 = new javax.swing.JLabel();
        jLabel49 = new javax.swing.JLabel();
        jButton11 = new javax.swing.JButton();
        jButton12 = new javax.swing.JButton();
        jButton13 = new javax.swing.JButton();
        jScrollPane13 = new javax.swing.JScrollPane();
        listtagmanager = new javax.swing.JList<>();

        jCheckBoxMenuItem1.setSelected(true);
        jCheckBoxMenuItem1.setText("jCheckBoxMenuItem1");

        jMenuItem1.setText("jMenuItem1");

        setAutoscrolls(true);

        jButton5.setText("Profiles Directory");
        jButton5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadConfigFile(evt);
            }
        });

        text11.setToolTipText("");

        jButton1.setText("Profiles Reload");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                profilesReload(evt);
            }
        });

        jTabbedPane2.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                showprofiles(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Lucida Grande", 1, 15)); // NOI18N
        jLabel1.setText("Select Profile:");

        combo1.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        combo1.setModel(new javax.swing.DefaultComboBoxModel<>());
        combo1.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                selectAttack(evt);
            }
        });

        jButton2.setText("Save");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveAttack(evt);
            }
        });

        jButton3.setText("New Profile");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        text1.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N

        jLabel18.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel18.setText("Author:");

        jLabel12.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel12.setText("Name:");

        textauthor.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N

        jLabel8.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel8.setText("Scanner:");

        buttonGroup1.add(radio2);
        radio2.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        radio2.setText("Passive Response");
        radio2.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                SelectPassiveResponse(evt);
            }
        });

        buttonGroup1.add(radioPR);
        radioPR.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        radioPR.setText("Passive Request");
        radioPR.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                selectPassiveRequest(evt);
            }
        });

        buttonGroup1.add(radio1);
        radio1.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        radio1.setText("Active");
        radio1.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                selectActive(evt);
            }
        });

        headerstab.setAutoscrolls(true);
        headerstab.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        headerstab.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                headerstabStateChanged(evt);
            }
        });

        jPanel10.setAutoscrolls(true);
        jPanel10.setMaximumSize(new java.awt.Dimension(800, 800));
        jPanel10.setPreferredSize(new java.awt.Dimension(716, 800));

        jLabel5.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel5.setForeground(new java.awt.Color(255, 102, 51));
        jLabel5.setText("Payload Sets");

        list1.setModel(payload);
        jScrollPane3.setViewportView(list1);

        button2.setText("Paste");
        button2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pastePayload(evt);
            }
        });

        textpayloads.setToolTipText("");

        button3.setText("Load File");
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

        jLabel19.setText("You can define one or more payloads. Each payload of this section will be sent at each insertion point.");

        buttonGroup9.add(append);
        append.setText("Append");

        buttonGroup9.add(replace);
        replace.setText("Replace");

        jLabel10.setText("Payload position:");

        check8.setText("URL-Encode these characters:");

        list3.setModel(encoder);
        jScrollPane4.setViewportView(list3);

        jButton9.setText("Remove");
        jButton9.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton9removeEncoder(evt);
            }
        });

        jButton8.setText("Up");
        jButton8.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton8upEncoder(evt);
            }
        });

        jButton7.setText("Down");
        jButton7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton7downEncoder(evt);
            }
        });

        jButton6.setText("Add");
        jButton6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton6addEncoder(evt);
            }
        });

        combo2.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "URL-encode key characters", "URL-encode all characters", "URL-encode all characters (Unicode)", "HTML-encode key characters", "HTML-encode all characters", "Base64-encode" }));

        jLabel22.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel22.setForeground(new java.awt.Color(255, 102, 51));
        jLabel22.setText("Payload Encoding");

        jLabel23.setText("You can define the encoding of payloads. You can encode each payload multiple times.");

        jLabel52.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel52.setForeground(new java.awt.Color(255, 102, 51));
        jLabel52.setText("Match and Replace");

        jLabel53.setText("These settings are used to automatically replace part of request when the active scanner run.");

        button18.setText("Remove");
        button18.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeMatchReplace(evt);
            }
        });

        table4.setFont(new java.awt.Font("Lucida Grande", 0, 13)); // NOI18N
        table4.setModel(model4);
        table4.setShowGrid(false);
        jScrollPane14.setViewportView(table4);

        button19.setText("Add");
        button19.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addMatchReplace(evt);
            }
        });

        jLabel54.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel54.setForeground(new java.awt.Color(255, 102, 51));
        jLabel54.setText("Payload Options");

        jLabel55.setText("You can define the payload options.");

        pathdiscovery.setText("Path discovery");

        javax.swing.GroupLayout jPanel10Layout = new javax.swing.GroupLayout(jPanel10);
        jPanel10.setLayout(jPanel10Layout);
        jPanel10Layout.setHorizontalGroup(
            jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel10Layout.createSequentialGroup()
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jSeparator2)
                    .addComponent(jSeparator3)
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addGroup(jPanel10Layout.createSequentialGroup()
                                    .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(jPanel10Layout.createSequentialGroup()
                                            .addGap(12, 12, 12)
                                            .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                    .addComponent(button3, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                    .addComponent(button4, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE))
                                                .addComponent(button5, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel10Layout.createSequentialGroup()
                                            .addContainerGap()
                                            .addComponent(button2, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                    .addGap(18, 18, 18)
                                    .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(textpayloads)
                                        .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 591, Short.MAX_VALUE)))
                                .addGroup(jPanel10Layout.createSequentialGroup()
                                    .addComponent(button6, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGap(18, 18, 18)
                                    .addComponent(textfield1, javax.swing.GroupLayout.PREFERRED_SIZE, 591, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addGroup(jPanel10Layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jLabel22)
                                    .addComponent(jLabel23, javax.swing.GroupLayout.PREFERRED_SIZE, 704, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel54)
                                    .addComponent(jLabel55, javax.swing.GroupLayout.PREFERRED_SIZE, 704, javax.swing.GroupLayout.PREFERRED_SIZE))))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel10Layout.createSequentialGroup()
                                .addGap(6, 6, 6)
                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel10Layout.createSequentialGroup()
                                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(button18, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(button19, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGap(18, 18, 18)
                                        .addComponent(jScrollPane14, javax.swing.GroupLayout.PREFERRED_SIZE, 830, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addComponent(jLabel53, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 704, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel52, javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel10Layout.createSequentialGroup()
                                            .addComponent(check8)
                                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                            .addComponent(text5))
                                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel10Layout.createSequentialGroup()
                                            .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                                .addComponent(jButton9, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(jButton6, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(jButton8, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(jButton7, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE))
                                            .addGap(12, 12, 12)
                                            .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                                .addComponent(jScrollPane4)
                                                .addComponent(combo2, 0, 447, Short.MAX_VALUE)))))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 13, Short.MAX_VALUE))
                            .addGroup(jPanel10Layout.createSequentialGroup()
                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel5)
                                    .addComponent(jLabel19, javax.swing.GroupLayout.PREFERRED_SIZE, 704, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGroup(jPanel10Layout.createSequentialGroup()
                                        .addGap(27, 27, 27)
                                        .addComponent(jLabel10)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                            .addComponent(append)
                                            .addComponent(replace))
                                        .addGap(68, 68, 68)
                                        .addComponent(pathdiscovery)))
                                .addGap(0, 0, Short.MAX_VALUE))))
                    .addComponent(jSeparator4))
                .addContainerGap())
        );

        jPanel10Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {combo2, jScrollPane4});

        jPanel10Layout.setVerticalGroup(
            jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel10Layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addComponent(jLabel5)
                .addGap(12, 12, 12)
                .addComponent(jLabel19)
                .addGap(27, 27, 27)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(textpayloads, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(button3))
                .addGap(25, 25, 25)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addComponent(button2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button4)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button5))
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 111, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(button6)
                    .addComponent(textfield1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel54)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel55)
                .addGap(19, 19, 19)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(replace)
                            .addComponent(pathdiscovery))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(append))
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGap(17, 17, 17)
                        .addComponent(jLabel10)))
                .addGap(18, 18, 18)
                .addComponent(jSeparator4, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel52)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel53)
                .addGap(18, 18, 18)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addComponent(button19)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button18))
                    .addComponent(jScrollPane14, javax.swing.GroupLayout.PREFERRED_SIZE, 190, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator3, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel22)
                .addGap(12, 12, 12)
                .addComponent(jLabel23)
                .addGap(18, 18, 18)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addComponent(jButton9)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton8)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton7))
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(combo2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton6))
                .addGap(19, 19, 19)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(check8)
                    .addComponent(text5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        headerstab.addTab("          Request          ", jPanel10);

        jPanel11.setAutoscrolls(true);

        button8.setText("Load File");
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

        button11.setText("Add");
        button11.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                setToGrep(evt);
            }
        });

        list2.setModel(grep);
        jScrollPane2.setViewportView(list2);

        button7.setText("Paste");
        button7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pasteGrep(evt);
            }
        });

        buttonGroup4.add(radio12);
        radio12.setText("Payload");
        radio12.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                payloadMatchType(evt);
            }
        });

        buttonGroup4.add(radio4);
        radio4.setText("Simple string");
        radio4.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                stringMatchType(evt);
            }
        });

        buttonGroup4.add(radio3);
        radio3.setText("Regex");
        radio3.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                regexMatchType(evt);
            }
        });

        buttonGroup4.add(radio22);
        radio22.setText("Payload without encode");
        radio22.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                payloadencodeMatchType(evt);
            }
        });

        check4.setText("Negative match");

        check1.setText("Case sensitive");

        excludehttp.setText("Exclude HTTP headers");

        onlyhttp.setText("Only in HTTP headers");

        check71.setText("Content type");

        check72.setText("Status code");

        negativeCT.setText("Negative match");

        negativeRC.setText("Negative match");

        jLabel16.setText("Seconds");

        jLabel24.setText("You can define one or more greps. For each payload response, each grep will be searched with specific grep options.");

        jLabel25.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel25.setForeground(new java.awt.Color(255, 102, 51));
        jLabel25.setText("Grep Sets");

        jLabel26.setText("You can define grep type.");

        jLabel27.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel27.setForeground(new java.awt.Color(255, 102, 51));
        jLabel27.setText("Match Type");

        jLabel28.setText("You can define how your profile handles redirections.");

        jLabel29.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel29.setForeground(new java.awt.Color(255, 102, 51));
        jLabel29.setText("Redirections");

        jLabel30.setText("These settings can be used to specify grep options of your profile.");

        jLabel31.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel31.setForeground(new java.awt.Color(255, 102, 51));
        jLabel31.setText("Grep Options");

        buttonGroup8.add(rb1);
        rb1.setText("Never");

        buttonGroup8.add(rb2);
        rb2.setText("On-site only");

        buttonGroup8.add(rb3);
        rb3.setText("In-scope only");

        buttonGroup8.add(rb4);
        rb4.setText("Always");

        jLabel2.setText("Max redirections:");

        buttonGroup4.add(radiotime);
        radiotime.setText("Timeout equal or more than ");
        radiotime.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                TimeoutSelect(evt);
            }
        });

        jLabel6.setText("Follow redirections: ");

        jLabel42.setText("Bytes");

        buttonGroup4.add(radiocl);
        radiocl.setText("Content Length difference");
        radiocl.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                radioclSelect(evt);
            }
        });
        radiocl.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                radioclActionPerformed(evt);
            }
        });

        buttonGroup4.add(variationsRadio);
        variationsRadio.setText("Variations");
        variationsRadio.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                variations(evt);
            }
        });

        buttonGroup4.add(invariationsRadio);
        invariationsRadio.setText("Invariations");
        invariationsRadio.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                invariations(evt);
            }
        });

        Attributes.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Attributes", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.TOP));

        status_code.setText("status_code");

        input_image_labels.setText("input_image_labels");

        non_hidden_form_input_types.setText("non_hidden_form_input_types");

        page_title.setText("page_title");

        visible_text.setText("visible_text");

        button_submit_labels.setText("button_submit_labels");

        div_ids.setText("div_ids");

        word_count.setText("word_count");

        content_type.setText("content_type");

        outbound_edge_tag_names.setText("outbound_edge_tag_names");

        location.setText("location");

        css_classes.setText("css_classes");

        last_modified_header.setText("last_modified_header");

        set_cookie_names.setText("set_cookie_names");

        line_count.setText("line_count");

        comments.setText("comments");

        tag_ids.setText("tag_ids");

        header_tags.setText("header_tags");

        content_length.setText("content_length");

        visible_word_count.setText("visible_word_count");

        whole_body_content.setText("whole_body_content");

        etag_header.setText("etag_header");

        first_header_tag.setText("first_header_tag");

        tag_names.setText("tag_names");

        input_submit_labels.setText("input_submit_labels");

        outbound_edge_count.setText("outbound_edge_count");

        content_location.setText("content_location");

        initial_body_content.setText("initial_body_content");

        limited_body_content.setText("limited_body_content");

        canonical_link.setText("canonical_link");

        anchor_labels.setText("anchor_labels");

        javax.swing.GroupLayout AttributesLayout = new javax.swing.GroupLayout(Attributes);
        Attributes.setLayout(AttributesLayout);
        AttributesLayout.setHorizontalGroup(
            AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(AttributesLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(page_title)
                    .addComponent(non_hidden_form_input_types)
                    .addComponent(input_image_labels)
                    .addComponent(status_code)
                    .addComponent(visible_text)
                    .addComponent(word_count)
                    .addComponent(div_ids)
                    .addComponent(button_submit_labels))
                .addGap(18, 18, 18)
                .addGroup(AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(content_type)
                    .addComponent(outbound_edge_tag_names)
                    .addComponent(anchor_labels)
                    .addComponent(etag_header)
                    .addComponent(whole_body_content)
                    .addComponent(content_length)
                    .addComponent(visible_word_count)
                    .addComponent(header_tags))
                .addGap(18, 18, 18)
                .addGroup(AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(input_submit_labels)
                    .addGroup(AttributesLayout.createSequentialGroup()
                        .addGroup(AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(tag_names)
                            .addComponent(first_header_tag)
                            .addComponent(set_cookie_names)
                            .addComponent(line_count)
                            .addComponent(comments)
                            .addComponent(tag_ids)
                            .addComponent(last_modified_header))
                        .addGap(18, 18, 18)
                        .addGroup(AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(outbound_edge_count)
                            .addComponent(initial_body_content)
                            .addComponent(css_classes)
                            .addComponent(canonical_link)
                            .addComponent(limited_body_content)
                            .addComponent(content_location)
                            .addComponent(location))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        AttributesLayout.setVerticalGroup(
            AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(AttributesLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(AttributesLayout.createSequentialGroup()
                        .addComponent(outbound_edge_count)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(initial_body_content)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(content_location)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(limited_body_content)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(canonical_link)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(css_classes)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(location)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(AttributesLayout.createSequentialGroup()
                        .addGroup(AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(AttributesLayout.createSequentialGroup()
                                .addGroup(AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(AttributesLayout.createSequentialGroup()
                                        .addComponent(content_type)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(outbound_edge_tag_names)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(anchor_labels)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(whole_body_content)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(etag_header))
                                    .addGroup(AttributesLayout.createSequentialGroup()
                                        .addComponent(tag_ids)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(comments)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(line_count)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(set_cookie_names)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(last_modified_header)))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(AttributesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(AttributesLayout.createSequentialGroup()
                                        .addComponent(visible_word_count)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(content_length)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(header_tags))
                                    .addGroup(AttributesLayout.createSequentialGroup()
                                        .addComponent(first_header_tag)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(tag_names)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(input_submit_labels))))
                            .addGroup(AttributesLayout.createSequentialGroup()
                                .addComponent(status_code)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(input_image_labels)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(non_hidden_form_input_types)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(page_title)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(visible_text)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(button_submit_labels)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(div_ids)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(word_count)))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
        );

        javax.swing.GroupLayout jPanel11Layout = new javax.swing.GroupLayout(jPanel11);
        jPanel11.setLayout(jPanel11Layout);
        jPanel11Layout.setHorizontalGroup(
            jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSeparator5)
            .addComponent(jSeparator6, javax.swing.GroupLayout.Alignment.TRAILING)
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addGap(8, 8, 8)
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel11Layout.createSequentialGroup()
                                .addComponent(button8, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(textgreps, javax.swing.GroupLayout.PREFERRED_SIZE, 591, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanel11Layout.createSequentialGroup()
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(button7, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(button9, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 87, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(button10, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(button11, javax.swing.GroupLayout.PREFERRED_SIZE, 87, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(textfield2, javax.swing.GroupLayout.PREFERRED_SIZE, 442, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 591, javax.swing.GroupLayout.PREFERRED_SIZE)))))
                    .addComponent(jLabel25)
                    .addComponent(jLabel24, javax.swing.GroupLayout.PREFERRED_SIZE, 769, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel27)
                    .addComponent(jLabel26, javax.swing.GroupLayout.PREFERRED_SIZE, 769, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(Attributes, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(variationsRadio))
                .addGap(0, 0, Short.MAX_VALUE))
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addComponent(jSeparator12, javax.swing.GroupLayout.DEFAULT_SIZE, 4, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator11, javax.swing.GroupLayout.PREFERRED_SIZE, 952, javax.swing.GroupLayout.PREFERRED_SIZE))
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(radio12)
                        .addGap(151, 151, 151)
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(radio22)
                            .addComponent(invariationsRadio)))
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(radio4)
                            .addComponent(radio3))
                        .addGap(116, 116, 116)
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(radiotime)
                            .addComponent(radiocl))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(texttime, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(textcl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel16, javax.swing.GroupLayout.PREFERRED_SIZE, 62, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel42, javax.swing.GroupLayout.PREFERRED_SIZE, 62, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addGap(20, 20, 20)
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel6)
                            .addComponent(jLabel2))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(rb1)
                            .addComponent(rb2)
                            .addComponent(rb3)
                            .addComponent(rb4)
                            .addComponent(sp1, javax.swing.GroupLayout.PREFERRED_SIZE, 56, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel31)
                            .addComponent(jLabel30, javax.swing.GroupLayout.PREFERRED_SIZE, 769, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(onlyhttp)
                            .addComponent(check4)
                            .addComponent(check1)
                            .addComponent(excludehttp)
                            .addGroup(jPanel11Layout.createSequentialGroup()
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(check72)
                                    .addComponent(check71))
                                .addGap(15, 15, 15)
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(text71, javax.swing.GroupLayout.DEFAULT_SIZE, 347, Short.MAX_VALUE)
                                    .addComponent(text72))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(negativeCT, javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(negativeRC, javax.swing.GroupLayout.Alignment.TRAILING)))
                            .addComponent(jLabel29)
                            .addComponent(jLabel28, javax.swing.GroupLayout.PREFERRED_SIZE, 769, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel11Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {jScrollPane2, textfield2, textgreps});

        jPanel11Layout.setVerticalGroup(
            jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel27)
                .addGap(12, 12, 12)
                .addComponent(jLabel26)
                .addGap(18, 18, 18)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addComponent(radio4)
                        .addGap(18, 18, 18)
                        .addComponent(radio3)
                        .addGap(18, 18, 18)
                        .addComponent(radio12))
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(radiotime)
                            .addComponent(texttime, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel16))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(radiocl)
                            .addComponent(jLabel42)
                            .addComponent(textcl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(radio22)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(variationsRadio)
                    .addComponent(invariationsRadio))
                .addGap(18, 18, 18)
                .addComponent(Attributes, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jSeparator12)
                    .addComponent(jSeparator11))
                .addGap(18, 18, 18)
                .addComponent(jLabel25)
                .addGap(12, 12, 12)
                .addComponent(jLabel24)
                .addGap(32, 32, 32)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(textgreps, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(button8))
                .addGap(26, 26, 26)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addComponent(button7)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button9)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button10))
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 111, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(textfield2, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(button11))
                .addGap(18, 18, 18)
                .addComponent(jSeparator6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel31)
                .addGap(12, 12, 12)
                .addComponent(jLabel30)
                .addGap(18, 18, 18)
                .addComponent(check4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(check1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(excludehttp)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(onlyhttp)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(check71)
                    .addComponent(text71, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(negativeCT))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(check72)
                    .addComponent(text72, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(negativeRC))
                .addGap(18, 18, 18)
                .addComponent(jSeparator5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel29)
                .addGap(12, 12, 12)
                .addComponent(jLabel28)
                .addGap(18, 18, 18)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(rb1)
                    .addComponent(jLabel6))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(rb2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(rb3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(rb4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(sp1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel11Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {textcl, texttime});

        headerstab.addTab("          Response          ", jPanel11);
        jPanel11.getAccessibleContext().setAccessibleName("");

        jPanel12.setAutoscrolls(true);

        jLabel32.setText("You can define the issue properties.");

        jLabel33.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel33.setForeground(new java.awt.Color(255, 102, 51));
        jLabel33.setText("Issue Properties");

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

        jLabel34.setText("You can define the issue details.");

        jLabel35.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel35.setForeground(new java.awt.Color(255, 102, 51));
        jLabel35.setText("Issue Detail");

        textarea2.setColumns(20);
        textarea2.setRows(5);
        jScrollPane7.setViewportView(textarea2);

        jLabel13.setText("Description:");

        jLabel36.setText("You can define the issue background.");

        jLabel37.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel37.setForeground(new java.awt.Color(255, 102, 51));
        jLabel37.setText("Issue Background");

        jLabel38.setText("You can define the remediation detail.");

        jLabel39.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel39.setForeground(new java.awt.Color(255, 102, 51));
        jLabel39.setText("Remediation Detail");

        textarea1.setColumns(20);
        textarea1.setRows(5);
        jScrollPane1.setViewportView(textarea1);

        jLabel9.setText("Description:");

        textarea3.setColumns(20);
        textarea3.setRows(5);
        jScrollPane8.setViewportView(textarea3);

        jLabel14.setText("Description:");

        jLabel40.setText("You can define the remediation background.");

        jLabel41.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel41.setForeground(new java.awt.Color(255, 102, 51));
        jLabel41.setText("Remediation Background");

        textarea4.setColumns(20);
        textarea4.setRows(5);
        jScrollPane9.setViewportView(textarea4);

        jLabel15.setText("Description:");

        javax.swing.GroupLayout jPanel12Layout = new javax.swing.GroupLayout(jPanel12);
        jPanel12.setLayout(jPanel12Layout);
        jPanel12Layout.setHorizontalGroup(
            jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel12Layout.createSequentialGroup()
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel12Layout.createSequentialGroup()
                        .addComponent(jSeparator7)
                        .addGap(6, 6, 6))
                    .addComponent(jSeparator10)
                    .addComponent(jLabel41)
                    .addComponent(jLabel40)
                    .addGroup(jPanel12Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jSeparator8, javax.swing.GroupLayout.DEFAULT_SIZE, 950, Short.MAX_VALUE)
                            .addComponent(jSeparator9)
                            .addComponent(jLabel33)
                            .addComponent(jLabel35)
                            .addComponent(jLabel34)
                            .addGroup(jPanel12Layout.createSequentialGroup()
                                .addComponent(jLabel13)
                                .addGap(18, 18, 18)
                                .addComponent(jScrollPane7, javax.swing.GroupLayout.PREFERRED_SIZE, 612, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanel12Layout.createSequentialGroup()
                                .addComponent(jLabel9)
                                .addGap(18, 18, 18)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 612, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanel12Layout.createSequentialGroup()
                                .addComponent(jLabel15)
                                .addGap(18, 18, 18)
                                .addComponent(jScrollPane9, javax.swing.GroupLayout.PREFERRED_SIZE, 612, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanel12Layout.createSequentialGroup()
                                .addComponent(jLabel14)
                                .addGap(18, 18, 18)
                                .addComponent(jScrollPane8, javax.swing.GroupLayout.PREFERRED_SIZE, 612, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jLabel37)
                            .addComponent(jLabel36)
                            .addComponent(jLabel39)
                            .addComponent(jLabel38)
                            .addComponent(jLabel32)
                            .addGroup(jPanel12Layout.createSequentialGroup()
                                .addComponent(jLabel3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addGroup(jPanel12Layout.createSequentialGroup()
                                        .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addGroup(jPanel12Layout.createSequentialGroup()
                                                .addComponent(radio8)
                                                .addGap(189, 189, 189))
                                            .addGroup(jPanel12Layout.createSequentialGroup()
                                                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                    .addComponent(radio6)
                                                    .addComponent(radio7)
                                                    .addComponent(radio5))
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(jLabel7)
                                                .addGap(18, 18, 18)
                                                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                    .addComponent(radio9)
                                                    .addComponent(radio11)
                                                    .addComponent(radio10)))))
                                    .addComponent(text4, javax.swing.GroupLayout.PREFERRED_SIZE, 419, javax.swing.GroupLayout.PREFERRED_SIZE))))))
                .addContainerGap())
        );
        jPanel12Layout.setVerticalGroup(
            jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel12Layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addComponent(jLabel33)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel32)
                .addGap(18, 18, 18)
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(text4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel12Layout.createSequentialGroup()
                        .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel7)
                            .addComponent(radio9))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(radio10)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(radio11))
                    .addGroup(jPanel12Layout.createSequentialGroup()
                        .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel4)
                            .addComponent(radio5))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(radio6)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(radio7)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(radio8)))
                .addGap(18, 18, 18)
                .addComponent(jSeparator7, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel35)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel34)
                .addGap(18, 18, 18)
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel9)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator8, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel37)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel36)
                .addGap(18, 18, 18)
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel13)
                    .addComponent(jScrollPane7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator9, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel39)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel38)
                .addGap(18, 18, 18)
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel15)
                    .addComponent(jScrollPane9, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator10, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel41)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel40)
                .addGap(18, 18, 18)
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel14)
                    .addComponent(jScrollPane8, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        headerstab.addTab("          Issue          ", jPanel12);

        removetag.setText("Remove");
        removetag.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removetag(evt);
            }
        });

        addTag.setText("Add");
        addTag.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addTag(evt);
            }
        });

        listtag.setModel(tag);
        jScrollPane11.setViewportView(listtag);

        jLabel46.setText("You can define one or multiple tags for this profile.");

        jLabel47.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel47.setForeground(new java.awt.Color(255, 102, 51));
        jLabel47.setText("Set Tags");

        newTagb.setText("New Tag");
        newTagb.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newTag(evt);
            }
        });

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel47)
                    .addComponent(jLabel46)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(newTagb, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(addTag, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(removetag, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(18, 18, 18)
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jScrollPane11)
                            .addComponent(newTagCombo, javax.swing.GroupLayout.PREFERRED_SIZE, 468, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel3Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {addTag, newTagb, removetag});

        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addComponent(jLabel47)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel46)
                .addGap(18, 18, 18)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane11, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addComponent(newTagb)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(removetag)))
                .addGap(18, 18, 18)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(newTagCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(addTag))
                .addContainerGap(1087, Short.MAX_VALUE))
        );

        headerstab.addTab("          Tags          ", jPanel3);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(headerstab, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(combo1, javax.swing.GroupLayout.PREFERRED_SIZE, 590, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton2)
                        .addGap(18, 18, 18)
                        .addComponent(jButton3, javax.swing.GroupLayout.PREFERRED_SIZE, 101, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel12)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(text1, javax.swing.GroupLayout.PREFERRED_SIZE, 265, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(38, 38, 38)
                        .addComponent(jLabel18)
                        .addGap(18, 18, 18)
                        .addComponent(textauthor, javax.swing.GroupLayout.PREFERRED_SIZE, 211, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(35, 35, 35)
                        .addComponent(jLabel8)
                        .addGap(18, 18, 18)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(radio1)
                            .addComponent(radio2)
                            .addComponent(radioPR))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel1Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {jButton2, jButton3});

        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(combo1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1)
                    .addComponent(jButton2)
                    .addComponent(jButton3))
                .addGap(22, 22, 22)
                .addComponent(radio1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(radio2)
                    .addComponent(text1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel12)
                    .addComponent(jLabel8)
                    .addComponent(jLabel18)
                    .addComponent(textauthor, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(radioPR)
                .addGap(18, 18, 18)
                .addComponent(headerstab, javax.swing.GroupLayout.PREFERRED_SIZE, 1361, Short.MAX_VALUE)
                .addContainerGap())
        );

        jTabbedPane2.addTab("   Profiles Definition   ", jPanel1);

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

        table.setAutoCreateRowSorter(true);
        table.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        table.setModel(model);
        table.setRowSorter(null);
        table.getTableHeader().setReorderingAllowed(false);
        jScrollPane5.setViewportView(table);

        jtabpane.addTab("Active Profiles", jScrollPane5);

        table1.setAutoCreateRowSorter(true);
        table1.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        table1.setModel(model1);
        table1.setRowSorter(null);
        table1.getTableHeader().setReorderingAllowed(false);
        jScrollPane6.setViewportView(table1);

        jtabpane.addTab("Passive Response Profiles", jScrollPane6);

        table2.setAutoCreateRowSorter(true);
        table2.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        table2.setModel(model2);
        table2.setRowSorter(null);
        table2.getTableHeader().setReorderingAllowed(false);
        jScrollPane10.setViewportView(table2);

        jtabpane.addTab("Passive Request Profiles", jScrollPane10);

        button1.setText("Enable");
        button1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button1setProfileEnable(evt);
            }
        });

        button12.setText("Disable");
        button12.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button12SetDisableProfiles(evt);
            }
        });

        button13.setText("Remove");
        button13.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button13DeleteItem(evt);
            }
        });

        jButton4.setText("Enable All");
        jButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enableAll(evt);
            }
        });

        jButton10.setText("Disable All");
        jButton10.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                disableAll(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(249, 249, 249)
                        .addComponent(jLabel45)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(newTagCombo2, javax.swing.GroupLayout.PREFERRED_SIZE, 325, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(25, 25, 25)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel2Layout.createSequentialGroup()
                                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(button12, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(jButton4, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                                    .addComponent(jButton10, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                                    .addComponent(button1, javax.swing.GroupLayout.PREFERRED_SIZE, 103, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(button13, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addGap(18, 18, 18)
                                .addComponent(jtabpane, javax.swing.GroupLayout.PREFERRED_SIZE, 704, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jLabel44, javax.swing.GroupLayout.PREFERRED_SIZE, 575, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel43))))
                .addContainerGap(133, Short.MAX_VALUE))
        );

        jPanel2Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {button1, button12, button13, jButton10, jButton4});

        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addComponent(jLabel43)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel44)
                .addGap(36, 36, 36)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(newTagCombo2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel45))
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(52, 52, 52)
                        .addComponent(button1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button12)
                        .addGap(18, 18, 18)
                        .addComponent(jButton4)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton10)
                        .addGap(18, 18, 18)
                        .addComponent(button13))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(18, 18, 18)
                        .addComponent(jtabpane, javax.swing.GroupLayout.PREFERRED_SIZE, 543, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(776, Short.MAX_VALUE))
        );

        jTabbedPane2.addTab("   Profiles Manager   ", jPanel2);

        jLabel48.setText("In this section you can manage the tags. You can delete tags, add, etc ");

        jLabel49.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel49.setForeground(new java.awt.Color(255, 102, 51));
        jLabel49.setText("Tags Manager");

        jButton11.setText("New");
        jButton11.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newTagManager(evt);
            }
        });

        jButton12.setText("Remove");
        jButton12.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeTagManager(evt);
            }
        });

        jButton13.setText("Delete tag for all profiles");
        jButton13.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteTagmanager(evt);
            }
        });

        listtagmanager.setModel(tagmanager);
        jScrollPane13.setViewportView(listtagmanager);

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel48, javax.swing.GroupLayout.PREFERRED_SIZE, 575, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel49)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jButton11)
                            .addComponent(jButton12))
                        .addGap(18, 18, 18)
                        .addComponent(jScrollPane13, javax.swing.GroupLayout.PREFERRED_SIZE, 333, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jButton13)))
                .addContainerGap(314, Short.MAX_VALUE))
        );

        jPanel4Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {jButton11, jButton12});

        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel49)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel48)
                .addGap(36, 36, 36)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(jButton11)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton12))
                    .addComponent(jButton13)
                    .addComponent(jScrollPane13, javax.swing.GroupLayout.PREFERRED_SIZE, 296, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(1076, Short.MAX_VALUE))
        );

        jTabbedPane2.addTab("   Tags Manager   ", jPanel4);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTabbedPane2)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(92, 92, 92)
                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 127, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jButton5, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(text11, javax.swing.GroupLayout.PREFERRED_SIZE, 440, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(18, 18, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton5)
                    .addComponent(text11, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton1))
                .addGap(48, 48, 48)
                .addComponent(jTabbedPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 1499, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void selectAttack(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_selectAttack
        if ((evt.getStateChange() == java.awt.event.ItemEvent.SELECTED)) {
            String name = combo1.getItemAt(combo1.getSelectedIndex());
            setAttackValues(name);
        }
    }//GEN-LAST:event_selectAttack

    private void saveAttack(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveAttack
        saveAttackValues();
        initCombo();
    }//GEN-LAST:event_saveAttack

    private void loadConfigFile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadConfigFile
        loadConfigFile();
        makeTagsFile();
        showTags();
    }//GEN-LAST:event_loadConfigFile

    private void profilesReload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_profilesReload
        initCombo();
        makeTagsFile();
        showTags();
    }//GEN-LAST:event_profilesReload

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        clear();
    }//GEN-LAST:event_jButton3ActionPerformed

    private void SelectPassiveResponse(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_SelectPassiveResponse
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            headerstab.setSelectedIndex(1);
            headerstab.setEnabledAt(0, false);
            radio12.setEnabled(false);
            radio22.setEnabled(false);
            radiotime.setEnabled(false);
            texttime.setEnabled(false);
            jLabel16.setEnabled(false);
            texttime.setEnabled(false);
            check71.setEnabled(true);
            check72.setEnabled(true);
            text71.setEnabled(true);
            text72.setEnabled(true);
            negativeCT.setEnabled(true);
            negativeRC.setEnabled(true);
            rb1.setEnabled(false);
            rb2.setEnabled(false);
            rb3.setEnabled(false);
            rb4.setEnabled(false);
            jLabel6.setEnabled(false);
            jLabel2.setEnabled(false);
            sp1.setEnabled(false);
            jLabel28.setEnabled(false);
            jLabel29.setEnabled(false);
            radiocl.setEnabled(false);
            textcl.setEnabled(false);
            jLabel42.setEnabled(false);
            variationsRadio.setEnabled(false);
            invariationsRadio.setEnabled(false);
            setEnabledVariations(false);
        }
    }//GEN-LAST:event_SelectPassiveResponse

    private void selectActive(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_selectActive
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            headerstab.setEnabledAt(0, true);
            radio12.setEnabled(true);
            radio22.setEnabled(true);
            radiotime.setEnabled(true);
            texttime.setEnabled(true);
            jLabel16.setEnabled(true);
            check71.setEnabled(true);
            check72.setEnabled(true);
            text71.setEnabled(true);
            text72.setEnabled(true);
            negativeCT.setEnabled(true);
            negativeRC.setEnabled(true);
            rb1.setEnabled(true);
            rb2.setEnabled(true);
            rb3.setEnabled(true);
            rb4.setEnabled(true);
            jLabel6.setEnabled(true);
            jLabel2.setEnabled(true);
            sp1.setEnabled(true);
            jLabel28.setEnabled(true);
            jLabel29.setEnabled(true);
            radiocl.setEnabled(true);
            textcl.setEnabled(true);
            jLabel42.setEnabled(true);
            variationsRadio.setEnabled(true);
            invariationsRadio.setEnabled(true);
            if (variationsRadio.isSelected() || invariationsRadio.isSelected()) {
                setEnabledVariations(true);
            }

        }
    }//GEN-LAST:event_selectActive

    private void selectPassiveRequest(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_selectPassiveRequest
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            headerstab.setSelectedIndex(1);
            headerstab.setEnabledAt(0, false);
            radio12.setEnabled(false);
            radio22.setEnabled(false);
            radiotime.setEnabled(false);
            texttime.setEnabled(false);
            jLabel16.setEnabled(false);
            check71.setEnabled(false);
            check72.setEnabled(false);
            text71.setEnabled(false);
            text72.setEnabled(false);
            negativeCT.setEnabled(false);
            negativeRC.setEnabled(false);
            rb1.setEnabled(false);
            rb2.setEnabled(false);
            rb3.setEnabled(false);
            rb4.setEnabled(false);
            jLabel6.setEnabled(false);
            jLabel2.setEnabled(false);
            sp1.setEnabled(false);
            jLabel28.setEnabled(false);
            jLabel29.setEnabled(false);
            radiocl.setEnabled(false);
            textcl.setEnabled(false);
            jLabel42.setEnabled(false);
            variationsRadio.setEnabled(false);
            invariationsRadio.setEnabled(false);
            setEnabledVariations(false);
        }
    }//GEN-LAST:event_selectPassiveRequest

    private void newTagCombo2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newTagCombo2ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_newTagCombo2ActionPerformed

    private void button1setProfileEnable(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button1setProfileEnable
        int activePane = jtabpane.getSelectedIndex();

        if (activePane == 0) {
            setEnableDisableProfile("Yes", 0);
        } else if (activePane == 1) {
            setEnableDisableProfile("Yes", 1);
        } else if (activePane == 2) {
            setEnableDisableProfile("Yes", 2);
        }
        initCombo();

    }//GEN-LAST:event_button1setProfileEnable

    private void button12SetDisableProfiles(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button12SetDisableProfiles
        int activePane = jtabpane.getSelectedIndex();

        if (activePane == 0) {
            setEnableDisableProfile("No", 0);
        } else if (activePane == 1) {
            setEnableDisableProfile("No", 1);
        } else if (activePane == 2) {
            setEnableDisableProfile("No", 2);
        }
        initCombo();
    }//GEN-LAST:event_button12SetDisableProfiles

    private void button13DeleteItem(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button13DeleteItem
        int activePane = jtabpane.getSelectedIndex();

        if (activePane == 0) {
            deleteProfile(0);
        } else if (activePane == 1) {
            deleteProfile(1);
        } else if (activePane == 2) {
            deleteProfile(2);
        }
        initCombo();
    }//GEN-LAST:event_button13DeleteItem

    private void showprofiles(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_showprofiles
        if (jTabbedPane2.isShowing()) {
            showProfiles("All");
            showTags();
        }
    }//GEN-LAST:event_showprofiles

    private void enableAll(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_enableAll
        setEnableDisableAllProfiles("Yes");
        initCombo();
    }//GEN-LAST:event_enableAll

    private void selectTag(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_selectTag
        if ((evt.getStateChange() == java.awt.event.ItemEvent.SELECTED)) {
            String name = newTagCombo2.getItemAt(newTagCombo2.getSelectedIndex());
            showProfiles(name);
        }
    }//GEN-LAST:event_selectTag

    private void disableAll(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disableAll
        setEnableDisableAllProfiles("No");
        initCombo();
    }//GEN-LAST:event_disableAll

    private void newTagManager(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newTagManager
        NewTag nt = new NewTag();
        int result = JOptionPane.showOptionDialog(this, nt, "New Tag", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, null, null);
        if (result == JOptionPane.OK_OPTION) {
            String newTag = nt.newTagtext.getText();
            addNewTag(newTag);
            showTags();
        }
    }//GEN-LAST:event_newTagManager

    private void removeTagManager(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeTagManager
        int selectedIndex = listtagmanager.getSelectedIndex();
        String tag = "";
        if (selectedIndex != -1) {
            tag = tagmanager.get(selectedIndex).toString();
            tagmanager.remove(selectedIndex);
        }
        removeTag(tag);
        showTags();
    }//GEN-LAST:event_removeTagManager

    private void deleteTagmanager(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteTagmanager
        int selectedIndex = listtagmanager.getSelectedIndex();
        String tag = "";
        if (selectedIndex != -1) {
            tag = tagmanager.get(selectedIndex).toString();
            tagmanager.remove(selectedIndex);
        }
        deleteTagProfiles(tag);
        removeTag(tag);
        showTags();
    }//GEN-LAST:event_deleteTagmanager

    private void headerstabStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_headerstabStateChanged
        int activePane = headerstab.getSelectedIndex();
        if (activePane == 3) {
            showTags();
        }
    }//GEN-LAST:event_headerstabStateChanged

    private void newTag(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newTag
        NewTag nt = new NewTag();
        int result = JOptionPane.showOptionDialog(this, nt, "New Tag", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, null, null);
        if (result == JOptionPane.OK_OPTION) {
            String newTag = nt.newTagtext.getText();
            addNewTag(newTag);
            showTags();
        }
    }//GEN-LAST:event_newTag

    private void addTag(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addTag
        tag.addElement(newTagCombo.getSelectedItem());
    }//GEN-LAST:event_addTag

    private void removetag(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removetag
        int selectedIndex = listtag.getSelectedIndex();
        if (selectedIndex != -1) {
            tag.remove(selectedIndex);
        }
    }//GEN-LAST:event_removetag

    private void radioclActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_radioclActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_radioclActionPerformed

    private void radioclSelect(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_radioclSelect
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
            setEnabledVarious(false);
        } else if (evt.getStateChange() == java.awt.event.ItemEvent.DESELECTED) {
            setEnabledVarious(true);
            setEnabledVariations(true);
        }
    }//GEN-LAST:event_radioclSelect

    private void TimeoutSelect(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_TimeoutSelect
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVarious(false);
            setEnabledVariations(false);
        } else if (evt.getStateChange() == java.awt.event.ItemEvent.DESELECTED) {
            setEnabledVarious(true);
            setEnabledVariations(true);
        }
    }//GEN-LAST:event_TimeoutSelect

    private void pasteGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pasteGrep
        String element = getClipboardContents();
        String[] lines = element.split("\n");
        for (String line : lines) {
            grep.addElement(line);
        }
    }//GEN-LAST:event_pasteGrep

    private void setToGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_setToGrep
        if (!grep.isEmpty() && grep.firstElement().equals(" ")) {
            grep.removeElementAt(0);
            grep.addElement(textfield2.getText());
            textfield2.setText("");
        } else {
            grep.addElement(textfield2.getText());
            textfield2.setText("");
        }
    }//GEN-LAST:event_setToGrep

    private void removeAllGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeAllGrep
        grep.removeAllElements();
    }//GEN-LAST:event_removeAllGrep

    private void removeGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeGrep
        int selectedIndex = list2.getSelectedIndex();
        if (selectedIndex != -1) {
            grep.remove(selectedIndex);
        }
    }//GEN-LAST:event_removeGrep

    private void loadGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadGrep
        loadGrepsFile(grep);
    }//GEN-LAST:event_loadGrep

    private void addMatchReplace(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addMatchReplace
        model4.addRow(new Object[]{"Payload", "Leave blank to add a new header", "Leave blank to remove a matched header", "String", "Generic comment"});
    }//GEN-LAST:event_addMatchReplace

    private void jButton6addEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton6addEncoder
        if (!encoder.isEmpty() && encoder.firstElement().equals(" ")) {
            encoder.removeElementAt(0);
            encoder.addElement(combo2.getSelectedItem().toString());
        } else {
            encoder.addElement(combo2.getSelectedItem().toString());
        }
    }//GEN-LAST:event_jButton6addEncoder

    private void jButton7downEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton7downEncoder
        int selectedIndex = list3.getSelectedIndex();
        if (selectedIndex != encoder.getSize() - 1) {
            swap(selectedIndex, selectedIndex + 1);
            list3.setSelectedIndex(selectedIndex + 1);
            list3.ensureIndexIsVisible(selectedIndex + 1);

        }
    }//GEN-LAST:event_jButton7downEncoder

    private void jButton8upEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton8upEncoder
        int selectedIndex = list3.getSelectedIndex();
        if (selectedIndex != 0) {
            swap(selectedIndex, selectedIndex - 1);
            list3.setSelectedIndex(selectedIndex - 1);
            list3.ensureIndexIsVisible(selectedIndex - 1);

        }
    }//GEN-LAST:event_jButton8upEncoder

    private void jButton9removeEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton9removeEncoder
        int selectedIndex = list3.getSelectedIndex();
        if (selectedIndex != -1) {
            encoder.remove(selectedIndex);
        }
    }//GEN-LAST:event_jButton9removeEncoder

    private void setToPayload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_setToPayload
        if (!payload.isEmpty() && payload.firstElement().equals(" ")) {
            payload.removeElementAt(0);
            payload.addElement(textfield1.getText());
            textfield1.setText("");
        } else {
            payload.addElement(textfield1.getText());
            textfield1.setText("");
        }
    }//GEN-LAST:event_setToPayload

    private void removeAllPayloads(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeAllPayloads
        payload.removeAllElements();
    }//GEN-LAST:event_removeAllPayloads

    private void removePayload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removePayload
        int selectedIndex = list1.getSelectedIndex();
        if (selectedIndex != -1) {
            payload.remove(selectedIndex);
        }
    }//GEN-LAST:event_removePayload

    private void loadPayloads(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadPayloads
        loadPayloadsFile(payload);
    }//GEN-LAST:event_loadPayloads

    private void pastePayload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pastePayload

        String element = getClipboardContents();
        String[] lines = element.split("\n");
        for (String line : lines) {
            payload.addElement(line);
        }
    }//GEN-LAST:event_pastePayload

    private void removeMatchReplace(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeMatchReplace
        int[] rows = table4.getSelectedRows();
        Arrays.sort(rows);
        for (int i = rows.length - 1; i >= 0; i--) {
            int row = rows[i];
            int modelRow = table4.convertRowIndexToModel(row);
            model4.removeRow(modelRow);
        }
    }//GEN-LAST:event_removeMatchReplace

    private void variations(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_variations
        if (evt.getStateChange() == java.awt.event.ItemEvent.DESELECTED) {
            setEnabledVarious(true);
            setEnabledVariations(false);
        } else if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVarious(false);
            setEnabledVariations(true);
        }
    }//GEN-LAST:event_variations

    private void invariations(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_invariations
        if (evt.getStateChange() == java.awt.event.ItemEvent.DESELECTED) {
            setEnabledVarious(true);
            setEnabledVariations(false);
        } else if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVarious(false);
            setEnabledVariations(true);
        }
    }//GEN-LAST:event_invariations

    private void stringMatchType(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_stringMatchType
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
        }
    }//GEN-LAST:event_stringMatchType

    private void regexMatchType(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_regexMatchType
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
        }
    }//GEN-LAST:event_regexMatchType

    private void payloadMatchType(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_payloadMatchType
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
        }
    }//GEN-LAST:event_payloadMatchType

    private void payloadencodeMatchType(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_payloadencodeMatchType
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
        }
    }//GEN-LAST:event_payloadencodeMatchType


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel Attributes;
    private javax.swing.JButton addTag;
    private javax.swing.JCheckBox anchor_labels;
    private javax.swing.JRadioButton append;
    private javax.swing.JButton button1;
    private javax.swing.JButton button10;
    private javax.swing.JButton button11;
    private javax.swing.JButton button12;
    private javax.swing.JButton button13;
    private javax.swing.JButton button18;
    private javax.swing.JButton button19;
    private javax.swing.JButton button2;
    private javax.swing.JButton button3;
    private javax.swing.JButton button4;
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
    private javax.swing.ButtonGroup buttonGroup7;
    private javax.swing.ButtonGroup buttonGroup8;
    private javax.swing.ButtonGroup buttonGroup9;
    private javax.swing.JCheckBox button_submit_labels;
    private javax.swing.JCheckBox canonical_link;
    private javax.swing.JCheckBox check1;
    private javax.swing.JCheckBox check4;
    private javax.swing.JCheckBox check71;
    private javax.swing.JCheckBox check72;
    public javax.swing.JCheckBox check8;
    public javax.swing.JComboBox<String> combo1;
    private javax.swing.JComboBox<String> combo2;
    private javax.swing.JCheckBox comments;
    private javax.swing.JCheckBox content_length;
    private javax.swing.JCheckBox content_location;
    private javax.swing.JCheckBox content_type;
    private javax.swing.JCheckBox css_classes;
    private javax.swing.JCheckBox div_ids;
    private javax.swing.JCheckBox etag_header;
    private javax.swing.JCheckBox excludehttp;
    private javax.swing.JCheckBox first_header_tag;
    private javax.swing.JCheckBox header_tags;
    private javax.swing.JTabbedPane headerstab;
    private javax.swing.JCheckBox initial_body_content;
    private javax.swing.JCheckBox input_image_labels;
    private javax.swing.JCheckBox input_submit_labels;
    private javax.swing.JRadioButton invariationsRadio;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton10;
    private javax.swing.JButton jButton11;
    private javax.swing.JButton jButton12;
    private javax.swing.JButton jButton13;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JButton jButton5;
    private javax.swing.JButton jButton6;
    private javax.swing.JButton jButton7;
    private javax.swing.JButton jButton8;
    private javax.swing.JButton jButton9;
    private javax.swing.JCheckBoxMenuItem jCheckBoxMenuItem1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel16;
    private javax.swing.JLabel jLabel18;
    private javax.swing.JLabel jLabel19;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel22;
    private javax.swing.JLabel jLabel23;
    private javax.swing.JLabel jLabel24;
    private javax.swing.JLabel jLabel25;
    private javax.swing.JLabel jLabel26;
    private javax.swing.JLabel jLabel27;
    private javax.swing.JLabel jLabel28;
    private javax.swing.JLabel jLabel29;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel30;
    private javax.swing.JLabel jLabel31;
    private javax.swing.JLabel jLabel32;
    private javax.swing.JLabel jLabel33;
    private javax.swing.JLabel jLabel34;
    private javax.swing.JLabel jLabel35;
    private javax.swing.JLabel jLabel36;
    private javax.swing.JLabel jLabel37;
    private javax.swing.JLabel jLabel38;
    private javax.swing.JLabel jLabel39;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel40;
    private javax.swing.JLabel jLabel41;
    private javax.swing.JLabel jLabel42;
    private javax.swing.JLabel jLabel43;
    private javax.swing.JLabel jLabel44;
    private javax.swing.JLabel jLabel45;
    private javax.swing.JLabel jLabel46;
    private javax.swing.JLabel jLabel47;
    private javax.swing.JLabel jLabel48;
    private javax.swing.JLabel jLabel49;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel52;
    private javax.swing.JLabel jLabel53;
    private javax.swing.JLabel jLabel54;
    private javax.swing.JLabel jLabel55;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel10;
    private javax.swing.JPanel jPanel11;
    private javax.swing.JPanel jPanel12;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane10;
    private javax.swing.JScrollPane jScrollPane11;
    private javax.swing.JScrollPane jScrollPane13;
    private javax.swing.JScrollPane jScrollPane14;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JScrollPane jScrollPane7;
    private javax.swing.JScrollPane jScrollPane8;
    private javax.swing.JScrollPane jScrollPane9;
    private javax.swing.JSeparator jSeparator10;
    private javax.swing.JSeparator jSeparator11;
    private javax.swing.JSeparator jSeparator12;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JSeparator jSeparator3;
    private javax.swing.JSeparator jSeparator4;
    private javax.swing.JSeparator jSeparator5;
    private javax.swing.JSeparator jSeparator6;
    private javax.swing.JSeparator jSeparator7;
    private javax.swing.JSeparator jSeparator8;
    private javax.swing.JSeparator jSeparator9;
    private javax.swing.JTabbedPane jTabbedPane2;
    private javax.swing.JTabbedPane jtabpane;
    private javax.swing.JCheckBox last_modified_header;
    private javax.swing.JCheckBox limited_body_content;
    private javax.swing.JCheckBox line_count;
    private javax.swing.JList<String> list1;
    private javax.swing.JList<String> list2;
    public javax.swing.JList<String> list3;
    public javax.swing.JList<String> listtag;
    public javax.swing.JList<String> listtagmanager;
    private javax.swing.JCheckBox location;
    private javax.swing.JCheckBox negativeCT;
    private javax.swing.JCheckBox negativeRC;
    private javax.swing.JComboBox<String> newTagCombo;
    private javax.swing.JComboBox<String> newTagCombo2;
    private javax.swing.JButton newTagb;
    private javax.swing.JCheckBox non_hidden_form_input_types;
    private javax.swing.JCheckBox onlyhttp;
    private javax.swing.JCheckBox outbound_edge_count;
    private javax.swing.JCheckBox outbound_edge_tag_names;
    private javax.swing.JCheckBox page_title;
    private javax.swing.JCheckBox pathdiscovery;
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
    private javax.swing.JRadioButton radioPR;
    private javax.swing.JRadioButton radiocl;
    private javax.swing.JRadioButton radiotime;
    private javax.swing.JRadioButton rb1;
    private javax.swing.JRadioButton rb2;
    private javax.swing.JRadioButton rb3;
    private javax.swing.JRadioButton rb4;
    private javax.swing.JButton removetag;
    private javax.swing.JRadioButton replace;
    private javax.swing.JCheckBox set_cookie_names;
    private javax.swing.JSpinner sp1;
    private javax.swing.JCheckBox status_code;
    private javax.swing.JTable table;
    private javax.swing.JTable table1;
    private javax.swing.JTable table2;
    private javax.swing.JTable table4;
    private javax.swing.JCheckBox tag_ids;
    private javax.swing.JCheckBox tag_names;
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
    private javax.swing.JTextField textauthor;
    private javax.swing.JTextField textcl;
    private javax.swing.JTextField textfield1;
    private javax.swing.JTextField textfield2;
    private javax.swing.JTextField textgreps;
    private javax.swing.JTextField textpayloads;
    private javax.swing.JTextField texttime;
    private javax.swing.JRadioButton variationsRadio;
    private javax.swing.JCheckBox visible_text;
    private javax.swing.JCheckBox visible_word_count;
    private javax.swing.JCheckBox whole_body_content;
    private javax.swing.JCheckBox word_count;
    // End of variables declaration//GEN-END:variables
}
