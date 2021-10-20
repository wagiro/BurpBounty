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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultListModel;

/**
 *
 * @author wagiro
 */
public class ProfilesManager {

    private String name;
    private String issuename;
    private String issuedetail;
    private String issuebackground;
    private String remediationdetail;
    private String remediationbackground;
    private String charstourlencode;
    private int matchtype;
    private int scope;
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
    private String urlextension;
    private boolean isurlextension;
    private boolean NegativeUrlExtension;
    private boolean Scanas;
    private int Scantype;
    private int redirtype;
    private int maxRedir;
    private int payloadPosition;
    private String payloadsfile;
    private String grepsfile;
    private String timeOut1;
    private String timeOut2;
    private String contentLength;
    private String httpResponseCode;
    private String author;
    private String profiles_directory;
    private List<Headers> headers;
    private List<String> variationAttributes;
    private List<Integer> insertionPointType;

    public ProfilesManager(String profiles_directory) {
        this.profiles_directory = profiles_directory;

        name = "";
        issuename = "";
        issuedetail = "";
        issuebackground = "";
        remediationdetail = "";
        remediationbackground = "";
        charstourlencode = "";
        matchtype = 0;
        scope = 0;
        issueseverity = "";
        issueconfidence = "";
        responsecode = "";
        contenttype = "";
        httpResponseCode = "";
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
        Scantype = 0;
        payloadsfile = "";
        grepsfile = "";
        timeOut1 = "";
        timeOut2 = "";
        contentLength = "";
        author = "";
        urlextension = "";
        isurlextension = false;
        NegativeUrlExtension = false;
        Scanas = false;
        headers = new ArrayList();
        variationAttributes = new ArrayList();
        insertionPointType = new ArrayList();
    }

    public void setActiveAttackValues(String profile_name, JsonArray activeprofiles, ActiveProfile profile) {
        //Set Attack values when select from main combobox
        try {
            GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
            Gson gson = builder.create();

            JsonArray json = activeprofiles;
            ProfilesProperties profile_property = new ProfilesProperties();

            if (json != null) {
                for (JsonElement pa : json) {
                    JsonObject bbObj = pa.getAsJsonObject();
                    if (bbObj.get("ProfileName").getAsString().equals(profile_name)) {
                        profile_property = gson.fromJson(bbObj.toString(), ProfilesProperties.class
                        );
                    }

                }
            }

            name = profile_property.getProfileName();
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
            isurlextension = profile_property.getIsURLExtension();
            urlextension = profile_property.getURLExtension();
            NegativeUrlExtension = profile_property.getNegativeURLExtension();
            redirtype = profile_property.getRedirection();
            maxRedir = profile_property.getMaxRedir();
            payloadsfile = profile_property.getpayloadsFile();
            grepsfile = profile_property.getgrepsFile();
            payloadPosition = profile_property.getPayloadPosition();
            timeOut1 = profile_property.getTime1();
            timeOut2 = profile_property.getTime2();
            author = profile_property.getAuthor();
            contentLength = profile_property.getContentLength();
            httpResponseCode = profile_property.getHttpResponseCode();
            headers = profile_property.getHeader();
            variationAttributes = profile_property.getVariationAttributes();
            insertionPointType = profile_property.getInsertionPointType();

            profile.textauthor.setText(author);
            profile.text1.setText(name);

            if (payloadPosition == 1) {
                profile.buttonGroup1.setSelected(profile.replace.getModel(), true);
            } else if (payloadPosition == 2) {
                profile.buttonGroup1.setSelected(profile.append.getModel(), true);
            }else if (payloadPosition == 3) {
                profile.buttonGroup1.setSelected(profile.insert.getModel(), true);
            }

            profile.grep.removeAllElements();
            profile.payload.removeAllElements();
            profile.encoder.removeAllElements();
            profile.tag.removeAllElements();

            profile.textpayloads.setText(payloadsfile);
            profile.textgreps.setText(grepsfile);

            profile.showGreps(profile_property.getGreps());
            profile.showPayloads(profile_property.getPayloads());

//            if (!payloadsfile.isEmpty()) {
//                loadPath(payloadsfile, profile.payload);
//                updatePayloads(payloadsfile, profile_property);
//
//            } else {
//                for (String pay : profile_property.getPayloads()) {
//                    profile.payload.addElement(pay);
//                }
//            }

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
            profile.text73.setText(urlextension);

            profile.check8.setSelected(urlencode);
            profile.text5.setText(charstourlencode);
            profile.excludehttp.setSelected(excludeHTTP);
            profile.onlyhttp.setSelected(onlyHTTP);

            if (timeOut2.equals("0")) {
                profile.texttime2.setText("");
            } else {
                profile.texttime2.setText(timeOut2);
            }

            if (timeOut1.equals("0")) {
                profile.texttime1.setText("");
            } else {
                profile.texttime1.setText(timeOut1);
            }

            profile.textcl.setText(contentLength);
            profile.resposecode.setText(httpResponseCode);

            switch (matchtype) {
                case 1:
                    profile.buttonGroup3.setSelected(profile.radio4.getModel(), true);
                    break;
                case 2:
                    profile.buttonGroup3.setSelected(profile.radio3.getModel(), true);
                    break;
                case 3:
                    profile.buttonGroup3.setSelected(profile.radio12.getModel(), true);
                    break;
                case 4:
                    profile.buttonGroup3.setSelected(profile.radio22.getModel(), true);
                    break;
                case 5:
                    profile.buttonGroup3.setSelected(profile.radiotime.getModel(), true);
                    break;
                case 6:
                    profile.buttonGroup3.setSelected(profile.radiocl.getModel(), true);
                    break;
                case 7:
                    profile.buttonGroup3.setSelected(profile.variationsRadio.getModel(), true);
                    break;
                case 8:
                    profile.buttonGroup3.setSelected(profile.invariationsRadio.getModel(), true);
                    break;
                case 9:
                    profile.buttonGroup3.setSelected(profile.radiohttp.getModel(), true);
                    break;
                default:
                    profile.buttonGroup3.clearSelection();
                    break;
            }

            switch (redirtype) {
                case 1:
                    profile.buttonGroup4.setSelected(profile.rb1.getModel(), true);
                    break;
                case 2:
                    profile.buttonGroup4.setSelected(profile.rb2.getModel(), true);
                    break;
                case 3:
                    profile.buttonGroup4.setSelected(profile.rb3.getModel(), true);
                    break;
                case 4:
                    profile.buttonGroup4.setSelected(profile.rb4.getModel(), true);
                    break;
                default:
                    profile.buttonGroup4.clearSelection();
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
            profile.check73.setSelected(isurlextension);
            profile.negativeCT.setSelected(negativect);
            profile.negativeRC.setSelected(negativerc);
            profile.negativeURL.setSelected(NegativeUrlExtension);
            profile.text4.setText(issuename);
            profile.textarea1.setText(issuedetail);
            profile.textarea2.setText(issuebackground);
            profile.textarea3.setText(remediationdetail);
            profile.textarea4.setText(remediationbackground);
            profile.sp1.setValue(maxRedir);

            switch (issueseverity) {
                case "High":
                    profile.buttonGroup5.setSelected(profile.radio5.getModel(), true);
                    break;
                case "Medium":
                    profile.buttonGroup5.setSelected(profile.radio6.getModel(), true);
                    break;
                case "Low":
                    profile.buttonGroup5.setSelected(profile.radio7.getModel(), true);
                    break;
                case "Information":
                    profile.buttonGroup5.setSelected(profile.radio8.getModel(), true);
                    break;
                default:
                    break;
            }

            switch (issueconfidence) {
                case "Certain":
                    profile.buttonGroup6.setSelected(profile.radio9.getModel(), true);
                    break;
                case "Firm":
                    profile.buttonGroup6.setSelected(profile.radio10.getModel(), true);
                    break;
                case "Tentative":
                    profile.buttonGroup6.setSelected(profile.radio11.getModel(), true);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            System.out.println("PofilesManager line 499:" + e.getMessage());
            for (StackTraceElement element : e.getStackTrace()) {
                System.out.println(element);
            }
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

            newfile.setProfileName(profile.text1.getText());

            newfile.setAuthor(profile.textauthor.getText());

            newfile.setScanner(1);

            if (profile.replace.isSelected()) {
                newfile.setPayloadPosition(1);
            } else if (profile.append.isSelected()) {
                newfile.setPayloadPosition(2);
            } else if (profile.insert.isSelected()) {
                newfile.setPayloadPosition(3);
            }

            newfile.setEnabled(true);
            List encoders = new ArrayList();
            List payloads = new ArrayList();
            List greps = new ArrayList();
            List tags = new ArrayList();

            newfile.setPayloadsFile(profile.textpayloads.getText());
           for (int i = 0; i < profile.modelpayload.getRowCount(); i++) {
                if (!profile.modelpayload.getValueAt(i, 1).toString().isEmpty()) {
                    payloads.add(profile.modelpayload.getValueAt(i, 0).toString() + "," + profile.modelpayload.getValueAt(i, 1).toString());
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
            newfile.setURLExtension(profile.text73.getText());

            newfile.setTime2(profile.texttime2.getText());
            newfile.setTime1(profile.texttime1.getText());
            newfile.setContentLength(profile.textcl.getText());
            newfile.setHttpResponseCode(profile.resposecode.getText());

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
            } else if (profile.radiohttp.isSelected()) {
                newfile.setMatchType(9);
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
            newfile.setInsertionPointType(insertionPointType);

            newfile.setCaseSensitive(profile.check1.isSelected());
            newfile.setNotResponse(profile.check4.isSelected());
            newfile.setIsContentType(profile.check71.isSelected());
            newfile.setIsResponseCode(profile.check72.isSelected());
            newfile.setIsURLExtension(profile.check73.isSelected());
            newfile.setNegativeCT(profile.negativeCT.isSelected());
            newfile.setNegativeRC(profile.negativeRC.isSelected());
            newfile.setNegativeURLExtension(profile.negativeURL.isSelected());
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
            GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
            Gson gson = builder.create();

            JsonArray ijson = new JsonArray();
            List<ProfilesProperties> newjson = gson.fromJson(ijson, new TypeToken<List<ProfilesProperties>>() {
            }.getType());
            newjson.add(newfile);

            String json = gson.toJson(newjson);

            //Write JSON String to file
            FileOutputStream fileStream;

            fileStream = new FileOutputStream(new File(profiles_directory + File.separator + profile.text1.getText().concat(".bb")));

            OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
            writer.write(json);
            writer.close();

        } catch (IOException e) {
            System.out.println("ProfilesManager line 852:");
            for (StackTraceElement element : e.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public void setResponseAttackValues(String profile_name, JsonArray passiveresprofiles, ResponseProfile profile) {
        //Set Attack values when select from main combobox
        try {
            GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
            Gson gson = builder.create();
            JsonArray json = passiveresprofiles;
            ProfilesProperties profile_property = new ProfilesProperties();

            if (json != null) {
                for (JsonElement pa : json) {
                    JsonObject bbObj = pa.getAsJsonObject();
                    if (bbObj.get("ProfileName").getAsString().equals(profile_name)) {
                        profile_property = gson.fromJson(bbObj.toString(), ProfilesProperties.class
                        );
                    }

                }
            }

            name = profile_property.getProfileName();
            casesensitive = profile_property.getCaseSensitive();
            notresponse = profile_property.getNotResponse();
            matchtype = profile_property.getMatchType();
            scope = profile_property.getScope();
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
            isurlextension = profile_property.getIsURLExtension();
            urlextension = profile_property.getURLExtension();
            NegativeUrlExtension = profile_property.getNegativeURLExtension();
            maxRedir = profile_property.getMaxRedir();
            grepsfile = profile_property.getgrepsFile();
            payloadPosition = profile_property.getPayloadPosition();
            author = profile_property.getAuthor();
            contentLength = profile_property.getContentLength();

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
                    profile.buttonGroup3.setSelected(profile.radio4.getModel(), true);
                    break;
                case 2:
                    profile.buttonGroup3.setSelected(profile.radio3.getModel(), true);
                    break;
                default:
                    profile.buttonGroup3.clearSelection();
                    break;
            }

            switch (scope) {
                case 1:
                    profile.buttonGroup7.setSelected(profile.first_match.getModel(), true);
                    break;
                case 2:
                    profile.buttonGroup7.setSelected(profile.all_matches.getModel(), true);
                    break;
                default:
                    profile.buttonGroup7.clearSelection();
                    break;
            }

            switch (redirtype) {
                case 1:
                    profile.buttonGroup4.setSelected(profile.rb1.getModel(), true);
                    break;
                case 2:
                    profile.buttonGroup4.setSelected(profile.rb2.getModel(), true);
                    break;
                case 3:
                    profile.buttonGroup4.setSelected(profile.rb3.getModel(), true);
                    break;
                case 4:
                    profile.buttonGroup4.setSelected(profile.rb4.getModel(), true);
                    break;
                default:
                    profile.buttonGroup4.clearSelection();
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
            profile.sp1.setValue(maxRedir);
            profile.text73.setText(urlextension);
            profile.check73.setSelected(isurlextension);
            profile.negativeURL.setSelected(NegativeUrlExtension);

            switch (issueseverity) {
                case "High":
                    profile.buttonGroup5.setSelected(profile.radio5.getModel(), true);
                    break;
                case "Medium":
                    profile.buttonGroup5.setSelected(profile.radio6.getModel(), true);
                    break;
                case "Low":
                    profile.buttonGroup5.setSelected(profile.radio7.getModel(), true);
                    break;
                case "Information":
                    profile.buttonGroup5.setSelected(profile.radio8.getModel(), true);
                    break;
                default:
                    break;
            }

            switch (issueconfidence) {
                case "Certain":
                    profile.buttonGroup6.setSelected(profile.radio9.getModel(), true);
                    break;
                case "Firm":
                    profile.buttonGroup6.setSelected(profile.radio10.getModel(), true);
                    break;
                case "Tentative":
                    profile.buttonGroup6.setSelected(profile.radio11.getModel(), true);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            System.out.println("ProfilesManager line 1015:" + e.getMessage());
            for (StackTraceElement element : e.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public void saveResponseAttackValues(ResponseProfile profile) {
        //Save attack with fields values
        try {
            //get GUI values
            ProfilesProperties newfile = new ProfilesProperties();

            newfile.setProfileName(profile.text1.getText());

            newfile.setAuthor(profile.textauthor.getText());

            newfile.setScanner(2);

            newfile.setEnabled(true);
            List greps = new ArrayList();
            List tags = new ArrayList();

            newfile.setGrepsFile(profile.textgreps.getText());
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

            if (profile.first_match.isSelected()) {
                newfile.setScope(1);
            } else if (profile.all_matches.isSelected()) {
                newfile.setScope(2);
            }

            newfile.setExcludeHTTP(profile.excludehttp.isSelected());
            newfile.setOnlyHTTP(profile.onlyhttp.isSelected());
            newfile.setContentType(profile.text71.getText());
            newfile.setResponseCode(profile.text72.getText());
            newfile.setURLExtension(profile.text73.getText());
            newfile.setIsURLExtension(profile.check73.isSelected());
            newfile.setNegativeURLExtension(profile.negativeURL.isSelected());

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
            GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
            Gson gson = builder.create();

            JsonArray ijson = new JsonArray();
            List<ProfilesProperties> newjson = gson.fromJson(ijson, new TypeToken<List<ProfilesProperties>>() {
            }.getType());
            newjson.add(newfile);

            String json = gson.toJson(newjson);

            //Write JSON String to file
            FileOutputStream fileStream;

            fileStream = new FileOutputStream(new File(profiles_directory + File.separator + profile.text1.getText().concat(".bb")));

            OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
            writer.write(json);
            writer.close();

        } catch (IOException e) {
            System.out.println("ProfilesManager line 1149:");
            for (StackTraceElement element : e.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public void setRequestAttackValues(String profile_name,JsonArray passivereqprofiles, RequestProfile profile) {
        //Set Attack values when select from main combobox
        try {
            GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
            Gson gson = builder.create();
            JsonArray json = passivereqprofiles;
            ProfilesProperties profile_property = new ProfilesProperties();

            if (json != null) {
                for (JsonElement pa : json) {
                    JsonObject bbObj = pa.getAsJsonObject();
                    if (bbObj.get("ProfileName").getAsString().equals(profile_name)) {
                        profile_property = gson.fromJson(bbObj.toString(), ProfilesProperties.class
                        );
                    }

                }
            }

            name = profile_property.getProfileName();
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
            grepsfile = profile_property.getgrepsFile();
            payloadPosition = profile_property.getPayloadPosition();
            author = profile_property.getAuthor();
            contentLength = profile_property.getContentLength();
            isurlextension = profile_property.getIsURLExtension();
            urlextension = profile_property.getURLExtension();
            NegativeUrlExtension = profile_property.getNegativeURLExtension();
            Scanas = profile_property.getScanAs();
            Scantype = profile_property.getScanType();

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
                    profile.buttonGroup3.setSelected(profile.radio4.getModel(), true);
                    break;
                case 2:
                    profile.buttonGroup3.setSelected(profile.radio3.getModel(), true);
                    break;
                default:
                    profile.buttonGroup3.clearSelection();
                    break;
            }

            profile.check1.setSelected(casesensitive);
            profile.check4.setSelected(notresponse);
            profile.text4.setText(issuename);
            profile.textarea1.setText(issuedetail);
            profile.textarea2.setText(issuebackground);
            profile.textarea3.setText(remediationdetail);
            profile.textarea4.setText(remediationbackground);
            profile.text73.setText(urlextension);
            profile.check73.setSelected(isurlextension);
            profile.negativeURL.setSelected(NegativeUrlExtension);

            switch (issueseverity) {
                case "High":
                    profile.buttonGroup5.setSelected(profile.radio5.getModel(), true);
                    break;
                case "Medium":
                    profile.buttonGroup5.setSelected(profile.radio6.getModel(), true);
                    break;
                case "Low":
                    profile.buttonGroup5.setSelected(profile.radio7.getModel(), true);
                    break;
                case "Information":
                    profile.buttonGroup5.setSelected(profile.radio8.getModel(), true);
                    break;
                default:
                    break;
            }

            switch (issueconfidence) {
                case "Certain":
                    profile.buttonGroup6.setSelected(profile.radio9.getModel(), true);
                    break;
                case "Firm":
                    profile.buttonGroup6.setSelected(profile.radio10.getModel(), true);
                    break;
                case "Tentative":
                    profile.buttonGroup6.setSelected(profile.radio11.getModel(), true);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            System.out.println("ProfilesManager line 1286:" + e.getMessage());
            for (StackTraceElement element : e.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public void saveRequestAttackValues(RequestProfile profile) {
        //Save attack with fields values
        try {
            //get GUI values
            ProfilesProperties newfile = new ProfilesProperties();

            newfile.setProfileName(profile.text1.getText());

            newfile.setAuthor(profile.textauthor.getText());

            newfile.setScanner(3);

            newfile.setEnabled(true);
            List greps = new ArrayList();
            List tags = new ArrayList();

            newfile.setGrepsFile(profile.textgreps.getText());

            for (int i = 0; i < profile.modelgrep.getRowCount(); i++) {
                if (!profile.modelgrep.getValueAt(i, 4).toString().isEmpty()) {
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


            newfile.setURLExtension(profile.text73.getText());

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
            newfile.setIsURLExtension(profile.check73.isSelected());
            newfile.setNegativeURLExtension(profile.negativeURL.isSelected());
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
            GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
            Gson gson = builder.create();

            JsonArray ijson = new JsonArray();
            List<ProfilesProperties> newjson = gson.fromJson(ijson, new TypeToken<List<ProfilesProperties>>() {
            }.getType());
            newjson.add(newfile);

            String json = gson.toJson(newjson);

            //Write JSON String to file
            FileOutputStream fileStream;

            fileStream = new FileOutputStream(new File(profiles_directory + File.separator + profile.text1.getText().concat(".bb")));

            OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
            writer.write(json);
            writer.close();

        } catch (IOException e) {
            System.out.println("ProfilesManager line 1403:");
            for (StackTraceElement element : e.getStackTrace()) {
                System.out.println(element);
            }
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
            System.out.println("ProfilesManager line 1912:" + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        } catch (IOException ex) {
            System.out.println("ProfilesManager line 1815:" + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }
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

            GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
            Gson gson = builder.create();
            String strJson = gson.toJson(issue);
            FileWriter writer = null;

            writer = new FileWriter(profiles_directory + File.separator + issue.getProfileName().concat(".bb"));
            writer.write("[" + strJson + "]");

            writer.close();
        } catch (FileNotFoundException ex) {
            System.out.println("ProfilesManager line 1639:");
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        } catch (IOException ex) {
            System.out.println("ProfilesManager line 1042:");
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }
    }
}
