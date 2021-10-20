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

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
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
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.swing.DefaultListModel;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

public class BurpBountyGui extends javax.swing.JPanel {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public String filename;

    Boolean pathDiscovery;
    JsonArray allrules;
    JsonArray allprofiles;
    JsonArray activeprofiles;
    JsonArray passiveresprofiles;
    JsonArray passivereqprofiles;
    DefaultTableModel model;
    DefaultTableModel model1;
    DefaultTableModel model2;
    DefaultTableModel model4;
    DefaultTableModel model9;
    DefaultTableModel model10;
    DefaultTableModel rulemodel;
    DefaultTableModel modeltagmanager;
    DefaultTableModel dashboardmodel;
    DefaultListModel tagmanager;
    String profiles_directory;
    BurpBountyExtension parent;

    public BurpBountyGui(BurpBountyExtension parent) {
        try {
            this.callbacks = parent.callbacks;
            this.helpers = callbacks.getHelpers();
            this.parent = parent;
            filename = "";
            model4 = new DefaultTableModel();
            model9 = new DefaultTableModel();
            model10 = new DefaultTableModel();
            modeltagmanager = new DefaultTableModel();
            dashboardmodel = new DefaultTableModel();
            rulemodel = new DefaultTableModel();
            allprofiles = new JsonArray();
            allrules = new JsonArray();
            activeprofiles = new JsonArray();
            passiveresprofiles = new JsonArray();
            passivereqprofiles = new JsonArray();
            tagmanager = new DefaultListModel();

            if (callbacks.loadExtensionSetting("filename") != null) {
                filename = callbacks.loadExtensionSetting("filename");
                if (filename.endsWith(File.separator)) {
                    profiles_directory = filename ;
                } else {
                    profiles_directory = filename + File.separator ;
                }
            } else {
                filename = System.getProperty("user.home");
                if (filename.endsWith(File.separator)) {
                    profiles_directory = filename ;
                } else {
                    profiles_directory = filename + File.separator;
                }
            }

            createDirectories(profiles_directory);

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
            checkProfilesProperties(profiles_directory);
        makeTagsFile();
        showTags();
        showProfiles("All");
           
        } catch (Exception e) {
            System.out.println("BurpBountyGui: line 461");
            for (StackTraceElement element : e.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public void createDirectories(String profiles_directory) {

        File profiles = new File(profiles_directory);

        if (!profiles.exists()) {
            profiles.mkdir();
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

            GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
            Gson gson = builder.create();
            String strJson = gson.toJson(issue);
            FileWriter writer = null;

            writer = new FileWriter(profiles_directory + File.separator + issue.getProfileName().concat(".bb"));
            writer.write("[" + strJson + "]");

            writer.close();
        } catch (FileNotFoundException ex) {
            System.out.println("BurpBountyGui line 1675:" + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        } catch (IOException ex) {
            System.out.println("BurpBountyGui line 1078:" + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    private List<String> readFile(String filename) {
        List<String> records = new ArrayList();
        try {
            FileReader reader2 = new FileReader(filename);
            BufferedReader reader = new BufferedReader(reader2);
            String line;
            while ((line = reader.readLine()) != null) {
                records.add(line);
            }
            reader2.close();
            reader.close();
        } catch (Exception e) {
            System.out.println("BurpBountyGui line 1882:" + e.getMessage());
            for (StackTraceElement element : e.getStackTrace()) {
                System.out.println(element);
            }
        }
        return records;
    }

    public void checkProfilesProperties(String profiles_directory) {
        FileReader fr;

        JsonArray alldata = new JsonArray();
        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
        Gson gson = builder.create();
        File f = new File(profiles_directory);

        if (f.exists() && f.isDirectory()) {
            for (File file : f.listFiles()) {
                if (file.getName().endsWith(".bb")) {
                    try {
                        fr = new FileReader(file.getAbsolutePath());
                    } catch (IOException ex) {
                        System.out.println("BurpBountyGui line 1796:" + ex.getMessage());
                        for (StackTraceElement element : ex.getStackTrace()) {
                            System.out.println(element);
                        }
                        continue;
                    }

                    JsonParser parser = new JsonParser();
                    JsonArray data = new JsonArray();
                    ProfilesProperties profile_property;

                    try {
                        JsonReader json = new JsonReader((fr));
                        data.addAll(parser.parse(json).getAsJsonArray());
                        Object idata = data.get(0);
                        profile_property = gson.fromJson(idata.toString(), ProfilesProperties.class);

                        String name = "";
                        name = profile_property.getProfileName();
                        JsonObject bbObj = data.get(0).getAsJsonObject();
                        if (name == null) {
                            name = profile_property.getName();
                            if (name == null) {
                                System.out.println("Profile name corrupted");
                                continue;
                            } else {
                                bbObj.remove("Name");
                                bbObj.addProperty("ProfileName", name);
                            }
                        }
                        data = new JsonArray();
                        data.add(bbObj);
                        alldata.addAll(data);
                    } catch (Exception e) {
                        System.out.println("BurpBountyGui line 1939");
                        for (StackTraceElement element : e.getStackTrace()) {
                            System.out.println(element);
                        }
                        continue;
                    }

                    try {
                        fr.close();
                    } catch (IOException ex) {
                        System.out.println("BurpBountyGui line 1825:" + ex.getMessage());
                        for (StackTraceElement element : ex.getStackTrace()) {
                            System.out.println(element);
                        }
                        continue;
                    }

                }
            }
        }
        parent.setAllProfiles(alldata);
        allprofiles = alldata;
        setActiveProfiles(allprofiles);
        setPassiveProfiles(allprofiles);
    }

    public void setActiveProfiles(JsonArray allprofiles) {
        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
        Gson gson = builder.create();
        int scanner = 0;
        ProfilesProperties issue;
        Boolean enabled = false;
        activeprofiles = new JsonArray();

        for (int i = 0; i < allprofiles.size(); i++) {
            try {
                Object idata = allprofiles.get(i);
                issue = gson.fromJson(idata.toString(), ProfilesProperties.class);
                scanner = issue.getScanner();
                enabled = issue.getEnabled();
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

    public JsonArray getProfiles() {
        parent.setAllProfiles(allprofiles);
        return allprofiles;
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
                System.out.println("BurpBountyGui line 1866:" + ex.getMessage());
                for (StackTraceElement element : ex.getStackTrace()) {
                    System.out.println(element);
                }
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

            checkProfilesProperties(profiles_directory);
            makeTagsFile();
            showTags();
            showProfiles("All");
            filename = file;
            this.callbacks.saveExtensionSetting("filename", file);

        }
    }

    public void setEnableDisableProfile(String enable, JTable table) {

        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
        Gson gson = builder.create();

        JsonArray json2 = new JsonArray();
        List<ProfilesProperties> newjson = gson.fromJson(json2, new TypeToken<List<ProfilesProperties>>() {
        }.getType());

        int[] rows = table.getSelectedRows();

        for (Integer row : rows) {
            try {
                String profile_name = table.getValueAt(row, 1).toString();
                JsonArray data = new JsonArray();
                FileReader reader = new FileReader(profiles_directory + File.separator + profile_name.concat(".bb"));
                JsonReader json = new JsonReader(reader);
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
                FileOutputStream fileStream = new FileOutputStream(profiles_directory + File.separator + profile_name.concat(".bb"));
                String fjson = gson.toJson(newjson);
                OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");
                writer.write(fjson);
                reader.close();
                json.close();
                writer.close();

            } catch (IOException e) {
                System.out.println("BurpBountyGui line 1956:" + e.getMessage());
                for (StackTraceElement element : e.getStackTrace()) {
                    System.out.println(element);
                }
            }
        }
        checkProfilesProperties(profiles_directory);
        showProfiles("All");

    }

 

    public void deleteTagProfiles(String tag) {

        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
        Gson gson = builder.create();
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
                    FileReader reader = new FileReader(file.getAbsolutePath());
                    JsonReader json = new JsonReader(reader);
                    JsonParser parser = new JsonParser();
                    data.addAll(parser.parse(json).getAsJsonArray());

                    Object idata = data.get(0);
                    ProfilesProperties profile_properties = gson.fromJson(idata.toString(), ProfilesProperties.class);
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
                    reader.close();
                    writer.close();
                    json.close();
                } catch (IOException e) {
                    System.out.println("BurpBountyGui line 2065:" + e.getMessage());
                    for (StackTraceElement element : e.getStackTrace()) {
                        System.out.println(element);
                    }
                }
            }
        }
        checkProfilesProperties(profiles_directory);
        showProfiles("All");
    }

    public void makeTagsFile() {

        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
        Gson gson = builder.create();
        allprofiles = getProfiles();
        List<String> tags = new ArrayList();

        for (int i = 0; i < allprofiles.size(); i++) {
            Object idata = allprofiles.get(0);
            ProfilesProperties profile_properties;
            try {
                profile_properties = gson.fromJson(idata.toString(), ProfilesProperties.class);
                tags.addAll(profile_properties.getTags());
            } catch (IllegalStateException e) {
                for (StackTraceElement element : e.getStackTrace()) {
                    System.out.println(element);
                }
                continue;
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
                        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
                        Gson gson = builder.create();
                        JsonArray json2 = new JsonArray();
                        List<ProfilesProperties> newjson = gson.fromJson(json2, new TypeToken<List<ProfilesProperties>>() {
                        }.getType());

                        String profile_name = model.getValueAt(row, 1).toString();

                        JsonArray data = new JsonArray();
                        JsonReader json;
                        OutputStreamWriter writer;
                        try ( FileReader reader = new FileReader(profiles_directory + File.separator + profile_name.concat(".bb"))) {
                            json = new JsonReader(reader);
                            JsonParser parser = new JsonParser();
                            data.addAll(parser.parse(json).getAsJsonArray());
                            Object idata = data.get(0);
                            ProfilesProperties profile_properties = gson.fromJson(idata.toString(), ProfilesProperties.class
                            );
                            profile_properties.setEnabled(true);
                            newjson.clear();
                            newjson.add(profile_properties);
                            FileOutputStream fileStream = new FileOutputStream(profiles_directory + File.separator + profile_name.concat(".bb"));
                            String fjson = gson.toJson(newjson);
                            writer = new OutputStreamWriter(fileStream, "UTF-8");
                            writer.write(fjson);
                        }
                        writer.close();
                        json.close();
                        checkProfilesProperties(profiles_directory);

                    } catch (Exception ex) {
                        System.out.println("BurpBountyGui line 1956:" + ex.getMessage());
                        for (StackTraceElement element : ex.getStackTrace()) {
                            System.out.println(element);
                        }
                    }
                } else {
                    try {
                        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
                        Gson gson = builder.create();
                        JsonArray json2 = new JsonArray();
                        List<ProfilesProperties> newjson = gson.fromJson(json2, new TypeToken<List<ProfilesProperties>>() {
                        }.getType());
                        String profile_name = model.getValueAt(row, 1).toString();
                        JsonArray data = new JsonArray();
                        JsonReader json;
                        try ( FileReader reader = new FileReader(profiles_directory + File.separator + profile_name.concat(".bb"))) {
                            json = new JsonReader(reader);
                            JsonParser parser = new JsonParser();
                            data.addAll(parser.parse(json).getAsJsonArray());
                            Object idata = data.get(0);
                            ProfilesProperties profile_properties = gson.fromJson(idata.toString(), ProfilesProperties.class
                            );
                            profile_properties.setEnabled(false);
                            newjson.clear();
                            newjson.add(profile_properties);
                            FileOutputStream fileStream = new FileOutputStream(profiles_directory + File.separator + profile_name.concat(".bb"));
                            String fjson = gson.toJson(newjson);
                            try ( OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8")) {
                                writer.write(fjson);
                            }
                        }
                        json.close();
                        checkProfilesProperties(profiles_directory);

                    } catch (Exception ex) {
                        System.out.println("BurpBountyGui line 1956:" + ex.getMessage());
                        for (StackTraceElement element : ex.getStackTrace()) {
                            System.out.println(element);
                        }
                    }
                }

            }

        }
    }


    public int getContentLength(IHttpRequestResponse response) {
        IResponseInfo response_info;
        try {
            response_info = helpers.analyzeResponse(response.getResponse());
        } catch (NullPointerException ex) {
            System.out.println("Utils line 1279: " + ex.getMessage());
            return 0;
        }

        int ContentLength = 0;

        for (String headers : response_info.getHeaders()) {
            if (headers.toUpperCase().startsWith("CONTENT-LENGTH:")) {
                ContentLength = Integer.parseInt(headers.split("\\s+")[1]);
                break;
            }
        }
        return ContentLength;
    }

   

    public void showProfiles(String Tag) {
        JsonArray json = getProfiles();
        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
        Gson gson = builder.create();
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

        TableRowSorter<TableModel> sorter3 = new TableRowSorter<>(table3.getModel());
        table3.setRowSorter(sorter3);
        List<RowSorter.SortKey> sortKeys3 = new ArrayList<>();
        sortKeys3.add(new RowSorter.SortKey(1, SortOrder.ASCENDING));
        sorter3.setSortKeys(sortKeys3);
        sorter3.sort();

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
        List<RowSorter.SortKey> sortKeys1 = new ArrayList<>();
        sortKeys1.add(new RowSorter.SortKey(1, SortOrder.ASCENDING));
        sorter1.setSortKeys(sortKeys1);
        sorter1.sort();
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
        List<RowSorter.SortKey> sortKeys2 = new ArrayList<>();
        sortKeys2.add(new RowSorter.SortKey(1, SortOrder.ASCENDING));
        sorter2.setSortKeys(sortKeys1);
        sorter2.sort();
        table2.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table2.getModel().addTableModelListener(new profilesModelListener());

        if (json != null) {
            for (JsonElement pa : json) {
                JsonObject bbObj = pa.getAsJsonObject();
                profile_property = gson.fromJson(bbObj.toString(), ProfilesProperties.class
                );

                if (Tag.equals("All")) {
                    if (profile_property.getScanner() == 1) {
                        model.addRow(new Object[]{profile_property.getEnabled(), profile_property.getProfileName(), profile_property.getAuthor()});
                    } else if (profile_property.getScanner() == 2) {
                        model2.addRow(new Object[]{profile_property.getEnabled(), profile_property.getProfileName(), profile_property.getAuthor()});
                    } else if (profile_property.getScanner() == 3) {
                        model1.addRow(new Object[]{profile_property.getEnabled(), profile_property.getProfileName(), profile_property.getAuthor()});

                    }

                } else {

                    try {
                        for (String tag : profile_property.getTags()) {
                            if (tag.equals(Tag) || Tag.isEmpty() || Tag.equals("All")) {
                                if (profile_property.getScanner() == 1) {
                                    model.addRow(new Object[]{profile_property.getEnabled(), profile_property.getProfileName(), profile_property.getAuthor()});
                                } else if (profile_property.getScanner() == 2) {
                                    model2.addRow(new Object[]{profile_property.getEnabled(), profile_property.getProfileName(), profile_property.getAuthor()});
                                } else if (profile_property.getScanner() == 3) {
                                    model1.addRow(new Object[]{profile_property.getEnabled(), profile_property.getProfileName(), profile_property.getAuthor()});

                                }

                            }
                        }
                    } catch (NullPointerException e) {
                        for (StackTraceElement element : e.getStackTrace()) {
                            System.out.println(element);
                        }
                        if (profile_property.getScanner() == 1) {
                            model.addRow(new Object[]{profile_property.getEnabled(), profile_property.getProfileName(), profile_property.getAuthor()});
                        } else if (profile_property.getScanner() == 2) {
                            model2.addRow(new Object[]{profile_property.getEnabled(), profile_property.getProfileName(), profile_property.getAuthor()});
                        } else if (profile_property.getScanner() == 3) {
                            model1.addRow(new Object[]{profile_property.getEnabled(), profile_property.getProfileName(), profile_property.getAuthor()});

                        }

                    }
                }
            }
        }
    }

    public void deleteProfile(JTable table) {

        GsonBuilder builder = new GsonBuilder().setPrettyPrinting();
        Gson gson = builder.create();
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
                        FileReader reader = new FileReader(file.getAbsolutePath());
                        JsonReader json = new JsonReader(reader);
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());

                        Object idata = data.get(0);
                        ProfilesProperties i = gson.fromJson(idata.toString(), ProfilesProperties.class
                        );
                        String pname = table.getValueAt(row, 1).toString();

                        if (pname.equals(i.getProfileName())) {
                            reader.close();
                            json.close();
                            Files.delete(file.toPath());
                            break;
                        }

                        reader.close();
                    } catch (IOException e) {
                        System.out.println("BurpBountyGui line 2490:" + e.getMessage());
                        for (StackTraceElement element : e.getStackTrace()) {
                            System.out.println(element);
                        }
                    }
                }
            }
        }
        checkProfilesProperties(profiles_directory);
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
                BufferedWriter out = new BufferedWriter(new FileWriter(profiles_directory + File.separator + "tags.txt", true));
                out.write(str.concat("\n"));
                out.close();
            } catch (IOException e) {
                System.out.println("BurpBountyGui line 2497:" + e.getMessage());
                for (StackTraceElement element : e.getStackTrace()) {
                    System.out.println(element);
                }
            }
        }
    }

    public void removeTag(String tag) {
        String file = profiles_directory + File.separator + "tags.txt";
        try {

            File inFile = new File(file);

            if (!inFile.isFile()) {
                System.out.println("BurpBountyGui line 2509:");
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
                System.out.println("Could not delete file, line 2535");
                return;
            }

            //Rename the new file to the filename the original file had.
            if (!tempFile.renameTo(inFile)) {
                System.out.println("Could not rename file line 2541");
            }

        } catch (FileNotFoundException ex) {
            System.out.println("BurpBountyGui line 2559:" + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        } catch (IOException ex) {
            System.out.println("BurpBountyGui line 2562:" + ex.getMessage());
            for (StackTraceElement element : ex.getStackTrace()) {
                System.out.println(element);
            }
        }
    }

    public void showTags() {

        List<String> tags = readFile(profiles_directory + File.separator + "tags.txt");

        newTagCombo2.removeAllItems();
        tagmanager.removeAllElements();
        for (String tag : tags) {
            newTagCombo2.addItem(tag);
            tagmanager.addElement(tag);
        }
        newTagCombo2.setSelectedItem("All");
    }

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
        jPopupMenu4 = new javax.swing.JPopupMenu();
        jMenuItem8 = new javax.swing.JMenuItem();
        jMenuItem9 = new javax.swing.JMenuItem();
        jSplitPane1 = new javax.swing.JSplitPane();
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
        jPanel10 = new javax.swing.JPanel();
        jLabel57 = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel22 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jLabel23 = new javax.swing.JLabel();
        jLabel24 = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jLabel58 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        jPanel8 = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();

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

        jMenuItem8.setText("Enable");
        jMenuItem8.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem8ActionPerformed(evt);
            }
        });
        jPopupMenu4.add(jMenuItem8);

        jMenuItem9.setText("Disable");
        jMenuItem9.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem9ActionPerformed(evt);
            }
        });
        jPopupMenu4.add(jMenuItem9);

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
        table3.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
        table3.setModel(model);
        table3.setComponentPopupMenu(jPopupMenu1);
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
                .addContainerGap(860, Short.MAX_VALUE))
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel3Layout.createSequentialGroup()
                    .addGap(133, 133, 133)
                    .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 830, Short.MAX_VALUE)
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
                .addContainerGap(743, Short.MAX_VALUE))
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 835, Short.MAX_VALUE))
        );

        jtabpane.addTab("     Active Profiles     ", jPanel3);

        table1.setAutoCreateRowSorter(true);
        table1.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
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
                .addContainerGap(860, Short.MAX_VALUE))
            .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel5Layout.createSequentialGroup()
                    .addGap(133, 133, 133)
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 830, Short.MAX_VALUE)
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
                .addContainerGap(743, Short.MAX_VALUE))
            .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 835, Short.MAX_VALUE))
        );

        jtabpane.addTab("   Passive Request Profiles   ", jPanel5);

        table2.setAutoCreateRowSorter(true);
        table2.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
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
                .addContainerGap(860, Short.MAX_VALUE))
            .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel7Layout.createSequentialGroup()
                    .addGap(133, 133, 133)
                    .addComponent(jScrollPane10, javax.swing.GroupLayout.DEFAULT_SIZE, 830, Short.MAX_VALUE)
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
                .addContainerGap(743, Short.MAX_VALUE))
            .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jScrollPane10, javax.swing.GroupLayout.DEFAULT_SIZE, 835, Short.MAX_VALUE))
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
                            .addComponent(jLabel51)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jButton5, javax.swing.GroupLayout.DEFAULT_SIZE, 108, Short.MAX_VALUE)
                                    .addComponent(jButton1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(text11, javax.swing.GroupLayout.PREFERRED_SIZE, 700, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jLabel48, javax.swing.GroupLayout.PREFERRED_SIZE, 575, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel49)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jButton11, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(jButton12, javax.swing.GroupLayout.PREFERRED_SIZE, 105, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jScrollPane13, javax.swing.GroupLayout.PREFERRED_SIZE, 700, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(0, 160, Short.MAX_VALUE)))
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
                .addGap(18, 18, 18)
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
                .addContainerGap(544, Short.MAX_VALUE))
        );

        jPanel4Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jButton1, jButton5});

        jTabbedPane2.addTab("     Options     ", jPanel4);

        jPanel10.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                goWebBurp(evt);
            }
        });

        jLabel57.setFont(new java.awt.Font("Lucida Grande", 1, 36)); // NOI18N
        jLabel57.setForeground(new java.awt.Color(229, 92, 58));
        jLabel57.setText("About Pro.");

        jLabel12.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
        jLabel12.setText("<html><p style=\"text-align: justify;\"> Burp Bounty Pro is a Burp Suite Pro extension that improves the active and passive scanner by means of advanced and customized vulnerability profiles through a very intuitive graphical interface.  <br><br> On the one hand, it acts as a the most advanced and flexible web application vulnerability scanner, being able to add your own vulnerability profiles, or add your own custom payloads/requests to the existing vulnerability profiles.  <br><br> On the other hand, it can simulate a manual pentest in search of maximum efficiency, without making unnecessary requests, it scans the targets only for those potentially vulnerable parameters, with the most effective payloads.   <br><br> Finally, this extension also helps you by collecting valuable information when performing the manual pentest, such as possible vulnerable parameters, versions detection and more.</p></html>");
        jLabel12.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jLabel6.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(0, 78, 112));
        jLabel6.setText("You are using Burp Bounty Free 4.0");

        jLabel22.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel22.setText("By using this software your are accepting the");

        jLabel7.setFont(new java.awt.Font("Tahoma", 1, 30)); // NOI18N
        jLabel7.setForeground(new java.awt.Color(229, 99, 58));
        jLabel7.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        jLabel7.setText("<html>Ride First<br> on Bug Hunting.</html>");

        jLabel23.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel23.setIcon(new javax.swing.ImageIcon(getClass().getResource("/logo_free.png"))); // NOI18N

        jLabel24.setText("<html><a href=\\\"\\\">EULA</a></html>");
        jLabel24.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jLabel24goWeb(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
        jLabel1.setText("<html><p style=\"text-align: justify;\"> Burp Bounty Free is a Burp Suite extension that allows you, in a quick and simple way, to improve the active and passive Burp Suite scanner by means of personalized profiles through a very intuitive graphical interface. Through an advanced search of patterns and an improvement of the payload to send, we can create our own issue profiles both in the active scanner and in the passive.</p></html>");

        jLabel58.setFont(new java.awt.Font("Lucida Grande", 1, 36)); // NOI18N
        jLabel58.setForeground(new java.awt.Color(229, 92, 58));
        jLabel58.setText("About Free.");

        jLabel3.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
        jLabel3.setText("<html><p style=\"text-align: justify;\">If you need more power, I invite you to try the new Burp Bounty Pro, which gives you more power and automation during your manual pentests.</p></html>");

        jLabel10.setFont(new java.awt.Font("Arial", 0, 24)); // NOI18N
        jLabel10.setForeground(new java.awt.Color(0, 78, 112));
        jLabel10.setText("<html>More information at: <a href=\\\"\\\">https://burpbounty.net</a></html>");

        javax.swing.GroupLayout jPanel10Layout = new javax.swing.GroupLayout(jPanel10);
        jPanel10.setLayout(jPanel10Layout);
        jPanel10Layout.setHorizontalGroup(
            jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel10Layout.createSequentialGroup()
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGap(14, 14, 14)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jLabel58)
                            .addComponent(jLabel57)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel10Layout.createSequentialGroup()
                                .addComponent(jLabel23, javax.swing.GroupLayout.DEFAULT_SIZE, 428, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 262, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                            .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                            .addComponent(jLabel12, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel10Layout.createSequentialGroup()
                                .addComponent(jLabel6)
                                .addGap(202, 202, 202))))
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGap(206, 206, 206)
                        .addComponent(jLabel22)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel24, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGap(131, 131, 131)
                        .addComponent(jLabel10, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(1138, Short.MAX_VALUE))
        );
        jPanel10Layout.setVerticalGroup(
            jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel10Layout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jLabel23, javax.swing.GroupLayout.PREFERRED_SIZE, 115, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(27, 27, 27)
                .addComponent(jLabel58)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel57)
                .addGap(18, 18, 18)
                .addComponent(jLabel12, javax.swing.GroupLayout.PREFERRED_SIZE, 237, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 61, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel10, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel22, javax.swing.GroupLayout.PREFERRED_SIZE, 27, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel24, javax.swing.GroupLayout.PREFERRED_SIZE, 27, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(133, Short.MAX_VALUE))
        );

        jTabbedPane2.addTab("     About     ", jPanel10);

        jLabel5.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Tabla.png"))); // NOI18N
        jLabel5.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                goImageWeb(evt);
            }
        });

        javax.swing.GroupLayout jPanel8Layout = new javax.swing.GroupLayout(jPanel8);
        jPanel8.setLayout(jPanel8Layout);
        jPanel8Layout.setHorizontalGroup(
            jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel8Layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addComponent(jLabel5)
                .addContainerGap(789, Short.MAX_VALUE))
        );
        jPanel8Layout.setVerticalGroup(
            jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel8Layout.createSequentialGroup()
                .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 714, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 271, Short.MAX_VALUE))
        );

        jTabbedPane2.addTab("     Burp Bounty Pro     ", jPanel8);

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

    }//GEN-LAST:event_showprofiles

    private void profilesReload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_profilesReload

        String fileload = text11.getText();

        profiles_directory = fileload;
        checkProfilesProperties(profiles_directory);

        makeTagsFile();
        showTags();
        showProfiles("All");
        this.callbacks.saveExtensionSetting("filename", fileload);
    }//GEN-LAST:event_profilesReload

    private void loadConfigFile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadConfigFile
        loadConfigFile();
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
                    ProfilesManager profile_manager = new ProfilesManager(profiles_directory);
                    profile_manager.saveActiveAttackValues(profile);
                    checkProfilesProperties(profiles_directory);
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

        dialog.setSize(new Dimension(920, 760));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(null);

        ProfilesManager profile_manager = new ProfilesManager(profiles_directory);
        profile_manager.setActiveAttackValues(profile_name, allprofiles, profile);

        dialog.setVisible(true);
        Object selectedValue = jopane1.getValue();

        if (selectedValue != null) {
            result = ((Integer) selectedValue).intValue();

            if (result == JOptionPane.OK_OPTION) {
                profile_manager.saveActiveAttackValues(profile);
                checkProfilesProperties(profiles_directory);
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
                    ProfilesManager profile_manager = new ProfilesManager(profiles_directory);
                    profile_manager.saveRequestAttackValues(profile);
                    checkProfilesProperties(profiles_directory);
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

        dialog.setSize(new Dimension(920, 760));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(null);

        ProfilesManager profile_manager = new ProfilesManager(profiles_directory);
        profile_manager.setRequestAttackValues(profile_name, allprofiles, profile);

        dialog.setVisible(true);
        Object selectedValue = jopane1.getValue();

        if (selectedValue != null) {
            result = ((Integer) selectedValue).intValue();
            if (result == JOptionPane.OK_OPTION) {
                profile_manager.saveRequestAttackValues(profile);
                checkProfilesProperties(profiles_directory);
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
                    ProfilesManager profile_manager = new ProfilesManager(profiles_directory);
                    profile_manager.saveResponseAttackValues(profile);
                    checkProfilesProperties(profiles_directory);
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

        dialog.setSize(new Dimension(920, 760));
        dialog.setResizable(true);
        dialog.setLocationRelativeTo(null);

        ProfilesManager profile_manager = new ProfilesManager(profiles_directory);
        profile_manager.setResponseAttackValues(profile_name, allprofiles, profile);

        dialog.setVisible(true);
        Object selectedValue = jopane1.getValue();

        if (selectedValue != null) {
            result = ((Integer) selectedValue).intValue();
            if (result == JOptionPane.OK_OPTION) {
                profile_manager.saveResponseAttackValues(profile);
                checkProfilesProperties(profiles_directory);
                showProfiles("All");
                showTags();
            }
        }
    }//GEN-LAST:event_editResponseProfile



    private void jMenuItem8ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem8ActionPerformed

    }//GEN-LAST:event_jMenuItem8ActionPerformed

    private void jMenuItem9ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem9ActionPerformed

    }//GEN-LAST:event_jMenuItem9ActionPerformed

    private void jLabel24goWeb(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel24goWeb
        try {
            Desktop.getDesktop().browse(new URI("https://burpbounty.net/legal"));
        } catch (URISyntaxException | IOException e) {
            callbacks.printError("Burp Bounty Gui 4383 Help web not opened: " + e);
        }
    }//GEN-LAST:event_jLabel24goWeb

    private void goWebBurp(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_goWebBurp
        try {
            Desktop.getDesktop().browse(new URI("https://burpbounty.net"));
        } catch (URISyntaxException | IOException e) {
           callbacks.printError("Active profile line 2109 Help web not opened: " + e);
        }
    }//GEN-LAST:event_goWebBurp

    private void goImageWeb(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_goImageWeb
          try {
            Desktop.getDesktop().browse(new URI("https://burpbounty.net"));
        } catch (URISyntaxException | IOException e) {
            callbacks.printError("Burp Bounty Gui 4383 Help web not opened: " + e);
        }
    }//GEN-LAST:event_goImageWeb

    


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
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel22;
    public javax.swing.JLabel jLabel23;
    private javax.swing.JLabel jLabel24;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel43;
    private javax.swing.JLabel jLabel44;
    private javax.swing.JLabel jLabel45;
    private javax.swing.JLabel jLabel48;
    private javax.swing.JLabel jLabel49;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel50;
    private javax.swing.JLabel jLabel51;
    private javax.swing.JLabel jLabel57;
    private javax.swing.JLabel jLabel58;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JMenuItem jMenuItem2;
    private javax.swing.JMenuItem jMenuItem3;
    private javax.swing.JMenuItem jMenuItem4;
    private javax.swing.JMenuItem jMenuItem5;
    private javax.swing.JMenuItem jMenuItem6;
    private javax.swing.JMenuItem jMenuItem7;
    private javax.swing.JMenuItem jMenuItem8;
    private javax.swing.JMenuItem jMenuItem9;
    public javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel10;
    private javax.swing.JPanel jPanel3;
    public javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    public javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JPanel jPanel8;
    private javax.swing.JPopupMenu jPopupMenu1;
    private javax.swing.JPopupMenu jPopupMenu2;
    private javax.swing.JPopupMenu jPopupMenu3;
    private javax.swing.JPopupMenu jPopupMenu4;
    private javax.swing.JScrollPane jScrollPane10;
    private javax.swing.JScrollPane jScrollPane13;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JSeparator jSeparator13;
    private javax.swing.JSplitPane jSplitPane1;
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
