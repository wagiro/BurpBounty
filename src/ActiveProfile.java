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
import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.DefaultCellEditor;
import javax.swing.DefaultListModel;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

/**
 *
 * @author eduardogarcia
 */
public class ActiveProfile extends javax.swing.JPanel {

    /**
     * Creates new form ActiveProfile
     */
    DefaultListModel payload;
    DefaultListModel grep;
    DefaultListModel encoder;
    DefaultListModel tag;
    DefaultListModel tagmanager;
    List<Headers> headers;
    List<String> variationAttributes;
    List<Integer> insertionPointType;
    List<String> Tags;
    Boolean pathDiscovery;
    DefaultTableModel model;
    DefaultTableModel model1;
    DefaultTableModel model2;
    DefaultTableModel model4;
    DefaultTableModel model9;
    DefaultTableModel model10;
    DefaultTableModel modelgrep;
    IBurpExtenderCallbacks callbacks;
    String filename;

    public ActiveProfile(IBurpExtenderCallbacks callbacks) {

        payload = new DefaultListModel();
        grep = new DefaultListModel();
        encoder = new DefaultListModel();
        tag = new DefaultListModel();
        tagmanager = new DefaultListModel();
        model4 = new DefaultTableModel();
        model9 = new DefaultTableModel();
        model10 = new DefaultTableModel();
        modelgrep = new DefaultTableModel();
        headers = new ArrayList();
        variationAttributes = new ArrayList();
        insertionPointType = new ArrayList();
        this.callbacks = callbacks;

        modelgrep = new DefaultTableModel() {
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
                if (column == 1) {
                    return false;
                } else {
                    return true;
                }
            }
        };

        
        initComponents();
        if (callbacks.loadExtensionSetting("filename") != null) {
            filename = callbacks.loadExtensionSetting("filename")+ File.separator;;
        } else {
            filename = System.getProperty("user.home")+ File.separator;;
        }
        showHeaders(headers);
        showGrepsTable();

    }

    public void showGrepsTable() {
        modelgrep.setNumRows(0);
        modelgrep.setColumnCount(0);
        modelgrep.addColumn("Enabled");
        modelgrep.addColumn("Operator");
        modelgrep.addColumn("Value");

        table5.getColumnModel().getColumn(0).setPreferredWidth(5);
        table5.getColumnModel().getColumn(1).setPreferredWidth(15);
        table5.getColumnModel().getColumn(2).setPreferredWidth(400);

        TableRowSorter<TableModel> sorter = new TableRowSorter<>(table5.getModel());
        table5.setRowSorter(sorter);
        List<RowSorter.SortKey> sortKeys = new ArrayList<>();
        sorter.setSortKeys(sortKeys);
        sorter.sort();
    }

    public void showGreps(List<String> greps) {

        for (String grepline : greps) {
            List<String> array = Arrays.asList(grepline.split(",",3));
            if (array.size() > 1) {
                if (array.get(0).equals("true")) {
                    modelgrep.addRow(new Object[]{true, array.get(1), array.get(2)});
                } else {
                    modelgrep.addRow(new Object[]{false, array.get(1), array.get(2)});
                }
            } else {

                modelgrep.addRow(new Object[]{true, "Or", grepline});
            }
        }
    }

    public void loadGrepsFile(DefaultTableModel model) {
        //Load file for implement payloads and match load button
        List<String> grep = new ArrayList();
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
                    grep.add(line);
                    line = bufferreader.readLine();
                }
                bufferreader.close();
                showGreps(grep);
            } catch (FileNotFoundException ex) {
                callbacks.printError("ActiveProfile line 213:" + ex.getMessage());
            } catch (IOException ex) {
                callbacks.printError("ActiveProfile line 215:" + ex.getMessage());
            }
        }
    }

    public void showHeaders(List<Headers> Header) {

        JComboBox jcb = new JComboBox();
        JComboBox jcb1 = new JComboBox();

        //model for active profiles
        model4.setNumRows(0);
        model4.setColumnCount(0);
        model4.addColumn("Item");
        model4.addColumn("Match");
        model4.addColumn("Replace");
        model4.addColumn("Type");

        jcb.addItem("Payload");
        jcb.addItem("Request");
        jcb1.addItem("String");
        jcb1.addItem("Regex");

        table4.getColumnModel().getColumn(0).setPreferredWidth(140);
        table4.getColumnModel().getColumn(1).setPreferredWidth(400);
        table4.getColumnModel().getColumn(2).setPreferredWidth(450);
        table4.getColumnModel().getColumn(3).setPreferredWidth(120);

        table4.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(jcb));
        table4.getColumnModel().getColumn(3).setCellEditor(new DefaultCellEditor(jcb1));
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(table4.getModel());
        table4.setRowSorter(sorter);
        List<RowSorter.SortKey> sortKeys = new ArrayList<>();

        sortKeys.add(new RowSorter.SortKey(0, SortOrder.DESCENDING));
        sorter.setSortKeys(sortKeys);
        sorter.sort();

        for (int i = 0; i < Header.size(); i++) {
            model4.addRow(new Object[]{Header.get(i).type, Header.get(i).match, Header.get(i).replace, Header.get(i).regex});
        }
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
                callbacks.printError("ActivePorfile line 304:" + ex.getMessage());
            }
        }
        return result;
    }

    public void setSelectedInsertionPointType(boolean state) {
        All.setSelected(state);
        extensionprovided.setSelected(state);
        header.setSelected(state);
        entirebody.setSelected(state);
        paramamf.setSelected(state);
        parambody.setSelected(state);
        paramcookie.setSelected(state);
        paramjson.setSelected(state);
        urlpathfolder.setSelected(state);
        parammultipartattr.setSelected(state);
        paramnamebody.setSelected(state);
        paramnameurl.setSelected(state);
        userprovided.setSelected(state);
        paramurl.setSelected(state);
        paramxml.setSelected(state);
        paramxmlattr.setSelected(state);
        urlpathfilename.setSelected(state);
        unknown.setSelected(state);
    }

    public void swap(int a, int b) {
        Object aObject = encoder.getElementAt(a);
        Object bObject = encoder.getElementAt(b);
        encoder.set(a, bObject);
        encoder.set(b, aObject);
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
                callbacks.printError("ActivePorfile line 361:" + ex.getMessage());
            } catch (IOException ex) {
                callbacks.printError("ActivePorfile line 363:" + ex.getMessage());
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
                callbacks.printError("ActivePorfile line 391:" + ex.getMessage());
            } catch (IOException ex) {
                callbacks.printError("ActivePorfile line 393:" + ex.getMessage());
            }
        }
    }

    public void addNewTag(String str) {
        if (!str.isEmpty()) {
            try {
                BufferedWriter out = new BufferedWriter(new FileWriter(filename.concat("tags.txt"), true));
                out.write(str.concat("\n"));
                out.close();
            } catch (IOException e) {
                callbacks.printError("ActivePorfile line 405:" + e.getMessage());
            }
        }
    }

    public void removeTag(String tag) {
        String file = filename.concat("tags.txt");
        try {

            File inFile = new File(file);

            if (!inFile.isFile()) {
                callbacks.printError("ActivePorfile line 417:");
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
                callbacks.printError("Activeprofile line 443 Could not delete file");
                return;
            }

            //Rename the new file to the filename the original file had.
            if (!tempFile.renameTo(inFile)) {
                callbacks.printError("ActiveProfile line 449 Could not rename file");
            }

        } catch (FileNotFoundException ex) {
            callbacks.printError("ActivePorfile line 453:" + ex.getMessage());
        } catch (IOException ex) {
            callbacks.printError("ActivePorfile line 455:" + ex.getMessage());
        }
    }

    public void showTags() {
        List<String> tags = readFile(filename.concat("tags.txt"));

        newTagCombo.removeAllItems();
        tagmanager.removeAllElements();
        for (String tag : tags) {
            newTagCombo.addItem(tag);
            tagmanager.addElement(tag);
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
            callbacks.printError("ActivePorfile line 494:" + e.getMessage());
        }
        return records;
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
        text1 = new javax.swing.JTextField();
        jLabel18 = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        textauthor = new javax.swing.JTextField();
        headerstab = new javax.swing.JTabbedPane();
        jScrollPane5 = new javax.swing.JScrollPane();
        jPanel10 = new javax.swing.JPanel();
        parambody = new javax.swing.JCheckBox();
        jSeparator2 = new javax.swing.JSeparator();
        text5 = new javax.swing.JTextField();
        jButton9 = new javax.swing.JButton();
        button6 = new javax.swing.JButton();
        jScrollPane3 = new javax.swing.JScrollPane();
        list1 = new javax.swing.JList<>();
        jButton8 = new javax.swing.JButton();
        jScrollPane14 = new javax.swing.JScrollPane();
        table4 = new javax.swing.JTable();
        jLabel22 = new javax.swing.JLabel();
        urlpathfolder = new javax.swing.JCheckBox();
        jScrollPane4 = new javax.swing.JScrollPane();
        list3 = new javax.swing.JList<>();
        header = new javax.swing.JCheckBox();
        jSeparator3 = new javax.swing.JSeparator();
        paramurl = new javax.swing.JCheckBox();
        button3 = new javax.swing.JButton();
        jLabel55 = new javax.swing.JLabel();
        paramcookie = new javax.swing.JCheckBox();
        jLabel52 = new javax.swing.JLabel();
        paramnamebody = new javax.swing.JCheckBox();
        button2 = new javax.swing.JButton();
        paramamf = new javax.swing.JCheckBox();
        urlpathfilename = new javax.swing.JCheckBox();
        unknown = new javax.swing.JCheckBox();
        jLabel11 = new javax.swing.JLabel();
        jLabel17 = new javax.swing.JLabel();
        jSeparator4 = new javax.swing.JSeparator();
        button4 = new javax.swing.JButton();
        button18 = new javax.swing.JButton();
        button19 = new javax.swing.JButton();
        combo2 = new javax.swing.JComboBox<>();
        extensionprovided = new javax.swing.JCheckBox();
        parammultipartattr = new javax.swing.JCheckBox();
        paramjson = new javax.swing.JCheckBox();
        paramxmlattr = new javax.swing.JCheckBox();
        paramnameurl = new javax.swing.JCheckBox();
        textpayloads = new javax.swing.JTextField();
        userprovided = new javax.swing.JCheckBox();
        jLabel54 = new javax.swing.JLabel();
        jButton6 = new javax.swing.JButton();
        jLabel19 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        button5 = new javax.swing.JButton();
        replace = new javax.swing.JRadioButton();
        jLabel5 = new javax.swing.JLabel();
        check8 = new javax.swing.JCheckBox();
        textfield1 = new javax.swing.JTextField();
        entirebody = new javax.swing.JCheckBox();
        All = new javax.swing.JCheckBox();
        paramxml = new javax.swing.JCheckBox();
        jLabel23 = new javax.swing.JLabel();
        jLabel53 = new javax.swing.JLabel();
        append = new javax.swing.JRadioButton();
        jButton7 = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jLabel20 = new javax.swing.JLabel();
        jScrollPane6 = new javax.swing.JScrollPane();
        jPanel11 = new javax.swing.JPanel();
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
        jScrollPane15 = new javax.swing.JScrollPane();
        table5 = new javax.swing.JTable();
        button20 = new javax.swing.JButton();
        button10 = new javax.swing.JButton();
        button7 = new javax.swing.JButton();
        button21 = new javax.swing.JButton();
        button8 = new javax.swing.JButton();
        textgreps = new javax.swing.JTextField();
        jScrollPane10 = new javax.swing.JScrollPane();
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

        setPreferredSize(new java.awt.Dimension(800, 600));

        text1.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N

        jLabel18.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel18.setText("Author:");

        jLabel12.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel12.setText("Name:");

        textauthor.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N

        headerstab.setAutoscrolls(true);
        headerstab.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        headerstab.setPreferredSize(new java.awt.Dimension(780, 570));
        headerstab.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                headerstabStateChanged(evt);
            }
        });

        jScrollPane5.setPreferredSize(new java.awt.Dimension(0, 0));
        jScrollPane5.getVerticalScrollBar().setUnitIncrement(20);

        jPanel10.setMaximumSize(new java.awt.Dimension(0, 0));

        parambody.setText("Param body");

        jButton9.setText("Remove");
        jButton9.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton9removeEncoder(evt);
            }
        });

        button6.setText("Add");
        button6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button6setToPayload(evt);
            }
        });

        list1.setModel(payload);
        jScrollPane3.setViewportView(list1);

        jButton8.setText("Up");
        jButton8.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton8upEncoder(evt);
            }
        });

        table4.setFont(new java.awt.Font("Lucida Grande", 0, 13)); // NOI18N
        table4.setModel(model4);
        table4.setShowGrid(false);
        jScrollPane14.setViewportView(table4);

        jLabel22.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel22.setForeground(new java.awt.Color(255, 102, 51));
        jLabel22.setText("Payload Encoding");

        urlpathfolder.setText("Url path folder");

        list3.setModel(encoder);
        jScrollPane4.setViewportView(list3);

        header.setText("Header");

        paramurl.setText("Param url");

        button3.setText("Load File");
        button3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button3loadPayloads(evt);
            }
        });

        jLabel55.setText("You can define the payload options.");

        paramcookie.setText("Param cookie");

        jLabel52.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel52.setForeground(new java.awt.Color(255, 102, 51));
        jLabel52.setText("Match and Replace");

        paramnamebody.setText("Param name body");

        button2.setText("Paste");
        button2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button2pastePayload(evt);
            }
        });

        paramamf.setText("Param AMF");

        urlpathfilename.setText("Url path filename");

        unknown.setText("Unknown");

        jLabel11.setText("Insertion point type:");

        jLabel17.setText("<html> * More info at <a href=\\\"\\\">Burp Suite Extender API</a></html>");
        jLabel17.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jLabel17goWeb(evt);
            }
        });

        button4.setText("Remove");
        button4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button4removePayload(evt);
            }
        });

        button18.setText("Remove");
        button18.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button18removeMatchReplace(evt);
            }
        });

        button19.setText("Add");
        button19.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addMatchReplace(evt);
            }
        });

        combo2.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "URL-encode key characters", "URL-encode all characters", "URL-encode all characters (Unicode)", "HTML-encode key characters", "HTML-encode all characters", "Base64-encode" }));

        extensionprovided.setText("Path discovery");

        parammultipartattr.setText("Param multipart attr");

        paramjson.setText("Param json");

        paramxmlattr.setText("Param xml attr");

        paramnameurl.setText("Param name url");

        textpayloads.setToolTipText("");

        userprovided.setText("User provided");

        jLabel54.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel54.setForeground(new java.awt.Color(255, 102, 51));
        jLabel54.setText("Payload Options");

        jButton6.setText("Add");
        jButton6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton6addEncoder(evt);
            }
        });

        jLabel19.setText("You can define one or more payloads. Each payload of this section will be sent at each insertion point.");

        jLabel10.setText("Payload position:");

        button5.setText("Clear");
        button5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button5removeAllPayloads(evt);
            }
        });

        buttonGroup1.add(replace);
        replace.setText("Replace");

        jLabel5.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel5.setForeground(new java.awt.Color(255, 102, 51));
        jLabel5.setText("Payload ");

        check8.setText("URL-Encode these characters:");

        entirebody.setText("Entire body");

        All.setText("All ");
        All.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                AllItemStateChanged(evt);
            }
        });

        paramxml.setText("Param xml");

        jLabel23.setText("You can define the encoding of payloads. You can encode each payload multiple times.");

        jLabel53.setText("These settings are used to automatically replace part of request when the active scanner run.");

        buttonGroup1.add(append);
        append.setText("Append");

        jButton7.setText("Down");
        jButton7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton7downEncoder(evt);
            }
        });

        jLabel1.setText("- {PAYLOAD} token will be replaced by your payload");

        jLabel20.setText("- {BC} token will be replaced by burpcollaborator host");

        javax.swing.GroupLayout jPanel10Layout = new javax.swing.GroupLayout(jPanel10);
        jPanel10.setLayout(jPanel10Layout);
        jPanel10Layout.setHorizontalGroup(
            jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel10Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel22)
                            .addComponent(jLabel23, javax.swing.GroupLayout.PREFERRED_SIZE, 704, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel54)
                            .addComponent(jLabel55, javax.swing.GroupLayout.PREFERRED_SIZE, 704, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel10Layout.createSequentialGroup()
                                .addGap(6, 6, 6)
                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jLabel53, javax.swing.GroupLayout.PREFERRED_SIZE, 704, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel52)
                                    .addGroup(jPanel10Layout.createSequentialGroup()
                                        .addComponent(check8)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(text5))
                                    .addGroup(jPanel10Layout.createSequentialGroup()
                                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                            .addComponent(jButton9, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                            .addComponent(jButton6, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                            .addComponent(jButton8, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                            .addComponent(jButton7, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGap(18, 18, 18)
                                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                            .addComponent(jScrollPane4)
                                            .addComponent(combo2, 0, 670, Short.MAX_VALUE)))
                                    .addGroup(jPanel10Layout.createSequentialGroup()
                                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(button18, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(button19, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGap(18, 18, 18)
                                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(jLabel1)
                                            .addComponent(jScrollPane14, javax.swing.GroupLayout.PREFERRED_SIZE, 673, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(jLabel20)))))
                            .addGroup(jPanel10Layout.createSequentialGroup()
                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(button6, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(jPanel10Layout.createSequentialGroup()
                                            .addGap(12, 12, 12)
                                            .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                    .addComponent(button3, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                    .addComponent(button4, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE))
                                                .addComponent(button5, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                        .addComponent(button2, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                .addGap(18, 18, 18)
                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 670, Short.MAX_VALUE)
                                    .addComponent(textfield1)
                                    .addComponent(textpayloads)))
                            .addComponent(jLabel19, javax.swing.GroupLayout.PREFERRED_SIZE, 704, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(jPanel10Layout.createSequentialGroup()
                                .addGap(47, 47, 47)
                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel17, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGroup(jPanel10Layout.createSequentialGroup()
                                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                            .addComponent(jLabel10)
                                            .addComponent(jLabel11))
                                        .addGap(18, 18, 18)
                                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addGroup(jPanel10Layout.createSequentialGroup()
                                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                    .addComponent(extensionprovided)
                                                    .addComponent(header)
                                                    .addComponent(urlpathfilename)
                                                    .addComponent(entirebody)
                                                    .addComponent(paramxml)
                                                    .addComponent(All))
                                                .addGap(42, 42, 42)
                                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                    .addComponent(paramjson)
                                                    .addComponent(parambody)
                                                    .addComponent(paramcookie)
                                                    .addComponent(urlpathfolder)
                                                    .addComponent(paramamf)
                                                    .addComponent(paramxmlattr))
                                                .addGap(39, 39, 39)
                                                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                    .addComponent(unknown)
                                                    .addComponent(parammultipartattr)
                                                    .addComponent(paramnamebody)
                                                    .addComponent(paramnameurl)
                                                    .addComponent(userprovided)
                                                    .addComponent(paramurl)))
                                            .addGroup(jPanel10Layout.createSequentialGroup()
                                                .addComponent(replace)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                .addComponent(append))))))
                            .addComponent(jLabel5))
                        .addContainerGap(15, Short.MAX_VALUE))))
            .addComponent(jSeparator2)
            .addComponent(jSeparator4)
            .addComponent(jSeparator3, javax.swing.GroupLayout.Alignment.TRAILING)
        );
        jPanel10Layout.setVerticalGroup(
            jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel10Layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel19)
                .addGap(25, 25, 25)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(textpayloads, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(button3))
                .addGap(18, 18, 18)
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
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel54)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel55)
                .addGap(23, 23, 23)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel10)
                    .addComponent(append)
                    .addComponent(replace))
                .addGap(32, 32, 32)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addComponent(jLabel11)
                        .addGap(154, 154, 154)
                        .addComponent(jLabel17, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jSeparator4, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel52)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel53)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel20)
                        .addGap(18, 18, 18)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel10Layout.createSequentialGroup()
                                .addComponent(button19)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(button18))
                            .addComponent(jScrollPane14, javax.swing.GroupLayout.PREFERRED_SIZE, 119, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(18, 18, 18)
                        .addComponent(jSeparator3, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel22)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel23)
                        .addGap(25, 25, 25)
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
                            .addComponent(text5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(paramamf)
                            .addComponent(parammultipartattr)
                            .addComponent(All))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(parambody)
                            .addComponent(paramnamebody)
                            .addComponent(urlpathfilename))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(extensionprovided)
                            .addComponent(paramcookie)
                            .addComponent(paramurl))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(header)
                            .addComponent(paramjson)
                            .addComponent(paramnameurl))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(entirebody)
                            .addComponent(urlpathfolder)
                            .addComponent(userprovided))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(paramxml)
                            .addComponent(paramxmlattr)
                            .addComponent(unknown))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jScrollPane5.setViewportView(jPanel10);

        headerstab.addTab("     Request     ", jScrollPane5);

        jScrollPane6.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jScrollPane6.getVerticalScrollBar().setUnitIncrement(20);

        jPanel11.setAutoscrolls(true);

        buttonGroup3.add(radio12);
        radio12.setText("Payload");
        radio12.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                radio12payloadMatchType(evt);
            }
        });

        buttonGroup3.add(radio4);
        radio4.setText("Simple string");
        radio4.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                radio4stringMatchType(evt);
            }
        });

        buttonGroup3.add(radio3);
        radio3.setText("Regex");
        radio3.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                radio3regexMatchType(evt);
            }
        });

        buttonGroup3.add(radio22);
        radio22.setText("Payload without encode");
        radio22.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                radio22payloadencodeMatchType(evt);
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
        jLabel25.setText("Grep");

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

        buttonGroup4.add(rb1);
        rb1.setText("Never");

        buttonGroup4.add(rb2);
        rb2.setText("On-site only");

        buttonGroup4.add(rb3);
        rb3.setText("In-scope only");

        buttonGroup4.add(rb4);
        rb4.setText("Always");

        jLabel2.setText("Max redirections:");

        buttonGroup3.add(radiotime);
        radiotime.setText("Timeout equal or more than ");
        radiotime.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                radiotimeTimeoutSelect(evt);
            }
        });

        jLabel6.setText("Follow redirections: ");

        jLabel42.setText("Bytes");

        buttonGroup3.add(radiocl);
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

        buttonGroup3.add(variationsRadio);
        variationsRadio.setText("Variations");
        variationsRadio.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                variationsRadiovariations(evt);
            }
        });

        buttonGroup3.add(invariationsRadio);
        invariationsRadio.setText("Invariations");
        invariationsRadio.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                invariationsRadioinvariations(evt);
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

        table5.setFont(new java.awt.Font("Lucida Grande", 0, 13)); // NOI18N
        table5.setModel(modelgrep);
        table5.setShowGrid(false);
        jScrollPane15.setViewportView(table5);

        button20.setText("Remove");
        button20.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button20removeMatchReplace(evt);
            }
        });

        button10.setText("Clear");
        button10.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button10removeAllGrep(evt);
            }
        });

        button7.setText("Paste");
        button7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button7pasteGrep(evt);
            }
        });

        button21.setText("Add");
        button21.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button21addGrep(evt);
            }
        });

        button8.setText("Load File");
        button8.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button8loadGrep(evt);
            }
        });

        javax.swing.GroupLayout jPanel11Layout = new javax.swing.GroupLayout(jPanel11);
        jPanel11.setLayout(jPanel11Layout);
        jPanel11Layout.setHorizontalGroup(
            jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSeparator5)
            .addComponent(jSeparator6, javax.swing.GroupLayout.Alignment.TRAILING)
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addComponent(jSeparator12)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator11, javax.swing.GroupLayout.PREFERRED_SIZE, 846, javax.swing.GroupLayout.PREFERRED_SIZE))
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
                                    .addComponent(text71, javax.swing.GroupLayout.DEFAULT_SIZE, 441, Short.MAX_VALUE)
                                    .addComponent(text72))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(negativeCT)
                                    .addComponent(negativeRC)))
                            .addComponent(jLabel29)
                            .addComponent(jLabel28, javax.swing.GroupLayout.PREFERRED_SIZE, 769, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel25)
                            .addComponent(jLabel24, javax.swing.GroupLayout.PREFERRED_SIZE, 769, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel27)
                            .addComponent(jLabel26, javax.swing.GroupLayout.PREFERRED_SIZE, 769, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(Attributes, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(variationsRadio)))
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(jPanel11Layout.createSequentialGroup()
                                .addComponent(button8, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(textgreps, javax.swing.GroupLayout.PREFERRED_SIZE, 662, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel11Layout.createSequentialGroup()
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addComponent(button20, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(button10, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(button7, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(button21, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addComponent(jScrollPane15, javax.swing.GroupLayout.PREFERRED_SIZE, 662, javax.swing.GroupLayout.PREFERRED_SIZE)))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel11Layout.setVerticalGroup(
            jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addComponent(jLabel27)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel26)
                .addGap(25, 25, 25)
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
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel25)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel24)
                .addGap(18, 18, 18)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(textgreps, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(button8))
                .addGap(18, 18, Short.MAX_VALUE)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addComponent(button21)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button7)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button10)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button20))
                    .addComponent(jScrollPane15, javax.swing.GroupLayout.PREFERRED_SIZE, 128, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel31)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel30)
                .addGap(25, 25, 25)
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
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel29)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel28)
                .addGap(25, 25, 25)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(rb1)
                    .addComponent(jLabel6))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(rb2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(rb3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(rb4)
                .addGap(18, 18, 18)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(sp1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        JScrollPane responseresScroll = new JScrollPane(jPanel11,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        jScrollPane6.setViewportView(jPanel11);

        headerstab.addTab("     Response     ", jScrollPane6);

        jScrollPane10.getVerticalScrollBar().setUnitIncrement(20);

        jPanel12.setAutoscrolls(true);

        jLabel32.setText("You can define the issue properties.");

        jLabel33.setFont(new java.awt.Font("Lucida Grande", 1, 14)); // NOI18N
        jLabel33.setForeground(new java.awt.Color(255, 102, 51));
        jLabel33.setText("Issue Properties");

        jLabel3.setText("Issue Name:");

        jLabel4.setText("Severity:");

        buttonGroup5.add(radio5);
        radio5.setText("High");

        buttonGroup5.add(radio6);
        radio6.setText("Medium");

        buttonGroup5.add(radio7);
        radio7.setText("Low");

        buttonGroup5.add(radio8);
        radio8.setText("Information");

        jLabel7.setText("Confidence:");

        buttonGroup6.add(radio9);
        radio9.setText("Certain");

        buttonGroup6.add(radio10);
        radio10.setText("Firm");

        buttonGroup6.add(radio11);
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
            .addComponent(jSeparator7)
            .addComponent(jSeparator8, javax.swing.GroupLayout.Alignment.TRAILING)
            .addComponent(jSeparator9, javax.swing.GroupLayout.Alignment.TRAILING)
            .addComponent(jSeparator10, javax.swing.GroupLayout.Alignment.TRAILING)
            .addGroup(jPanel12Layout.createSequentialGroup()
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel12Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
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
                                    .addComponent(text4, javax.swing.GroupLayout.PREFERRED_SIZE, 419, javax.swing.GroupLayout.PREFERRED_SIZE)))))
                    .addComponent(jLabel41)
                    .addComponent(jLabel40))
                .addContainerGap(93, Short.MAX_VALUE))
        );
        jPanel12Layout.setVerticalGroup(
            jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel12Layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addComponent(jLabel33)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel32)
                .addGap(25, 25, 25)
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
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel35)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel34)
                .addGap(25, 25, 25)
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel9)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator8, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel37)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel36)
                .addGap(25, 25, 25)
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel13)
                    .addComponent(jScrollPane7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator9, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel39)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel38)
                .addGap(25, 25, 25)
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel15)
                    .addComponent(jScrollPane9, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator10, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel41)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel40)
                .addGap(25, 25, 25)
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel14)
                    .addComponent(jScrollPane8, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jScrollPane10.setViewportView(jPanel12);

        headerstab.addTab("     Issue     ", jScrollPane10);

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
                newTagbnewTag(evt);
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
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addComponent(jLabel47)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel46)
                .addGap(25, 25, 25)
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
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        headerstab.addTab("          Tags          ", jPanel3);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel12)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(text1)
                .addGap(18, 18, 18)
                .addComponent(jLabel18)
                .addGap(18, 18, 18)
                .addComponent(textauthor, javax.swing.GroupLayout.PREFERRED_SIZE, 228, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
            .addComponent(headerstab, javax.swing.GroupLayout.DEFAULT_SIZE, 831, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(text1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel12)
                    .addComponent(textauthor, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel18))
                .addGap(18, 18, 18)
                .addComponent(headerstab, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void jButton9removeEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton9removeEncoder
        int selectedIndex = list3.getSelectedIndex();
        if (selectedIndex != -1) {
            encoder.remove(selectedIndex);
        }
    }//GEN-LAST:event_jButton9removeEncoder

    private void button6setToPayload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button6setToPayload
        if (!textfield1.getText().isEmpty()) {
            payload.addElement(textfield1.getText());
            textfield1.setText("");
        }
    }//GEN-LAST:event_button6setToPayload

    private void jButton8upEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton8upEncoder
        int selectedIndex = list3.getSelectedIndex();
        if (selectedIndex != 0) {
            swap(selectedIndex, selectedIndex - 1);
            list3.setSelectedIndex(selectedIndex - 1);
            list3.ensureIndexIsVisible(selectedIndex - 1);

        }
    }//GEN-LAST:event_jButton8upEncoder

    private void button3loadPayloads(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button3loadPayloads
        loadPayloadsFile(payload);
    }//GEN-LAST:event_button3loadPayloads

    private void button2pastePayload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button2pastePayload

        String element = getClipboardContents();
        String[] lines = element.split("\n");
        for (String line : lines) {
            payload.addElement(line);
        }
    }//GEN-LAST:event_button2pastePayload

    private void jLabel17goWeb(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel17goWeb
        try {
            Desktop.getDesktop().browse(new URI("https://portswigger.net/burp/extender/api/burp/IScannerInsertionPoint.html"));
        } catch (URISyntaxException | IOException e) {
            callbacks.printError("Active profile line 2109 Help web not opened: " + e);
        }
    }//GEN-LAST:event_jLabel17goWeb

    private void button4removePayload(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button4removePayload
        int selectedIndex = list1.getSelectedIndex();
        if (selectedIndex != -1) {
            payload.remove(selectedIndex);
        }
    }//GEN-LAST:event_button4removePayload

    private void button18removeMatchReplace(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button18removeMatchReplace
        int[] rows = table4.getSelectedRows();
        Arrays.sort(rows);
        for (int i = rows.length - 1; i >= 0; i--) {
            int row = rows[i];
            int modelRow = table4.convertRowIndexToModel(row);
            model4.removeRow(modelRow);
        }
    }//GEN-LAST:event_button18removeMatchReplace

    private void addMatchReplace(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addMatchReplace
        model4.addRow(new Object[]{"Payload", "Leave blank to add a new header", "Leave blank to remove a matched header", "String"});
    }//GEN-LAST:event_addMatchReplace

    private void jButton6addEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton6addEncoder
        if (!encoder.isEmpty() && encoder.firstElement().equals(" ")) {
            encoder.removeElementAt(0);
            encoder.addElement(combo2.getSelectedItem().toString());
        } else {
            encoder.addElement(combo2.getSelectedItem().toString());
        }
    }//GEN-LAST:event_jButton6addEncoder

    private void button5removeAllPayloads(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button5removeAllPayloads
        payload.removeAllElements();
    }//GEN-LAST:event_button5removeAllPayloads

    private void AllItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_AllItemStateChanged
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            extensionprovided.setSelected(true);
            header.setSelected(true);
            entirebody.setSelected(true);
            paramamf.setSelected(true);
            parambody.setSelected(true);
            paramcookie.setSelected(true);
            paramjson.setSelected(true);
            urlpathfolder.setSelected(true);
            parammultipartattr.setSelected(true);
            paramnamebody.setSelected(true);
            paramnameurl.setSelected(true);
            userprovided.setSelected(true);
            paramurl.setSelected(true);
            paramxml.setSelected(true);
            paramxmlattr.setSelected(true);
            urlpathfilename.setSelected(true);
            unknown.setSelected(true);
        } else {
            extensionprovided.setSelected(false);
            header.setSelected(false);
            entirebody.setSelected(false);
            paramamf.setSelected(false);
            parambody.setSelected(false);
            paramcookie.setSelected(false);
            paramjson.setSelected(false);
            urlpathfolder.setSelected(false);
            parammultipartattr.setSelected(false);
            paramnamebody.setSelected(false);
            paramnameurl.setSelected(false);
            userprovided.setSelected(false);
            paramurl.setSelected(false);
            paramxml.setSelected(false);
            paramxmlattr.setSelected(false);
            urlpathfilename.setSelected(false);
            unknown.setSelected(false);
        }
    }//GEN-LAST:event_AllItemStateChanged

    private void jButton7downEncoder(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton7downEncoder
        int selectedIndex = list3.getSelectedIndex();
        if (selectedIndex != encoder.getSize() - 1) {
            swap(selectedIndex, selectedIndex + 1);
            list3.setSelectedIndex(selectedIndex + 1);
            list3.ensureIndexIsVisible(selectedIndex + 1);

        }
    }//GEN-LAST:event_jButton7downEncoder

    private void radio12payloadMatchType(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_radio12payloadMatchType
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
        }
    }//GEN-LAST:event_radio12payloadMatchType

    private void radio4stringMatchType(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_radio4stringMatchType
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
        }
    }//GEN-LAST:event_radio4stringMatchType

    private void radio3regexMatchType(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_radio3regexMatchType
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
        }
    }//GEN-LAST:event_radio3regexMatchType

    private void radio22payloadencodeMatchType(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_radio22payloadencodeMatchType
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
        }
    }//GEN-LAST:event_radio22payloadencodeMatchType

    private void radiotimeTimeoutSelect(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_radiotimeTimeoutSelect
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
        } else if (evt.getStateChange() == java.awt.event.ItemEvent.DESELECTED) {
            setEnabledVariations(true);
        }
    }//GEN-LAST:event_radiotimeTimeoutSelect

    private void radioclSelect(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_radioclSelect
        if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(false);
        } else if (evt.getStateChange() == java.awt.event.ItemEvent.DESELECTED) {
            setEnabledVariations(true);
        }
    }//GEN-LAST:event_radioclSelect

    private void radioclActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_radioclActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_radioclActionPerformed

    private void variationsRadiovariations(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_variationsRadiovariations
        if (evt.getStateChange() == java.awt.event.ItemEvent.DESELECTED) {
            setEnabledVariations(false);
        } else if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(true);
        }
    }//GEN-LAST:event_variationsRadiovariations

    private void invariationsRadioinvariations(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_invariationsRadioinvariations
        if (evt.getStateChange() == java.awt.event.ItemEvent.DESELECTED) {
            setEnabledVariations(false);
        } else if (evt.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
            setEnabledVariations(true);
        }
    }//GEN-LAST:event_invariationsRadioinvariations

    private void removetag(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removetag
        int selectedIndex = listtag.getSelectedIndex();
        if (selectedIndex != -1) {
            tag.remove(selectedIndex);
        }
    }//GEN-LAST:event_removetag

    private void addTag(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addTag
        tag.addElement(newTagCombo.getSelectedItem());
    }//GEN-LAST:event_addTag

    private void newTagbnewTag(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newTagbnewTag
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
    }//GEN-LAST:event_newTagbnewTag

    private void headerstabStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_headerstabStateChanged
        int activePane = headerstab.getSelectedIndex();
        if (activePane == 3) {
            showTags();
        }
    }//GEN-LAST:event_headerstabStateChanged

    private void button20removeMatchReplace(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button20removeMatchReplace
        int[] rows = table5.getSelectedRows();
        Arrays.sort(rows);
        for (int i = rows.length - 1; i >= 0; i--) {
            int row = rows[i];
            int modelRow = table5.convertRowIndexToModel(row);
            modelgrep.removeRow(modelRow);
        }
    }//GEN-LAST:event_button20removeMatchReplace

    private void button10removeAllGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button10removeAllGrep
        int rowCount = modelgrep.getRowCount();
        for (int i = rowCount - 1; i >= 0; i--) {
            modelgrep.removeRow(i);
        }
    }//GEN-LAST:event_button10removeAllGrep

    private void button7pasteGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button7pasteGrep
        String element = getClipboardContents();
        List<String> lines = Arrays.asList(element.split("\n"));
        showGreps(lines);
    }//GEN-LAST:event_button7pasteGrep

    private void button21addGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button21addGrep
        modelgrep.addRow(new Object[]{true, "Or", "Value"});
    }//GEN-LAST:event_button21addGrep

    private void button8loadGrep(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button8loadGrep
        loadGrepsFile(modelgrep);
    }//GEN-LAST:event_button8loadGrep


    // Variables declaration - do not modify//GEN-BEGIN:variables
    public javax.swing.JCheckBox All;
    private javax.swing.JPanel Attributes;
    private javax.swing.JButton addTag;
    public javax.swing.JCheckBox anchor_labels;
    public javax.swing.JRadioButton append;
    private javax.swing.JButton button10;
    private javax.swing.JButton button18;
    private javax.swing.JButton button19;
    public javax.swing.JButton button2;
    private javax.swing.JButton button20;
    private javax.swing.JButton button21;
    public javax.swing.JButton button3;
    public javax.swing.JButton button4;
    public javax.swing.JButton button5;
    public javax.swing.JButton button6;
    private javax.swing.JButton button7;
    private javax.swing.JButton button8;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.ButtonGroup buttonGroup2;
    private javax.swing.ButtonGroup buttonGroup3;
    private javax.swing.ButtonGroup buttonGroup4;
    private javax.swing.ButtonGroup buttonGroup5;
    private javax.swing.ButtonGroup buttonGroup6;
    public javax.swing.JCheckBox button_submit_labels;
    public javax.swing.JCheckBox canonical_link;
    public javax.swing.JCheckBox check1;
    public javax.swing.JCheckBox check4;
    public javax.swing.JCheckBox check71;
    public javax.swing.JCheckBox check72;
    public javax.swing.JCheckBox check8;
    public javax.swing.JComboBox<String> combo2;
    public javax.swing.JCheckBox comments;
    public javax.swing.JCheckBox content_length;
    public javax.swing.JCheckBox content_location;
    public javax.swing.JCheckBox content_type;
    public javax.swing.JCheckBox css_classes;
    public javax.swing.JCheckBox div_ids;
    public javax.swing.JCheckBox entirebody;
    public javax.swing.JCheckBox etag_header;
    public javax.swing.JCheckBox excludehttp;
    public javax.swing.JCheckBox extensionprovided;
    public javax.swing.JCheckBox first_header_tag;
    public javax.swing.JCheckBox header;
    public javax.swing.JCheckBox header_tags;
    public javax.swing.JTabbedPane headerstab;
    public javax.swing.JCheckBox initial_body_content;
    public javax.swing.JCheckBox input_image_labels;
    public javax.swing.JCheckBox input_submit_labels;
    public javax.swing.JRadioButton invariationsRadio;
    private javax.swing.JButton jButton6;
    private javax.swing.JButton jButton7;
    private javax.swing.JButton jButton8;
    private javax.swing.JButton jButton9;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel16;
    private javax.swing.JLabel jLabel17;
    private javax.swing.JLabel jLabel18;
    private javax.swing.JLabel jLabel19;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel20;
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
    private javax.swing.JLabel jLabel46;
    private javax.swing.JLabel jLabel47;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel52;
    private javax.swing.JLabel jLabel53;
    private javax.swing.JLabel jLabel54;
    private javax.swing.JLabel jLabel55;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel9;
    public javax.swing.JPanel jPanel10;
    private javax.swing.JPanel jPanel11;
    private javax.swing.JPanel jPanel12;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane10;
    private javax.swing.JScrollPane jScrollPane11;
    private javax.swing.JScrollPane jScrollPane14;
    private javax.swing.JScrollPane jScrollPane15;
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
    public javax.swing.JCheckBox last_modified_header;
    public javax.swing.JCheckBox limited_body_content;
    public javax.swing.JCheckBox line_count;
    public javax.swing.JList<String> list1;
    public javax.swing.JList<String> list3;
    public javax.swing.JList<String> listtag;
    public javax.swing.JCheckBox location;
    public javax.swing.JCheckBox negativeCT;
    public javax.swing.JCheckBox negativeRC;
    public javax.swing.JComboBox<String> newTagCombo;
    private javax.swing.JButton newTagb;
    public javax.swing.JCheckBox non_hidden_form_input_types;
    public javax.swing.JCheckBox onlyhttp;
    public javax.swing.JCheckBox outbound_edge_count;
    public javax.swing.JCheckBox outbound_edge_tag_names;
    public javax.swing.JCheckBox page_title;
    public javax.swing.JCheckBox paramamf;
    public javax.swing.JCheckBox parambody;
    public javax.swing.JCheckBox paramcookie;
    public javax.swing.JCheckBox paramjson;
    public javax.swing.JCheckBox parammultipartattr;
    public javax.swing.JCheckBox paramnamebody;
    public javax.swing.JCheckBox paramnameurl;
    public javax.swing.JCheckBox paramurl;
    public javax.swing.JCheckBox paramxml;
    public javax.swing.JCheckBox paramxmlattr;
    public javax.swing.JRadioButton radio10;
    public javax.swing.JRadioButton radio11;
    public javax.swing.JRadioButton radio12;
    public javax.swing.JRadioButton radio22;
    public javax.swing.JRadioButton radio3;
    public javax.swing.JRadioButton radio4;
    public javax.swing.JRadioButton radio5;
    public javax.swing.JRadioButton radio6;
    public javax.swing.JRadioButton radio7;
    public javax.swing.JRadioButton radio8;
    public javax.swing.JRadioButton radio9;
    public javax.swing.JRadioButton radiocl;
    public javax.swing.JRadioButton radiotime;
    public javax.swing.JRadioButton rb1;
    public javax.swing.JRadioButton rb2;
    public javax.swing.JRadioButton rb3;
    public javax.swing.JRadioButton rb4;
    private javax.swing.JButton removetag;
    public javax.swing.JRadioButton replace;
    public javax.swing.JCheckBox set_cookie_names;
    public javax.swing.JSpinner sp1;
    public javax.swing.JCheckBox status_code;
    public javax.swing.JTable table4;
    public javax.swing.JTable table5;
    public javax.swing.JCheckBox tag_ids;
    public javax.swing.JCheckBox tag_names;
    public javax.swing.JTextField text1;
    public javax.swing.JTextField text4;
    public javax.swing.JTextField text5;
    public javax.swing.JTextField text71;
    public javax.swing.JTextField text72;
    public javax.swing.JTextArea textarea1;
    public javax.swing.JTextArea textarea2;
    public javax.swing.JTextArea textarea3;
    public javax.swing.JTextArea textarea4;
    public javax.swing.JTextField textauthor;
    public javax.swing.JTextField textcl;
    public javax.swing.JTextField textfield1;
    public javax.swing.JTextField textgreps;
    public javax.swing.JTextField textpayloads;
    public javax.swing.JTextField texttime;
    public javax.swing.JCheckBox unknown;
    public javax.swing.JCheckBox urlpathfilename;
    public javax.swing.JCheckBox urlpathfolder;
    public javax.swing.JCheckBox userprovided;
    public javax.swing.JRadioButton variationsRadio;
    public javax.swing.JCheckBox visible_text;
    public javax.swing.JCheckBox visible_word_count;
    public javax.swing.JCheckBox whole_body_content;
    public javax.swing.JCheckBox word_count;
    // End of variables declaration//GEN-END:variables
}
