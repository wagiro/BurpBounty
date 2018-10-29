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

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.List;
import javax.swing.table.DefaultTableModel;
import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

/**
 *
 * @author eduardogarcia
 */
public class ProfilesManager extends javax.swing.JPanel {

    /**
     * Creates new form ProfilesManager
     */
    DefaultTableModel model = new DefaultTableModel(){

        @Override
        public boolean isCellEditable(int row, int column) {
           //all cells false
           return false;
        }   
    };
    private final BurpBountyGui BBG;
    
    public ProfilesManager(BurpBountyGui bbg) {
        this.BBG = bbg;
        initComponents();
        showProfiles(this.BBG);
    }
    

    public void setEnableDisableProfile(BurpBountyGui bbg, String enable){ 
        
        Gson gson = new Gson();
        File f = new File(bbg.filename);

        JsonArray json2 = new JsonArray();
        List<Issue> newjson = gson.fromJson(json2, new TypeToken<List<Issue>>() {}.getType());
        
        File[] files = f.listFiles(new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
                if(name.toLowerCase().endsWith(".bb")){
                    return true;
                } else {
                    return false;
                }
            }
        });
                
        
        
        int[] rows = table.getSelectedRows();
        if(f.exists() && f.isDirectory()){
            for(File file :files){
                for(Integer row: rows){
                    try{
                        JsonArray data = new JsonArray();
                        JsonReader json = new JsonReader(new FileReader(file.getAbsolutePath()));
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());
                        
                        Object idata = data.get(0);                      
                        Issue i = gson.fromJson(idata.toString(), Issue.class);
                        String pname = table.getValueAt(row, 0).toString();
                        
                        if(pname.contains(i.getName())){
                            if(enable.contains("Yes")){
                                i.setActive(true);
                                table.setValueAt("Yes", row, 1);
                            }else{
                                i.setActive(false);
                                table.setValueAt("No", row, 1);
                            }
                            newjson.clear();
                            newjson.add(i);
                            FileOutputStream fileStream = new FileOutputStream(file.getAbsoluteFile());
                            String fjson = gson.toJson(newjson);
                            OutputStreamWriter writer = new OutputStreamWriter(fileStream, "UTF-8");  
                            writer.write(fjson.replace(",", ",\n"));
                            writer.close();
                        }
                    } catch (IOException e){
                        e.printStackTrace();
                    }
                }
            }
        }
    }  
    
        
    public void showProfiles(BurpBountyGui bbg){        
        JsonArray json = bbg.initJson();
        model.setNumRows(0);
        model.setColumnCount(0);
        model.addColumn("Profile");
        model.addColumn("Active");
        model.addColumn("Authors Twitter");
       
        table.getColumnModel().getColumn(0).setPreferredWidth(220);
        table.getColumnModel().getColumn(1).setPreferredWidth(5);
        table.getColumnModel().getColumn(2).setPreferredWidth(70);
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(table.getModel());
        table.setRowSorter(sorter);
        List<RowSorter.SortKey> sortKeys = new ArrayList<>();
       
        sortKeys.add(new RowSorter.SortKey(0, SortOrder.ASCENDING));
        sorter.setSortKeys(sortKeys);
        sorter.sort();
        
        if (json != null){
            for (JsonElement pa : json) {
                JsonObject bbObj  = pa.getAsJsonObject();
                if(bbObj.get("Active").getAsBoolean()){
                    model.addRow(new Object[]{bbObj.get("Name").getAsString(), "Yes", bbObj.get("Author").getAsString()});    
                }else{
                    model.addRow(new Object[]{bbObj.get("Name").getAsString(), "No", bbObj.get("Author").getAsString()});
                }
            }   
        }
    }
    

    public void deleteProfile(BurpBountyGui bbg){ 
        
        Gson gson = new Gson();
        File f = new File(bbg.filename);
        
        File[] files = f.listFiles(new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
                if(name.toLowerCase().endsWith(".bb")){
                    return true;
                } else {
                    return false;
                }
            }
        });
                
        
        
        int[] rows = table.getSelectedRows();
        if(f.exists() && f.isDirectory()){
            for(File file :files){
                for(Integer row: rows){
                    try{
                        JsonArray data = new JsonArray();
                        JsonReader json = new JsonReader(new FileReader(file.getAbsolutePath()));
                        JsonParser parser = new JsonParser();
                        data.addAll(parser.parse(json).getAsJsonArray());
                        
                        Object idata = data.get(0);                      
                        Issue i = gson.fromJson(idata.toString(), Issue.class);
                        String pname = table.getValueAt(row, 0).toString();
                        
                        if(pname.contains(i.getName())){
                            file.delete();
                        }
                    } catch (IOException e){
                        e.printStackTrace();
                    }
                }
            }
        }showProfiles(bbg);
    }  
    
    
    
    
    
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        button3 = new javax.swing.JButton();
        button1 = new javax.swing.JButton();
        button2 = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        table = new javax.swing.JTable();

        button3.setText("Remove");
        button3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RemoveEvent(evt);
            }
        });

        button1.setText("Enable");
        button1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                setProfileEnable(evt);
            }
        });

        button2.setText("Disable");
        button2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SetDisableProfiles(evt);
            }
        });

        table.setAutoCreateRowSorter(true);
        table.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        table.setModel(model);
        table.setRowSorter(null);
        table.getTableHeader().setReorderingAllowed(false);
        jScrollPane2.setViewportView(table);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(button2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(button1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(button3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(18, 18, 18)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 454, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(29, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(button1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(button3))
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 369, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(19, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void setProfileEnable(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_setProfileEnable
        setEnableDisableProfile(this.BBG,"Yes");
        
    }//GEN-LAST:event_setProfileEnable

    private void SetDisableProfiles(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SetDisableProfiles
        setEnableDisableProfile(this.BBG,"No");
    }//GEN-LAST:event_SetDisableProfiles

    private void RemoveEvent(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RemoveEvent
        deleteProfile(this.BBG);
    }//GEN-LAST:event_RemoveEvent


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton button1;
    private javax.swing.JButton button2;
    private javax.swing.JButton button3;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTable table;
    // End of variables declaration//GEN-END:variables
}
