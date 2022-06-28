package org.jnetpcap.examples;


import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
public class tok extends DefaultTableCellRenderer
{
  public Component getTableCellRendererComponent (JTable table,Object obj, boolean isSelected, boolean hasFocus, int row, int column) 
  {
	  Component cell = super.getTableCellRendererComponent(table, obj, isSelected, hasFocus, row, column);
	  try
	  {
		  int check = obj.toString().indexOf("Spoofed IP");
		  if (check!=-1) 
		  {
			  cell.setBackground(Color.RED);
		  } 
		  else 
		  {
			  cell.setBackground(Color.cyan);
		  }
	  }
	  catch(NullPointerException nx)
	  {
		  
	  }
	  return cell;
  }


	public static void main(String[]args){
		new tok();
	}
	 
}
