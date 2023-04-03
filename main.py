"""
************************************************************************************************************************
OWNER: POWER Engineers Inc.
SCRIPT: NMAP XML to CSV Converter
VERSION: 1.1
DESCRIPTION: Reads in an XML files and builds an object tree that can be written to CSV format
************************************************************************************************************************
"""

from converter import GUI

""" 
Initialize the GUI class
Select the location of the XML file
Select the destination folder for the CSV output
Parses host tree and builds a list of ports for each host
Open the CSV if it already exists and check new entries against existing rows, append if new
"""

gui = GUI()
