"""
SCRIPT: NMAP XML to CSV Converter
AUTHOR: TWEBB
DESCRIPTION: Reads in a list of XML files and builds an object tree that can be written to CSV format
"""

from converter import Converter

""" 
Initialize the Converter class
Reads in all files located at C:/Users/Public/Documents and finds XML files
Parses XML tree and builds a list of hosts
Parses host tree and builds a list of ports
"""

xmltocsv = Converter()

# After host data has been parsed, we can create port objects and parse the port attributes
for file in xmltocsv.xml_file_list:
    for host in file.host_list:
        host.create_ports()
        host.parse_ports()
    file.parse_to_csv()