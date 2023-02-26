import os
import xml.etree.ElementTree as ET
import csv

class Converter:

    def __init__(self):
        # File path to get xml files from and send csv files to
        self.root = '/Users/todd/nmap/'
        self.path = ''
        self.save_path = self.root + self.path
        # Initialize XML file list
        self.xml_file_list = []
        # Get list of XML files
        self.get_xml_files()

    def get_xml_files(self):
        for file in os.listdir(self.save_path):
            if file.endswith(".xml"):
                # If the file has an XML extension, create a File object for data pre-processing and add to a list of objects
                ob = File(self.save_path, file)
                self.xml_file_list.append(ob)


class File(object):

    def __init__(self, path, file):
        # Pass in file path and file name
        self.path = path
        self.filename_xml = file
        # Initialize variables for opening a CSV file
        self.csv_data = None
        self.csv_writer = None
        # Extract filename without extension
        self.filename_name = os.path.splitext(self.filename_xml)[0]
        # Parse XML Data
        self.xml_data = ET.parse(self.path + self.filename_xml)
        # Get XML tree
        self.root = self.xml_data.getroot()
        # Initialize lists
        self.host_list = []
        self.host_data = []
        self.addr_info = []
        # Extract member of tree titled 'host'
        self.hosts = self.root.findall('host')
        # Method that creates host objects and adds them to a list
        self.create_hosts()
        # Gets data for each host in the host list
        self.parse_hosts()
        # Append new extension to extensionless filename
        self.filename_csv = self.filename_name + '.csv'
        # Initialize placeholder for CSV file when we open and write to it
        self.csvfile = None


    def create_hosts(self):
        # Create a Host object for every host in the XML file
        for h in self.hosts:
            host = Host(h, self)
            self.host_list.append(host)

    def parse_hosts(self):
        # Parse each host for data
        for h in self.host_list:
            h.status = h.raw_data.findall('status')[0].attrib['state']
            h.ip_address = h.raw_data.findall('address')[0].attrib['addr']
            h.ip_address_type = h.raw_data.findall('address')[0].attrib['addrtype']
            # Attempt to get MAC Address and Vendor name, return '' otherwise
            try:
                h.mac_address = h.raw_data.findall('address')[1].attrib['addr']
                h.vendor = h.raw_data.findall('address')[1].attrib['vendor']
            except IndexError:
                h.mac_address = ''
                h.vendor = ''
            h.host_name_element = h.raw_data.findall('hostnames')
            # Attempt to get Host Name if it has one, return '' otherwise
            try:
                h.host_name = h.host_name_element[0].findall('hostname')[0].attrib['name']
            except IndexError:
                h.host_name = ''
            #Attempt to get OS info if available, return '' otherwise
            try:
                h.os_element = h.raw_data.findall('os')
                h.os_name = h.os_element[0].findall('osmatch')[0].attrib['name']
            except IndexError:
                h.os_name = ''
            # Attempt to get ports if available, return '' otherwise
            try:
                h.port_element = h.raw_data.findall('ports')
                h.ports = h.port_element[0].findall('port')
            except IndexError:
                h.ports = ''
            #Read NMAP host comment, usually blank unless filled in on NMAP
            self.comment = h.raw_data.attrib['comment']

    def parse_to_csv(self):
        # Write to the CSV file ONLY if the file doesn't currently exist, otherwise do nothing
        if not os.path.isfile(self.path + self.filename_csv):
            self.csv_data = open(self.path + self.filename_csv, 'w', encoding='utf-8', newline='')
            self.csv_writer = csv.writer(self.csv_data)
            headers = ['Status', 'IP', 'IP Type', 'MAC Address', 'Host', 'OS', 'Protocol', 'Port', 'State', 'Service', 'Vendor', 'Notes']
            self.csv_writer.writerow(headers)
            self.csv_writer.writerows(self.host_data)
            self.csv_data.close()



class Host(object):

    def __init__(self, host, file):
        self.raw_data = host
        self.addr_info = []
        self.ip_address = ''
        self.host_name_element = ''
        self.host_name = ''
        self.os_element = ''
        self.os_name = ''
        self.port_element = ''
        self.ports = []
        self.ports_list = []
        self.port_data = []
        self.file = file
        self.mac_address = ''
        self.vendor = ''
        self.ip_address_type = ''
        self.comment = ''
        self.status = ''

    def create_ports(self):
        # Create a Port object for every host in the XML file
        for p in self.ports:
            port = Port(p)
            self.ports_list.append(port)

    def parse_ports(self):
        # If host contains no ports, send host data to file
        if len(self.ports_list) < 1:
            self.port_data.extend((self.status, self.ip_address, self.ip_address_type, self.mac_address, self.host_name, self.os_name, '',
                                   '', '', '', self.vendor, self.comment))
            self.file.host_data.append(self.port_data)
        # If ports are present, iterate through and parse data
        else:
            for p in self.ports_list:
                p.protocol = p.raw_data.attrib['protocol']
                p.port_id = p.raw_data.attrib['portid']
                p.service = p.raw_data.findall('service')[0].attrib['name']
                try:
                    p.state = p.raw_data.findall('state')[0].attrib['state']
                except (IndexError, KeyError):
                    p.state = ''
                # Unused data points, leaving in code in case they're needed
                #try:
                #    p.product = p.raw_data.findall('service')[0].attrib['product']
                #except (IndexError, KeyError):
                #    p.product = ''
                #try:
                #    p.servicefp = p.raw_data.findall('service')[0].attrib['servicefp']
                #except (IndexError, KeyError):
                #    p.servicefp = ''
                #try:
                #    p.script_id = p.raw_data.findall('script')[0].attrib['id']
                #except (IndexError, KeyError):
                #    p.script_id = ''
                #try:
                #    p.script_output = p.raw_data.findall('script')[0].attrib['output']
                #except (IndexError, KeyError):
                #    p.script_output = ''

                # Compile a list of data for each port
                self.port_data.extend((self.status, self.ip_address, self.ip_address_type, self.mac_address, self.host_name, self.os_name, p.protocol, p.port_id, p.state, p.service, self.vendor, self.comment))
                # Copy data out to file object
                self.file.host_data.append(self.port_data)
                # Reset port data for next iteration
                self.port_data = []


class Port(object):

    def __init__(self, port):
        self.raw_data = port
        self.protocol = ''
        self.port_id = ''
        self.service = ''
        self.product = ''
        self.servicefp = ''
        self.script_id = ''
        self.script_output = ''
        self.state = ''


