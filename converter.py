import os
import xml.etree.ElementTree as ET
import csv
import PySimpleGUI as sg
import pandas as pd


class GUI():

    def __init__(self, file_path=None, folder_path=None):
        if file_path is not None and folder_path is not None:
            self.xml_location = file_path
            self.csv_location = folder_path
            if os.path.splitext(self.xml_location)[1] == '.xml':
                # Make a File object from the selection
                file = File(self.xml_location, self.csv_location)
                # Populate Port objects
                for host in file.host_list:
                    host.create_ports()
                    host.parse_ports()
                file.parse_to_csv()
                print("Conversion Complete!")
            else:
                print(f"Incorrect File Type: {os.path.splitext(self.xml_location)[1]}")
            return

        # Create the GUI window, which is a list of lists. The outer list is a list of rows which contains a list of objects
        self.window = sg.Window('Nmap XML to CSV Converter v1.2', [[sg.Image('POWER_LOGO.png')],
                                                                           [sg.Text('XML File')],
                                                                           [sg.Input(), sg.FileBrowse(initial_folder='/Users/todd/Documents')],
                                                                           [sg.Text('CSV Output Folder')],
                                                                           [sg.Input(), sg.FolderBrowse(initial_folder='/Users/todd/Documents')],
                                                                           [sg.Output(size=(80,8))], [sg.Button(key='Convert', button_text='Convert'), sg.Exit()]
                                                                           ], background_color='White')
        while True:
            # Read window objects continuously and wait for event
            self.event, self.values = self.window.read()

            # Convert button clicked
            if self.event == 'Convert':
                # Check for blank entries
                if self.values[1] != '':
                    if self.values[2] != '':
                        # Grab specified strings from window
                        self.xml_location = self.values[1]
                        self.csv_location = self.values[2]
                        # Verify an XML file was specified
                        if os.path.splitext(self.xml_location)[1] == '.xml':
                            # Make a File object from the selection
                            file = File(self.xml_location, self.csv_location)
                            # Populate Port objects
                            for host in file.host_list:
                                host.create_ports()
                                host.parse_ports()
                            file.parse_to_csv()
                            print("Conversion Complete!")
                        else:
                            print(f"Incorrect File Type: {os.path.splitext(self.xml_location)[1]}")
                    else:
                        print(f"Output location {self.values[2]} does not exist!")
                else:
                    print("No File Specified!")
            if self.event == sg.WIN_CLOSED or self.event == 'Exit':
                break


class File(object):

    def __init__(self, xml_location, csv_location):
        # Pass in file path and file name
        self.filename_xml = xml_location
        self.extensionless_path = os.path.splitext(self.filename_xml)[0]
        self.basename = os.path.basename(self.extensionless_path)
        self.filename_csv = csv_location + '/' + self.basename + '.csv'
        # Initialize variables for opening a CSV file
        self.csv_data = None
        self.csv_writer = None
        self.csv_reader = None
        self.new_data = []
        self.header = ['Status', 'IP', 'IP Type', 'MAC Address', 'Host', 'OS', 'Protocol', 'Ports', 'State',
                           'Services', 'Vendor', 'Notes']
        # Extract filename without extension
        # Parse XML Data
        self.xml_data = ET.parse(self.filename_xml)
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


    def create_hosts(self):
        # Create a Host object for every host in the XML file
        for h in self.hosts:
            host = Host(h, self)
            self.host_list.append(host)

    def parse_hosts(self):
        # Parse each host for data
        for h in self.host_list:
            hostAddressElement = h.raw_data.findall('address')
            hostStatusElement = h.raw_data.findall('status')

            h.host_name_element = h.raw_data.findall('hostnames')
            h.port_element = h.raw_data.findall('ports')
            h.os_element = h.raw_data.findall('os')

            h.status = hostStatusElement[0].attrib['state']
            h.ip_address = hostAddressElement[0].attrib['addr']
            h.ip_address_type = hostAddressElement[0].attrib['addrtype']
            # Attempt to get MAC Address and Vendor name, return '' otherwise
            try:
                h.mac_address = hostAddressElement[1].attrib['addr']
                h.vendor = hostAddressElement[1].attrib['vendor']
            except IndexError:
                h.mac_address = ''
                h.vendor = ''
            # Attempt to get Host Name if it has one, return '' otherwise
            try:
                h.host_name = h.host_name_element[0].findall('hostname')[0].attrib['name']
            except IndexError:
                h.host_name = ''
            #Attempt to get OS info if available, return '' otherwise
            try:
                h.os_name = h.os_element[0].findall('osmatch')[0].attrib['name']
            except IndexError:
                h.os_name = ''
            # Attempt to get ports if available, return '' otherwise
            try:
                h.ports = h.port_element[0].findall('port')
            except IndexError:
                h.ports = ''
            #Read NMAP host comment, usually blank unless filled in on NMAP
            self.comment = h.raw_data.attrib['comment']

    import pandas as pd

    def parse_to_csv(self):
        try:
            # Read the existing CSV file into a DataFrame
            existing_df = pd.read_csv(self.filename_csv)
            print(f"File exists, comparing data with {self.filename_csv}...")
        except FileNotFoundError:
            existing_df = pd.DataFrame(columns=self.header)
            print(f"File does not exist, creating {self.filename_csv}...")

        # Create a new DataFrame from the host_data
        new_data_df = pd.DataFrame(self.host_data, columns=self.header)

        # Convert lists to strings in both existing_df and new_data_df
        existing_df = existing_df.applymap(lambda x: ','.join(x) if isinstance(x, list) else x)
        new_data_df = new_data_df.applymap(lambda x: ','.join(x) if isinstance(x, list) else x)

        # Concatenate the existing DataFrame and the new_data DataFrame
        combined_df = pd.concat([existing_df, new_data_df], ignore_index=True)

        # Replace NaN values with empty strings
        combined_df.fillna("", inplace=True)

        # Group by IP and apply a custom aggregation function to combine unique values
        combined_df = combined_df.groupby('IP', as_index=False).agg(
            lambda x: ','.join(set(x.str.split(',').sum())) if x.dtype == "object" else x.unique().tolist())

        # Remove duplicates
        combined_df.drop_duplicates(inplace=True)

        # Sort by IP
        combined_df.sort_values(by='IP', inplace=True)

        # Write the combined DataFrame to the CSV file
        combined_df.to_csv(self.filename_csv, index=False)


'''
        
            print(f"File does not exist, creating {self.filename_csv}...")
            # File doesn't currently exist, create new file and dump
            with open(self.filename_csv, 'w', encoding='utf-8', newline='') as csv_data:
                csv_writer = csv.writer(csv_data)
                headers = ['Status', 'IP', 'IP Type', 'MAC Address', 'Host', 'OS', 'Protocol', 'Ports', 'State',
                           'Services', 'Vendor', 'Notes']
                csv_writer.writerow(headers)
                for row in self.host_data:
                    csv_writer.writerow([','.join(x) if isinstance(x, list) else x for x in row])
'''


'''
    def parse_to_csv(self):
        # Attempt to read file if it exists
        try:
            # Open the CSV file create the reader object
            self.csv_data = open(self.filename_csv, 'r')
            self.csv_reader = csv.reader(self.csv_data)
            self.header = next(self.csv_reader)
            # Check each new row against every row of the existing file, append if it's unique
            for row in self.host_data:
                if row not in self.csv_reader:
                    self.new_data.append(row)
            self.csv_data.close()
            # Reading is complete, close file and re-open with append ('a') permissions
            self.csv_data = open(self.filename_csv, 'a', encoding='utf-8', newline='')
            self.csv_writer = csv.writer(self.csv_data)
            # Write unique rows
            self.csv_writer.writerows(self.new_data)
            self.csv_data.close()
            # Close CSV file
            print(f"Additional rows written to: {self.filename_csv}")
        except Exception as e:
            #print(e)
            print(f"File does not exist, creating {self.filename_csv}...")
            # File doesn't currently exist, create new file and dump
            self.csv_data = open(self.filename_csv, 'w', encoding='utf-8', newline='')
            self.csv_writer = csv.writer(self.csv_data)
            headers = ['Status', 'IP', 'IP Type', 'MAC Address', 'Host', 'OS', 'Protocol', 'Ports', 'State', 'Services', 'Vendor', 'Notes']
            self.csv_writer.writerow(headers)
            self.csv_writer.writerows(self.host_data)
            self.csv_data.close()
'''




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
        self.state_list = []
        self.service_list = []
        self.port_id_list = []
        self.protocol_list = []

    def create_ports(self):
        # Create a Port object for every host in the XML file
        for p in self.ports:
            port = Port(p)
            self.ports_list.append(port)

    def parse_ports(self):
        # If host contains no ports, send host data to file
        if len(self.ports_list) < 1:
            self.port_data.extend(
                (self.status, self.ip_address, self.ip_address_type, self.mac_address, self.host_name, self.os_name, '',
                 '', '', '', self.vendor, self.comment))
            self.file.host_data.append(self.port_data)
        # If ports are present, iterate through and parse data
        else:
            for p in self.ports_list:
                p.protocol = p.raw_data.attrib['protocol']
                if p.protocol not in self.protocol_list:
                    self.protocol_list.append(p.protocol)
                p.port_id = p.raw_data.attrib['portid']
                self.port_id_list.append(p.port_id)
                p.service = p.raw_data.findall('service')[0].attrib['name']
                self.service_list.append(p.service)
                try:
                    p.state = p.raw_data.findall('state')[0].attrib['state']
                    if p.state not in self.state_list:
                        self.state_list.append(p.state)
                except (IndexError, KeyError):
                    p.state = ''

            # Compile a list of data for each port
            self.port_data.extend((self.status, self.ip_address, self.ip_address_type, self.mac_address, self.host_name,
                                   self.os_name, ';'.join(self.protocol_list), ';'.join(self.port_id_list),
                                   ';'.join(self.state_list), ';'.join(self.service_list), self.vendor, self.comment))
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


