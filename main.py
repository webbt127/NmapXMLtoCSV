"""
************************************************************************************************************************
OWNER: POWER Engineers Inc.
SCRIPT: NMAP XML to CSV Converter
VERSION: 1.1
DESCRIPTION: Reads in an XML files and builds an object tree that can be written to CSV format
************************************************************************************************************************
"""

import argparse
from converter import GUI

def main(file_path, folder_path):
    """
    Initialize the GUI class
    Select the location of the XML file
    Select the destination folder for the CSV output
    Parses host tree and builds a list of ports for each host
    Open the CSV if it already exists and check new entries against existing rows, append if new
    """
    gui = GUI(file_path, folder_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XML to CSV converter")
    parser.add_argument("--file_path", type=str, default=None, help="Path to the input XML file (optional)")
    parser.add_argument("--folder_path", type=str, default=None, help="Path to the output folder for the CSV file (optional)")

    args = parser.parse_args()
    main(args.file_path, args.folder_path)


