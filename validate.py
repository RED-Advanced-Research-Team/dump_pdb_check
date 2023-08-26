#!/usr/bin/env python3
#
# Author:
#  Alexander Kalinin (https://appsec.su)
#

import sys

sys.path.append("./minidump/")

from minidump import minidumpfile

# simple check for prefix: \\ and \??\
def validate_path(p : str):
    prefix_bl = ["\\\\", "\\??\\"]
    for pfx in prefix_bl:
        if p.startswith(pfx):
            return False
    return True

# Returns list of suspicious pdb paths
def validate_pdbs_in_dmp(dmp_path):
    mdf = minidumpfile.MinidumpFile()
    dmp = mdf.parse(dmp_path)
    if dmp == None or dmp.modules == None:
        return []
    
    bads = []
    for m in dmp.modules.modules:
        if validate_path(m.cv.PdbName) == False:
            bads.append(m.cv.PdbName)
    return bads


def run(dmp):
	result = validate_pdbs_in_dmp(dmp)
	if len(result)==0:
		print("Dump file is OK, no SMB paths found")
	else:
		print("Suspicious dump, SMB paths found:", result)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: ./validate.py path/to/file.dmp")
        exit(-1)
    run(sys.argv[1])
    exit(0)
