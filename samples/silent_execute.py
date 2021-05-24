import sys
import os
import logging

filename = sys.argv[1]
if not "silent_execute.py" in filename:
    logging.getLogger('angr').setLevel("CRITICAL")
    print("")
    print("====== " + filename + " ======")
    exec(open(filename).read())
