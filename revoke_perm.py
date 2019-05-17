import cx_Oracle
import argparse
import sys
import time

def script_usage():
    return "\
\nScript usage: \n\
revoke_perm.py --DC dc2  --ENV test  --file list \n\
"

try:
    arg = sys.argv[2]
except IndexError:
    print '\nNo arguments passed.\n', script_usage(), '\nExiting...'
    sys.exit(1)

parser = argparse.ArgumentParser()
parser.add_argument('--DC', dest="DC", action="store", required=True, help="DC like dc2", mvar='')
parser.add_argument('--ENV', dest="ENV", action="store", required=True, help="ENV like test", mvar='')
parser.add_argument('--file', dest="file", action="store", required=True, help="file like list", mvar='')

command_line_options = parser.parse_args()
DC = command_line_options.DC
ENV = command_line_options.ENV
file = command_line_options.file


con = cx_Oracle.connect(db_user + "/" + db_pass + '@' + db_host)
cur = con.cursor()
inst_file = open(file, "r")
for inst in inst_file:
    grantees = []
    inst = inst.rstrip('\n')
    cur.execute("select GRANTEE from dba_tab_privs where owner = '" + db_user + "' and TABLE_NAME = '" + inst + "_process_settings'")
    for result in cur:
        for grantee in result:
            grantees.append(grantee)
    for grantee in grantees:
        cur.execute('REVOKE ALL ON "' + inst + '_process_settings" FROM "' + grantee + '"')
cur.close()
inst_file.close()
con.close()
