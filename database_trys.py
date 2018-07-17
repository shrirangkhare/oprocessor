import sqlite3
import sys, traceback

db = None
cursor = None

arr_col_names1 = ["nasl_file_name_val", "oid", "version", "tag", "cve_id", "bugtraq_id", "xref", "name", "category",
                 "copyright", "family", "dependencies", "require_ports", "exclude_keys",
                 "mandatory_keys", "require_keys", "timeout", "require_udp_ports", "year", "cvss_base_vector", "URL",
                 "cvss_base", "creation_date", "last_modification", "summary", "qod_type", "solution",
                 "solution_type", "impact", "affected", "insight", "vuldetect", "IAVA", "qod",
                 "OWASP", "deprecated", "OSVDB", "SuSE", "MOD_YEAR", "MOD_DAY", "MOD_MONTH",
                 "CREATE_YEAR", "CREATE_DAY", "CREATE_MONTH"]

def init():
    global db
    global cursor
    db = sqlite3.connect('mydb')
    db.text_factory = str
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE  IF NOT EXISTS  nvt( oid TEXT, version TEXT, tag TEXT, cve_id TEXT,bugtraq_id TEXT, xref TEXT, name TEXT, category TEXT,
                    copyright TEXT, family TEXT, dependencies TEXT, require_ports TEXT, exclude_keys TEXT,  
                    mandatory_keys TEXT, require_keys TEXT,timeout TEXT, require_udp_ports TEXT, year TEXT, cvss_base_vector TEXT, URL text, 
                    cvss_base TEXT, creation_date TEXT, last_modification TEXT, summary TEXT, qod_type TEXT, solution TEXT, 
                    solution_type TEXT, impact TEXT, affected TEXT, insight TEXT, vuldetect TEXT)
    ''')


def addrecords():
    init()
    global db
    global cursor

    insert_string = "insert into nvt (family,mandatory_keys,insight,creation_date,category,cvss_base_vector,copyright,version,impact,affected,cve_id,URL,cvss_base,oid,dependencies,CB-A,name,solution,summary,bugtraq_id,last_modification,require_ports,qod_type) VALUES " \
                    "('Denial of Service'," \
                    "'SMB/WindowsVersion'," \
                    "'tag_insight'," \
                    "'2008-09-26 14:12:58 +0200 (Fri, 26 Sep 2008)'," \
                    "'ACT_GATHER_INFO'," \
                    "'AV:N/AC:L/Au:N/C:C/I:C/A:C'," \
                    "'Copyright (C) 2008 Greenbone Networks GmbH'," \
                    "'$Revision: 9349 $'," \
                    "'tag_impact','tag_affected'," \
                    "'CVE-2008-2541','http://secunia.com/advisories/30518http://www.zerodayinitiative.com/advisories/ZDI-08-035/http://www.zerodayinitiative.com/advisories/ZDI-08-036/http://www.ca.com/us/securityadvisor/vulninfo/vuln.aspx?id=36408'," \
                    "'10.0'," \
                    "'1.3.6.1.4.1.25623.1.0.800101'," \
                    "'secpod_reg_enum.nasl','08-0091'," \
                    "'CA eTrust SCM Multiple HTTP Gateway Service Vulnerabilities'," \
                    "'tag_solution'," \
                    "'tag_summary'," \
                    "'29528'," \
                    "'$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $','Services/www, 8080, 139, 445','registry')"

    insert_string1 = "insert into nvt (category,impact,family,cvss_base_vector,affected,name,copyright,insight,cvss_base,oid,solution,solution_type,creation_date,vuldetect,version,last_modification,exclude_keys,dependencies,summary,require_ports,qod_type) VALUES " \
                     "('val,1','val2','val3','val4','val5','val6','val7','val8','val9','val10','val11','val12','val13','val14','val15', 'val16','val17','val18', 'val19','val20','val21')"
    #for x in range(0,100):
    cursor.execute(insert_string)
    db.commit()

    print "EOF database trys"

def select_query():
    init()
    cursor.execute('select distinct family from nvt')
    count = 0

    try:
        #rows = cursor.fetchall()
        for row in cursor:
            print row[0]
            #i = arr_col_names1.index("family")
            #print row[i]
        count = count + 1
    except sqlite3.OperationalError:
        print count
        count = count + 1
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_exception(exc_type, exc_value, exc_traceback,
                                  limit=2, file=sys.stdout)
        # print "sqlite3.OperationalError For -> " + insertstr1

    #print count


select_query()
#addrecords()