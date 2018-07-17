import re
import csv
import json
import os
from flask import Flask , request
from nasl_utils import *
import pprint
import sqlite3
import sys, traceback
from sets import Set;


from os import walk

db = None
cursor = None
outputJson = {}

arr_col_names = ["nasl_file_name_val", "oid", "version", "tag", "cve_id", "bugtraq_id", "xref", "name", "category",
                 "copyright", "family", "dependencies", "require_ports", "exclude_keys",
                 "mandatory_keys", "require_keys", "timeout", "require_udp_ports", "year", "cvss_base_vector", "URL",
                 "cvss_base", "creation_date", "last_modification", "summary", "qod_type", "solution",
                 "solution_type", "impact", "affected", "insight", "vuldetect", "IAVA", "qod",
                 "OWASP", "deprecated", "OSVDB", "SuSE", "MOD_YEAR", "MOD_DAY", "MOD_MONTH",
                 "CREATE_YEAR", "CREATE_DAY", "CREATE_MONTH"]

def nvt_parse_and_db_addition_required():
    if os.path.isfile("mydb"):
        return False
    return True

def init():
    global db
    global cursor
    db = sqlite3.connect('mydb')
    cursor = db.cursor()

#get nasl file attributes
def naslfileattributes(filepath):
    var_arr = []
    #print "parsing " + filepath
    retjson = {}
    file = open(filepath, "r")
    for line in file:
        line = line.lstrip()
        line = re.sub("\n$",'',line)
        parseLine(retjson, line, var_arr)
    return retjson

def walk_all_nvt(basepath):
    all_nvts = []
    for (dirpath, dirnames, filenames) in walk(basepath):
        print dirpath + "====================\n==================="
        for file1 in filenames:
            filename, file_extension = os.path.splitext(file1)
            if file_extension == '.nasl':
                fullfilename = dirpath + "/" + file1
                filejsoninfo = naslfileattributes(fullfilename)
                filejsoninfo["nasl_file_name_val"] = filename + file_extension
                all_nvts.append(filejsoninfo)
                #if len(all_nvts) > 10:
                #       return all_nvts
                #pp = pprint.PrettyPrinter(indent=4)
                #pp.pprint(filejsoninfo)
                #print "\n\n\n@#@#@#@#@#@#@#@#@#\n\n\n"
    return all_nvts

e = Set()



def convert_to_csv_row(elem):
    cols = [ "oid", "version", "bugtraq_id", "cve_id", "cvss_base", "cvss_base_vector", "name", "family", "dependencies", "require_ports"]
    outputString = ""
    for a in cols:
        if elem.has_key(a):
            outputString = outputString + getQuotedString(elem[a][0]) + ","
        else:
            outputString = outputString + "\"\","
    return outputString + "\n"




def add_nvts_to_db(xarray):
    global db
    global cursor
    print "add_nvts_to_db"
    if not os.path.isfile("mydb"):
        init()
        cursor.execute('''
            CREATE TABLE  IF NOT EXISTS  nvt(nasl_file_name_val TEXT, oid TEXT, version TEXT, tag TEXT, cve_id TEXT,bugtraq_id TEXT, xref TEXT, name TEXT, category TEXT,
                        copyright TEXT, family TEXT, dependencies TEXT, require_ports TEXT, exclude_keys TEXT,  
                        mandatory_keys TEXT, require_keys TEXT,timeout TEXT, require_udp_ports TEXT, year TEXT, cvss_base_vector TEXT, URL text, 
                        cvss_base TEXT, creation_date TEXT, last_modification TEXT, summary TEXT, qod_type TEXT, solution TEXT, 
                        solution_type TEXT, impact TEXT, affected TEXT, insight TEXT, vuldetect TEXT, IAVA TEXT, qod TEXT, 
                        OWASP TEXT, deprecated TEXT, OSVDB TEXT, SuSE TEXT, MOD_YEAR INT, MOD_DAY INT, MOD_MONTH INT, 
                        CREATE_YEAR INT, CREATE_DAY INT, CREATE_MONTH INT)
        ''')
        keystring = ""
        valuesstring = ""
        insertstr1 = ""

        file_object = open("nvt.csv", "w")

        for elem1 in xarray:
            line = convert_to_csv_row(elem1)
            file_object.write(line)
        file_object.close()
        exit()
        for elem in xarray:
            convert_to_csv_row(elem)
            try:
                for key in elem.keys():
                    keystring = keystring + key + ","
                    if key == "nasl_file_name_val":
                        actual_value = elem[key]
                    elif key in ["MOD_YEAR", "MOD_DAY", "MOD_MONTH", "CREATE_YEAR", "CREATE_DAY", "CREATE_MONTH"]:
                        actual_value = elem[key]
                        actual_value = str(actual_value)
                    else:
                        actual_value = ''.join(elem[key])
                        #print "file-> " + actual_value
                    actual_value = re.sub('\"|\'','',actual_value)
                    valuesstring = valuesstring + "\'" + actual_value + "\',"
                keystring = re.sub(",$", '', keystring)
                valuesstring = re.sub(",$", '', valuesstring)
                insertstr1 = "insert into nvt (" + keystring + ") VALUES (" + valuesstring +")"
                #print insertstr1
                keystring = ""
                valuesstring = ""
                #cursor.execute(insertstr1)
            except sqlite3.OperationalError:
                print "file -> " + elem["nasl_file_name_val"]
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_exception(exc_type, exc_value, exc_traceback,
                                          limit=2, file=sys.stdout)
                #print "sqlite3.OperationalError For -> " + insertstr1
                continue
        db.commit()

def create_grouped_data():
    global db
    global cursor
    global outputJson

    yearArray = []
    cvssArray = []
    familyArray = []
    outputJson["id"] = "NVT"
    outputJson["text"] = "NVT"
    outputJson["children"] = []
    cursor.execute('select distinct CREATE_YEAR from nvt')
    for row in cursor:
        yearArray.append(row[0])

    cursor.execute('select distinct family from nvt')
    for row in cursor:
        familyArray.append(row[0])

    cursor.execute('select distinct cvss_base from nvt')
    for row in cursor:
        cvssArray.append(row[0])

    yearArray = ["2015","2016","2017","2018"]

    familyArray = ["Product detection", "Web application abuses", "Malware", "Web application abuses", "Compliance", "Firewalls",
     "Web Servers", "Credentials", "SMTP problems", "SuSE Local Security ", "Checks",
     "Citrix Xenserver Local Security Checks"]

    lc = 0
    for a1 in yearArray:
        print "year " + a1
        #'{"year":' + str(a1) + ','"arr" : []}'
        yearval = json.loads('{"id" : '+str(a1)+ ',"text": "year ' + str(a1) + '","year":' + str(a1) + ',"children" : []}')
        outputJson["children"].append(yearval)
        for b1 in cvssArray:
            if b1 != None and b1 != '10.00.0':

                b1 = re.sub('\);','',b1)
                b1 = b1.lstrip()
                b1 = b1.rstrip()
                cvalue = float(b1)
                if cvalue > 8.0:
                    print "    cvss " + b1
                    cvssval = json.loads('{"id" : '+b1+ ',"text": "cvss ' + b1 + '","cvss":' + b1 +',"children" : []}')
                    yearval["children"].append(cvssval)
                    for c1 in familyArray:
                        #print c1
                        c1 = c1.lstrip()
                        c1 = c1.rstrip()
                        c1 = re.sub('\);','',c1)

                        familyVal = json.loads('{"id" : "'+c1+ '","text": "' + c1 + '","family":"' + c1 +'","children" : []}')
                        familyVal["arr"] = []
                        familyVal["row_value"] = []
                        cvssval["children"].append(familyVal)
                        lc = lc + 1
                        print lc
                        cursor.execute("select * from nvt where CREATE_YEAR = ? and family = ? and cvss_base = ?", (a1,c1,b1))
                        for row in cursor:
                             all_fields = list(row)
                             familyVal["children"] = {"id" : row[arr_col_names.index("oid")], "text" : row[arr_col_names.index("oid")]}
                             familyVal["row_value"].append(all_fields)
                             #familyVal["arr"].append(row)

    final_output = [outputJson]
    s1 = json.dumps(final_output)
    nvtjson = open("NVT.json", "w")
    nvtjson.write(s1)
    print s1
            # for c1 in cvssArray:
            #     familyval["family"] =


    # for elem in yearArray:
    #     cursor.execute("select * from nvt where CREATE_YEAR = ?",(elem))
    #     for row in cursor:
    #         outputJson[elem]

def nvt_processing():
    process = nvt_parse_and_db_addition_required()
    #init()
    if process == True:
        naslfile = "/home/sidbg/Desktop/govt_project/community-nvt-feed-current/gb_adobe_flash_player_detect_lin.nasl"
        xarray = walk_all_nvt("/home/sidbg/Desktop/govt_project/community-nvt-feed-current")
        #xarray = walk_all_nvt("/home/sidbg/Desktop/govt_project/tmp")
        add_nvts_to_db(xarray)
    create_grouped_data()

nvt_processing()
exit()

arr = []
with open('/home/sidbg/Desktop/govt_project/all_stigs.csv', 'rb') as csvfile:
    spamreader = csv.reader(csvfile, delimiter=',', quotechar='"')
    count = 0

    for row in spamreader:
        if(len(row)>=23):
            # print row[0] + " " + row[23]
            specs = row[23].split('\n')
            vul_id = row[0]
            CCI_id = specs[0]
            if(len(specs)>=4):
                nistsp80053 = specs[4]
                nistsp80053 = nistsp80053.split(":")
                if len(nistsp80053) >=2:
                    nistsp80053 = nistsp80053[2]
                    stig_id = row[4]
                    count = count + 1
                    print "\"" + vul_id + "\",\"" + CCI_id + "\",\"" +  stig_id + "\",\"" +  nistsp80053.lstrip() + "\""
                    dictrow = {"vul_id" : vul_id, "CCI_id" : CCI_id, "stig_id" : stig_id, "nistsp80053" : nistsp80053.lstrip()}
                    arr.append(dictrow)
            else:
                print "cannot process -> " + vul_id + str(specs)
    print "\n" + str(count) + " new line \n"
#, quotechar=''

app = Flask(__name__)


def getvullist(p):
    resarr = []
    for elem in arr:
        if re.match(p + " ", elem["nistsp80053"]):
            resarr.append(elem)
    return resarr

@app.route('/')
def hello():
    return "Hello World!"

@app.route('/vulnerabilityinfo', methods=['POST']) #GET requests will be blocked
def get_vul_id():
    paramarr = request.get_json()["NIST80053IDs"]
    finallist = []
    for p in paramarr:
        vularr = getvullist(p)
        e = {"id" : p, "vul": vularr}
        finallist.append(e)
    retstr = json.dumps(finallist)
    return retstr

@app.route('/getNVDdata', methods=['POST']) #GET requests will be blocked
def get_vul_id():
    paramarr = request.get_json()
    finallist = []
    for p in paramarr:
        vularr = getvullist(p)
        e = {"id" : p, "vul": vularr}
        finallist.append(e)
    retstr = json.dumps(finallist)
    return retstr

@app.route('/getAllNVTData', methods=['POST']) #GET requests will be blocked
def get_vul_id():
    paramarr = request.get_json()
    finallist = []
    for p in paramarr:
        vularr = getvullist(p)
        e = {"id" : p, "vul": vularr}
        finallist.append(e)
    retstr = json.dumps(finallist)
    return retstr

if __name__ == '__main__':
    app.run(host= '0.0.0.0')