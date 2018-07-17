import re
import json
from dateutil.parser import parse

def getQuotedString(str):
    res = str
    s = re.search("^\"", str)
    if s == None:
        res = "\"" + res
    e = re.search("\"$", str)
    if e == None :
        res = res + "\""
    return res

def getnaslinfotags():
    nasl_info_tags = ["script_oid", "script_version", "script_tag","script_cve_id","script_bugtraq_id",
                      "script_xref", "script_name", "script_category", "script_copyright", "script_family", "script_dependencies",
                      "script_require_ports", "script_exclude_keys", "script_xref", "script_mandatory_keys", "script_require_keys","script_timeout",
                      "script_require_udp_ports"]
    return nasl_info_tags



def addkeyvalueindict(dict, key, value):
    if(key in dict):
        dict[key].append(value)
    else:
        a = []
        a.append(value)
        dict[key] =  a

def getNameValue(res):
    ar = res.split("value")
    name = ar[0]
    value = ar[1]
    #name = re.sub("name", '',name)
    name = re.sub("name|\"|:|,| ", '', name)
    value = re.sub("^\":|\"", '',value)
    value = re.sub("^ : ", '', value)
    return name, value

def parseScriptTagData(dict, line, tag,var_arr):
    line = line.strip()
    res = re.sub(tag + "\(",'', line)
    res = re.sub("\);$", '', res)
    res = re.sub("name", '"name"', res)
    res = re.sub("value", '"value"', res)
    if tag == "script_tag":
        n1, v1 = getNameValue(res)
        addkeyvalueindict(dict,n1,v1)
        dateObject = None
        if ("last_modification" in line):
            #print n1, v1
            date1 = v1.split('(')
            tempx = re.sub('\) \$', '', date1[1])
            tempx = re.sub('\)$|\) \$;|\) \$|\);', '', date1[1])

            dateObject = parse(tempx)
            dict["MOD_YEAR"] = dateObject.year
            dict["MOD_DAY"] = dateObject.day
            dict["MOD_MONTH"] = dateObject.month
        if ("creation_date" in line):
            date1 = v1.split('(')
            tempx1 = re.sub('\) \$', '', date1[1])
            tempx1 = re.sub('\)$', '', date1[1])
            tempx1 = re.sub('\)\);$','', date1[1])
            tempx1 = re.sub('\)', '', date1[1])
            dateObject = parse(tempx1)
            dict["CREATE_YEAR"] = dateObject.year
            dict["CREATE_DAY"] = dateObject.day
            dict["CREATE_MONTH"] = dateObject.month
    elif tag == "script_xref":
        line = re.sub('^script_xref\(', '', line)
        line = re.sub('\);$', '', line)
        addkeyvalueindict(dict, "xref", line)
    else:
        addkeyvalueindict(dict,re.sub("script_", '', tag), res)

def parse_vars(line):
    res = None
    if re.search("^SCRIPT_OID", line):
        res = re.sub(" ",'',line)
        oidvalue = res.split("=")[1]
        return {"var_name": "SCRIPT_OID", "var_name": oidvalue}
    return res


def parseLine(dict, line, var_arr):
    line = line.lstrip()
    if re.search("^script_", line):
        #print "Parsing  " + line
        tagarray = getnaslinfotags()
        for e in tagarray:
            if re.search(e, line):
                parseScriptTagData(dict, line, e, var_arr)
                return
        print line + " tag repository needs to be updated"
    else:
        vardict = parse_vars(line)
        if vardict != None:
            var_arr.append(vardict)
