import json
from sets import Set
from pprint import pprint
new_item_array = []

def gather_NVD_Data():
    global new_item_array
    with open('/home/sidbg/Desktop/govt_project/nvdcve-1.0-2018.json') as f:
        data = json.load(f)

    count = 0
    skipped_count = 0
    for cveitem in data["CVE_Items"]:
        new_item = {}
        new_item["CVE_ID"] = cveitem['cve']['CVE_data_meta']['ID']
        print new_item["CVE_ID"]
        if not cveitem['impact'].has_key('baseMetricV3'):
            skipped_count = skipped_count + 1
            continue
        new_item["AttackVector"] = cveitem['impact']['baseMetricV3']['cvssV3']['attackVector']
        new_item["Severiety"] = cveitem['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        new_item["AvailabilityImpact"] = cveitem['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
        new_item["ConfidentialityImpact"] = cveitem['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
        if(len(cveitem["cve"]["affects"]['vendor']['vendor_data'])==0):
            new_item = {}
            skipped_count = skipped_count + 1
            continue
        new_item["Vendor"] = cveitem["cve"]["affects"]['vendor']['vendor_data'][0]["vendor_name"]
        new_item["Description"] = cveitem["cve"]["description"]["description_data"][0]["value"]
        new_item["id"] = new_item["CVE_ID"]
        new_item["text"] = new_item["CVE_ID"]
        new_item["children"] = []
        count = count + 1
        new_item_array.append(new_item)
        ss = json.dumps(cveitem)

def getUniqueColumValue(column_name):
    result = Set([])
    for elem in new_item_array:
        result.add(elem[column_name])
    return result

def doesRowQualify(row, column, value):
    if row[column] == value:
        return True
    return False


def get_qualifying_rows(criteria):
    result = []
    for data in new_item_array:
        res = True
        for columnname in criteria.keys():
            if doesRowQualify(data,columnname, criteria[columnname]) == False:
                res = False
                break
        if res == True :
            result.append(data)
    return result



def build_tree_structure():
    count = 0
    attackvectors = getUniqueColumValue("AttackVector")
    severietyvectors = getUniqueColumValue("Severiety")
    #vendors = getUniqueColumValue("Vendor")
    vendors = ["cisco", "samsung", "fsi", "sophos", "sonicwall", "nasa", "ivanti", "rubyonrails", "microsoft", "belkin",
               "kddi", "fujielectric", "apple"]
    main_arr = {"id" : "NVD Data", "text":"NVD Data", "children" : []}
    for attackvector in attackvectors:
        avval = "Attack Vector -> " + attackvector
        attackvectorjson = {"id" : avval, "text": avval, "children" : []}
        main_arr["children"].append(attackvectorjson)
        for severietyvector in severietyvectors:
            sval = "Severiety -> " + severietyvector
            severietyvectorjson = {"id": sval, "text": sval, "children": []}
            attackvectorjson["children"].append(severietyvectorjson)
            for vendor in vendors:
                vendorjson = {"id" : vendor, "text": vendor, "children" : []}
                severietyvectorjson["children"].append(vendorjson)
                qualifying_rows = get_qualifying_rows({"AttackVector":attackvector, "Severiety":severietyvector, "Vendor" : vendor})
                vendorjson["children"] = qualifying_rows
                count = count + 1
                print count
    return main_arr

def driver():
    gather_NVD_Data()
    a = build_tree_structure()
    final_output = [a]
    s1 = json.dumps(final_output)
    nvdjson = open("NVD.json", "w")
    nvdjson.write(s1)
    #print  a

#ch = get_qualifying_rows({"AttackVector":attackvector, "Severiety":severietyvector})

driver()

#pprint(data)