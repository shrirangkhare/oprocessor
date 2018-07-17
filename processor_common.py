import os.path
import json
from os import path
import xml.etree.ElementTree as ET
import pickle


tree = None

tree = ET.parse('/home/sidbg/vulnerability/oval.xml')
tree1 = ET.parse('/home/sidbg/vulnerability/test.xml')

r = tree1.getroot()

metadata = list(r)[0]

title = metadata[0].text

affected = metadata[1].attrib['family']

#save_object(tree, 'oval_tree.pkl')

# print only the windows versions

root = tree.getroot()
tests = root[2]
definitions = root[1]
objects = root[3]
states = root[4]
variables = root[5]



def save_object(obj, filename):
    with open(filename, 'wb') as output:  # Overwrites any existing file.
        pickle.dump(obj, output, pickle.HIGHEST_PROTOCOL)

def findchildrenwithattrib(node, attribtxt):
    for elem in node.iter():
        for keyid in attribtxt.keys():
            print elem.attrib
            if keyid in elem.attrib:
                if elem.attrib[keyid] == attribtxt[keyid]:
                    return elem
    return None

def further_exploration_attribs():
    return ['state_ref', 'object_ref', 'var_ref']

def search_node(key, value):
    nodeArr = []
    if key == 'state_ref':
        nodeArr = list(states)
    if key == 'object_ref':
        nodeArr = list(objects)
    if key == 'var_ref':
        nodeArr = list(variables)

    for elem in nodeArr:
        if elem.attrib['id'] == value:
            return elem
    return None

def get_space(x):
    str1 = ""
    for a in range(0,x):
        str1 = str1 + " "
    return str1

def splittag(s):
    arr = s.split('}')
    return arr[1]

def print_node(node,x):
    txt = ""
    if node == None:
        print "NODE EMPTY--------------"
        return
    if node.text != None:
        wtwhitespace = node.text.rstrip()
        if wtwhitespace != "":
            txt = " text -> " + node.text
    print get_space(x) + "Nodetag -> " + splittag(node.tag) + " attrib -> " + json.dumps(node.attrib) + txt
    for k in node.attrib.keys():
        if k in further_exploration_attribs():
            n = search_node(k, node.attrib[k])
            print_node(n, x+2)
    for elem in list(node):
        print_node(elem,x+2)

def search_node_and_print(nodearr, id):
    for elem in nodearr:
        if elem.attrib['id'] == id:
            print_node(elem,2)

def checkfilter(txt):
    if 'rpminfo_test' in txt:
        return True
    return False

def printalltests(nodearr):
    big_str = ""
    test_s = set()
    for elem in nodearr:
        if checkfilter(splittag(elem.tag)) == True :
            print "\n\n=============== NEW TEST print START -> "
            test_s.add(splittag(elem.tag))
            big_str = big_str + splittag(elem.tag) + "," + elem.attrib['comment'] + "\n"
            print "Nodetag -> " + splittag(elem.tag) + " attrib -> " + json.dumps(elem.attrib)
            for ch in list(elem):
                print_node(ch, 2)
            print "=============== NEW TEST print END <- "
    print test_s
    f = open("test_type.csv", "w+")
    f.write(big_str)

def printalldefinitions(nodearr):
    str = ""
    for elem in nodearr:
        metadata = list(elem)[0]
        idd = elem.attrib['id']
        #print idd
        iclass = elem.attrib['class']
        title = metadata[0].text

        if ('family' in metadata[1].attrib.keys()):
            affected = metadata[1].attrib['family']
        else:
            affected = ""
        s1 = "\"" + idd + "\"!@\"" + iclass + "\"!@\"" + title + "\"!@\"" + affected + "\"\n"
        str = str + s1
        f = open("definitions.csv", "w+")
        print s1
    f.write(str.encode('utf-8'))


#printalltests(list(tests))
print "start"
printalldefinitions(list(definitions))
print "end"


# if path.isfile('oval_tree.pkl'):
#     with open('oval_tree.pkl', 'rb') as input:
#         tree = pickle.load(input)
# else:

#findchildrenwithattrib(tests, {"id":"oval:org.mitre.oval:tst:43783"})