from ldap3 import Server, Connection, MODIFY_ADD, MODIFY_REPLACE, ALL_ATTRIBUTES, SUBTREE, LEVEL, BASE
from ldap3.core.exceptions import LDAPBindError
from ldap3.utils.dn import safe_rdn
from flask import Flask, jsonify, abort, request, make_response, url_for
import random

server = Server('zeus')
app = Flask(__name__, static_url_path="")

# print(0, conn.extend.standard.who_am_i())
users = {}


@app.route('/login', methods=['POST'])
def login():
    if not request.json:
        return "Not JSON", 400
    if not "username" in request.json:
        return "No Username", 400
    if not "password" in request.json:
        return "No password", 400
    try:
        conn = Connection(server, 'uid=' + request.json["username"] + ', ou=People, dc=nodomain ',
                          request.json["password"], auto_bind=True)
        ### TODO Create a random hash with uid and post it somewhere (LDAP or a DB)
        hash = random.getrandbits(64)
        users[hash] = request.json['username']
        return jsonify({"logged": 1, "key": hash, "valid": 3600}), 201
    except LDAPBindError:
        return jsonify({"logged": 0, "error": "Wrong username/password combination"}), 401


@app.route('/getgroups', methods=["POST"])
def get_servers():
    if not request.json:
        return jsonify({"error": "Not JSON"}), 400
    if 'key' not in request.json:
        return jsonify({"error": "No key"}), 401
    if 'username' not in request.json:
        return jsonify({"error": "No username"}), 401

    ### TODO Check key
    print(users)
    if request.json["key"] in users:
        print(users[request.json["key"]])
        print(request.json["username"])
        if users[request.json["key"]] != request.json["username"]:
            return jsonify({"error": "Invalid key/user combination"})
    else:
        return jsonify({"error": "Invalid key"})
    conn = Connection(server, auto_bind=True)
    conn.search("ou=Servers,dc=nodomain", "(l=" + request.json["username"] + ")", attributes=["objectClass"])

    return_data = {"groups": list()}

    groups = conn.response
    for f in groups:
        print(f)
        if "organizationalUnit" in f["attributes"]["objectClass"]:
            getChildren(conn, f["dn"], return_data)
        elif "ipHost" in f["attributes"]["objectClass"]:
            return_data["groups"].append(f["dn"])

    return jsonify(return_data), 201


@app.route('/getpassword', methods=["POST"])
def get_password():
    if not request.json:
        return jsonify({"error": "Not JSON"}), 400
    if 'key' not in request.json:
        return jsonify({"error": "No key"}), 401
    if 'username' not in request.json:
        return jsonify({"error": "No username"}), 401
    if 'dn' not in request.json:
        return jsonify({"error": "No group"}), 401

    if request.json["key"] in users:
        print(users[request.json["key"]])
        print(request.json["username"])
        if users[request.json["key"]] != request.json["username"]:
            return jsonify({"error": "Invalid key/user combination"})
    else:
        return jsonify({"error": "Invalid key"})

    conn = Connection(server, auto_bind=True)
    conn.search(request.json["dn"], "(objectClass=*)", attributes=["serialNumber", "ipHostNumber"])
    pww = conn.response[0]["attributes"]["serialNumber"][0]
    iph = conn.response[0]["attributes"]["ipHostNumber"][0]
    return jsonify({"password": pww, "ip": iph}), 200


def getChildren(a, b, c):
    # a.search(b, "(&(objectClass=*)(!(dn=" + b + ")))", attributes=["objectClass"])
    a.search(b, "(objectClass=*)", attributes=["objectClass"], search_scope=LEVEL)
    d = a.response
    for f in d:
        print(f)
        if "organizationalUnit" in f["attributes"]["objectClass"]:
            getChildren(a, f["dn"], c)
        elif "ipHost" in f["attributes"]["objectClass"]:
            c["groups"].append(f["dn"])


app.run()
