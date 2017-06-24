from ldap3 import Server, Connection, MODIFY_ADD, MODIFY_REPLACE, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPBindError
from ldap3.utils.dn import safe_rdn
from flask import Flask, jsonify, abort, request, make_response, url_for
import random

server = Server('84.104.226.71')
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
        hash = random.getrandbits(32)
        users[hash] = request.json['username']
        return jsonify({"logged": 1, "key": hash}), 201
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

        ### TODO Get username from DB or LDAP by using the key

        ### TODO get groups from LDAP
    conn = Connection(server,auto_bind=True)
    conn.search("dc=nodomain", "(&(cn=*)(objectClass=posixGroup)(memberUid=udingh))")

    return_data = {"groups":list()}

    groups = conn.response
    for f in groups:
        print(f)
        return_data["groups"].append(f["dn"])
    return jsonify(return_data), 201


app.run()
