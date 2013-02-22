#!/usr/bin/env python
# coding: utf-8

import os
import sys
import hashlib
import getpass
import uuid

import xtea
import zshelve

program_name    = "gumpswd"
program_version = "v0.1"

program_dbpath  = "%s.db" % (program_name.lower())

def generate_id():
    return str(uuid.uuid1())

def get_user_input_password():
    while True:
        pwd1 = getpass.getpass("password:")
        pwd2 = getpass.getpass("verify:")
        if (len(pwd1) != 0) and (pwd1 == pwd2):
            return pwd1
        else:
            print "Passwords don't match - try again:"

def encrypt_string(str, key):
    return xtea.crypt(key, str)

def db_open():
    try:
        db = zshelve.btopen(program_dbpath)
    except:
        db = zshelve.open(program_dbpath)
    return db

def check_main_password():
    pwd = getpass.getpass("Please input the main password:")
    db = db_open()
    digest = db["reserved001"]["sha512"]
    db.close()
    return (hashlib.sha512(pwd).hexdigest() == digest), hashlib.md5(pwd).digest()

def init():
    db = db_open()
    if not db.has_key("reserved001"):
        pwd = get_user_input_password()
        db["reserved001"] = {"sha512": hashlib.sha512(pwd).hexdigest()}
    else:
        sys.exit(1)
    db.close()

def add(str):
    db = db_open()
    db[generate_id()] = eval(str)
    db.close()

def set_password(uuid):
    db = db_open()
    if not db.has_key(uuid):
        print "Entry not fould!"
    else:
        ret, key = check_main_password()
        if ret:
            pwd = get_user_input_password()
            d = db[uuid]
            d["password"] = encrypt_string(pwd, key)
            db[uuid] = d
        else:
            print "Wrong main password!"
    db.close()

def copy(uuid):
    db = db_open()
    if not db.has_key(uuid):
        print "Entry not fould!"
    else:
        ret, key = check_main_password()
        if ret:
            print encrypt_string(db[uuid]["password"], key)
        else:
            print "Wrong main password!"
    db.close()

def remove(uuid):
    db = db_open()
    if not db.has_key(uuid):
        print "Entry not fould!"
    else:
        ret, key = check_main_password()
        if ret:
            del db[uuid]
        else:
            print "Wrong main password!"
    db.close()

def main():
    global program_dbpath

    # parse the options
    usage = program_name + " [-f <file>] [-h] [-v]"
    program_dbpath = os.path.join(os.path.expanduser("~"), program_dbpath)

    # parse the db
    #program_dbpath = os.path.expanduser(options.file)
    if not os.path.isabs(program_dbpath):
        program_dbpath = os.path.realpath(os.path.join(os.curdir, program_dbpath))
    print program_dbpath

    if sys.argv[1] == "init":
        init()
    elif sys.argv[1] == "add":
        add(sys.argv[2])
    elif sys.argv[1] == "setpassword":
        set_password(sys.argv[2])
    elif sys.argv[1] == "copy":
        copy(sys.argv[2])
    elif sys.argv[1] == "remove":
        remove(sys.argv[2])

    return

if __name__ == "__main__":
    main()
