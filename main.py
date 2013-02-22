#!/usr/bin/env python
# coding: utf-8

import datetime
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

setting_key     = "setting_00_00_00_01"

def print_usage():
    print \
"""Usage: %s <subcommand> [option(s)] [args]

Available subcommands:
    add             "dict(caption='xx', ...)"
    copy            <uuid>
    init
    list            [<uuid>]
    remove          <uuid>
    set             <uuid>  "dict(caption='xx', ...)"
    setpassword     <uuid>
""" % (program_name)

def print_error(str):
    print "[ERROR]: %s" % (str)

def generate_id():
    return str(uuid.uuid1())

def encrypt_string(str, key):
    return xtea.crypt(key, str)

def save_text_to_clipboard(str):
    import pyperclip
    pyperclip.setcb(str)

def get_user_input_password():
    while True:
        pwd1 = getpass.getpass("password:")
        pwd2 = getpass.getpass("verify:")
        if (len(pwd1) != 0) and (pwd1 == pwd2):
            return pwd1
        else:
            print "Passwords don't match - try again:"

def dump_tree(t, level=0, indent='    |'):
    level += 1
    try:
        for i in t.items():
            print indent * level + '-', i[0]
            try:
                dump_tree(i[1], level)
            except:
                print indent * level + '-', i[1]
    except:
        if hasattr(t, '__iter__'):
            for i in t:
                print indent * level + '-',i
        else:
            print indent * level + '-', t

def db_open():
    try:
        db = zshelve.btopen(program_dbpath)
    except:
        db = zshelve.open(program_dbpath)
    return db

def check_main_password():
    pwd = getpass.getpass("Please input the main password:")
    db = db_open()
    digest = db[setting_key]["sha512"]
    db.close()
    return (hashlib.sha512(pwd).hexdigest() == digest), hashlib.md5(pwd).digest()

def init():
    db = db_open()
    if not db.has_key(setting_key):
        pwd = get_user_input_password()
        db[setting_key] = { \
                "sha512": hashlib.sha512(pwd).hexdigest(), \
                "create": str(datetime.datetime.now()) \
                }
    else:
        sys.exit(1)
    db.close()

def set_content(uuid, str):
    db = db_open()
    if uuid:
        d = db[uuid]
    else:
        uuid = generate_id()
        db[uuid] = {}
        d = db[uuid]
    t = eval(str)
    for k, v in t.items():
        d[k] = v
    db[uuid] = d
    db.close()

def set_password(uuid):
    db = db_open()
    if not db.has_key(uuid):
        print_error("Entry not found!")
    else:
        ret, key = check_main_password()
        if ret:
            print "OK, now please input the password for that entry:"
            pwd = get_user_input_password()
            d = db[uuid]
            d["password"] = encrypt_string(pwd, key)
            db[uuid] = d
        else:
            print_error("Wrong main password!")
    db.close()

def copy(uuid):
    db = db_open()
    if not db.has_key(uuid):
        print_error("Entry not found!")
    else:
        ret, key = check_main_password()
        if ret:
            save_text_to_clipboard(encrypt_string(db[uuid]["password"], key))
        else:
            print_error("Wrong main password!")
    db.close()

def remove(uuid):
    db = db_open()
    if not db.has_key(uuid):
        print_error("Entry not found!")
    else:
        ret, key = check_main_password()
        if ret:
            del db[uuid]
        else:
            print_error("Wrong main password!")
    db.close()

def list(uuid=None):
    db = db_open()
    if uuid:
        if not db.has_key(uuid):
            print_error("Entry not found!")
        else:
            dump_tree(db[uuid])
    else:
        dump_tree(db)
    db.close()

def main():
    global program_dbpath
    print_flag = False

    program_dbpath = os.path.join(os.path.expanduser("~"), program_dbpath)

    if len(sys.argv) >= 2:
        if sys.argv[1] == "init":
            init()
        elif sys.argv[1] == "add":
            set_content(None, sys.argv[2])
        elif sys.argv[1] == "set":
            if len(sys.argv) >= 4:
                set_content(sys.argv[2], sys.argv[3])
            else:
                print_flag = True
        elif sys.argv[1] == "setpassword":
            set_password(sys.argv[2])
        elif sys.argv[1] == "copy":
            copy(sys.argv[2])
        elif sys.argv[1] == "remove":
            remove(sys.argv[2])
        elif sys.argv[1] == "list":
            if len(sys.argv) > 2:
                list(sys.argv[2])
            else:
                list()
    else:
        print_flag = True

    if print_flag:
        print_usage()

if __name__ == "__main__":
    main()
