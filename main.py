#!/usr/bin/env python
# coding: utf-8

import argparse
import cPickle as pickle
import datetime
import getpass
import hashlib
import os
import random
import readline
import string
import sys

import xtea

program_name    = "gumpswd"
program_version = "v0.2"

key_info        = "setting_00_02_00_01"
key_data        = "data_00_02_00_01"

def print_command_usage():
    print \
"""Command action
    d               delete the item
    e               edit the item
    m               print this menu
    n               add a new item
    p               list all items
    p <str>         list all matching items
    p <str> copy    copy the password of the matching item
    p <str> show    show the password of the matching item
    pid <id>        list the specified item
    pid <id> copy   copy the password of the specified item
    pid <id> show   show the password of the specified item
    q               quit without saving changes
    w               write data changes and exit
    X               change the main password
"""

def encrypt_string(str, key):
    return xtea.crypt(key, str)

def save_text_to_clipboard(str):
    import pyperclip
    pyperclip.setcb(str)

def generate_password(range=None, size=16):
    if not range:
        range = string.digits + string.ascii_letters + string.digits
    a = []
    while len(a) < size - 2:
        a.append(random.choice(range))
    while len(a) < size:
        a.append(random.choice(string.punctuation))
    random.shuffle(a)
    return ''.join(a)

def dump_db(db, key):
    print "+-- %s" % (key_info)
    for k, v in db[key_info].items():
        print "|   +-- %s: %s" % (k, v)

    index = 0
    print "+-- %s" % (key_data)

    for i in db[key_data]:
        print "|   +-- %d" % (index)
        index = index + 1

        for k, v in i.items():
            print "|   |   +-- %s: %s" % (k, encrypt_string(v, key))

def print_item(db, key, index, show=False):
    item = db[key_data][index].items()
    print "+-- %d" % (index)
    if show is True:
        for k, v in item:
            if k in ("c", "u", "p", "t"):
                print "|   +-- %s: %s" % (k, encrypt_string(v, key))
    else:
        for k, v in item:
            if k in ("c", "u", "t"):
                print "|   +-- %s: %s" % (k, encrypt_string(v, key))
            else:
                print "|   +-- %s: %s" % (k, "***")

def print_id_db(db, key, index, show=False, copy=False):
    if copy is True:
        save_text_to_clipboard(encrypt_string(db[key_data][index]["p"], key))
    else:
        print_item(db, key, index, show)

def print_db(db, key, str=None, show=False, copy=False):
    index = 0
    result = []
    for i in db[key_data]:
        if str is None or str in encrypt_string(i["c"], key):
            result.append(index)
        index = index + 1

    if len(result) == 0:
        info("no match.")
        return

    if show is False and copy is False:
        for index in result:
            print_item(db, key, index)
    else:
        if len(result) > 1:
            info("to many match.")
            return

        index = result[0]

        if show is True:
            print_item(db, key, index, True)
        elif copy is True:
            save_text_to_clipboard(encrypt_string(db[key_data][index]["p"], key))
    print ""

def get_pass_strip(prompt):
    if not prompt:
        str = getpass.getpass()
    else:
        str = getpass.getpass(prompt)
    return str.strip()

def get_non_empty_raw_input(prompt):
    while True:
        str = raw_input(prompt).strip()
        if len(str) == 0:
            continue
        return str

def get_non_empty_password():
    while True:
        pwd1 = get_pass_strip("Enter encryption key:")
        pwd2 = get_pass_strip("Enter same key again:")
        if (len(pwd1) != 0) and (pwd1 == pwd2):
            return pwd1
        else:
            print "Passwords don't match - try again."

def check_user_input_id(db, id):
    return id in range(0, len(db[key_data]))

def add_new_item(db, c, u, p, t):
    item = {"c": c, "u": u, "p": p, "t": t}
    db[key_data].append(item)

def change_main_password(db, key, pwd):
    if db[key_info]["sha512"] == hashlib.sha512(pwd).hexdigest():
        return

    db[key_info]["sha512"] = hashlib.sha512(pwd).hexdigest()

    newkey = hashlib.md5(pwd).digest()

    for i in db[key_data]:
        for k, v in i.items():
            a = encrypt_string(v, key)
            i[k] = encrypt_string(encrypt_string(v, key), newkey)

def load_db_from_file(file):
    f = open(file, "rb")
    db = pickle.load(f)
    f.close()
    return db

def save_db_to_file(db, file):
    db[key_info]["update"] = str(datetime.datetime.now())
    f = open(file, "wb")
    pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)
    f.close()

def panic(str):
    print "[ERROR]: %s\n" % (str)
    sys.exit(1)

def info(str):
    print "[WRONG]: %s\n" % (str)

def main():

    # Parse the command line options
    parser = argparse.ArgumentParser(description="simple password manager. %s" % (program_version))
    parser.add_argument("-f", "--file", help="specify the db file")
    parser.add_argument("-g", "--generate", help="generate one password in <N> characters", type=int, metavar="N")
    version_string = program_name + " " + program_version
    parser.add_argument("-v", "--version", action="version", version=version_string)
    args = parser.parse_args()

    # generate one password
    if args.generate is not None:
        if args.generate in xrange(4, 128):
            print generate_password(range=None, size=args.generate)
            sys.exit(0)
        else:
            panic("invalid choice: %d (choose from 4 to 128)" % (args.generate))

    # configure the db file path
    if args.file is not None:
        dbpath = args.file
    else:
        dbpath = "%s.db" % (program_name.lower())
        dbpath = os.path.join(os.path.expanduser("~"), dbpath)

    # The db data tree
    db = { \
            key_info: { \
                "sha512": "", \
                "create": "", \
                "update": "" \
            }, \
            \
            key_data: [] \
            }

    # Check if the file exists.
    if not os.path.exists(dbpath):

        # Setup the main password.
        pwd = get_non_empty_password()

        # Init the info.
        db[key_info]["sha512"] = hashlib.sha512(pwd).hexdigest()
        db[key_info]["create"] = str(datetime.datetime.now())
    else:

        db = load_db_from_file(dbpath)

        if not db.has_key(key_info):
            panic("File format error!")

        digest = db[key_info]["sha512"]

        pwd = get_pass_strip("Enter encryption key:")

        if hashlib.sha512(pwd).hexdigest() != digest:
            panic("Permission denied!")

    key = hashlib.md5(pwd).digest()

    # Print the db info.
    print ">> file: %s" % (dbpath)
    print "Created: %s" % (db[key_info]["create"])
    if db[key_info].has_key("update"):
        print "Updated: %s" % (db[key_info]["update"])
    print ""

    # Main loop.
    while True:

        # Get the input command.
        cmd = raw_input("Command (m for help): ").strip()
        if len(cmd) == 0:
            continue

        # Print
        if cmd.startswith("p"):
            args = cmd.split()

            if args[0] == "p":
                if len(args) == 1:
                    print_db(db, key)
                elif len(args) == 2:
                    print_db(db, key, args[1])
                elif len(args) == 3:
                    if args[2] == "show":
                        print_db(db, key, args[1], show=True)
                    elif args[2] == "copy":
                        print_db(db, key, args[1], copy=True)
                    else:
                        info("%s: invalid input." % (args[2]))

            elif args[0] == "pid":
                if len(args) == 1:
                    print_db(db, key)
                elif len(args) == 2:
                    print_id_db(db, key, int(args[1]))
                elif len(args) == 3:
                    if args[2] == "show":
                        print_id_db(db, key, int(args[1]), show=True)
                    elif args[2] == "copy":
                        print_id_db(db, key, int(args[1]), copy=True)
                    else:
                        info("%s: invalid input." % (args[2]))
            else:
                info("%s: unknown command." % (cmd))

        # Delete.
        elif cmd == "d":
            id = get_non_empty_raw_input("[id]: ")
            id = int(id)

            if check_user_input_id(db, id):
                del db[key_data][id]
            else:
                print "Invalid id (%d)." % (id)

        # Dump.
        elif cmd == "dump":
            dump_db(db, key)

        # Edit.
        elif cmd == "e":

            # user input id
            id = get_non_empty_raw_input("[id]: ")
            id = int(id)

            if check_user_input_id(db, id):

                op = get_non_empty_raw_input("[c/u/p/t]: ")
                if op in ("c", "u", "p", "t"):
                    if op == "c":
                        value = get_non_empty_raw_input("[caption]: ")
                    elif op == "u":
                        value = get_non_empty_raw_input("[username]: ")
                    elif op == "p":
                        value = get_non_empty_password()
                    else:
                        value = get_non_empty_raw_input("[text]: ")

                    # update the values
                    db[key_data][id][op] = encrypt_string(value, key)

                else:
                    info("%s: invalid input." % (op))
            else:
                info("Invalid id (%d)." % (id))

        # New.
        elif cmd == "n":
            c = get_non_empty_raw_input("[caption]: ")
            u = get_non_empty_raw_input("[username]: ")
            p = get_non_empty_password()
            t = get_non_empty_raw_input("[text]: ")

            c = encrypt_string(c, key)
            u = encrypt_string(u, key)
            p = encrypt_string(p, key)
            t = encrypt_string(t, key)

            add_new_item(db, c, u, p, t)

        # Help.
        elif cmd == "m":
            print_command_usage()

        # Quit.
        elif cmd == "q":
            sys.exit(0)

        # Write.
        elif cmd == "w":
            save_db_to_file(db, dbpath)
            sys.exit(0)

        # Change the main password.
        elif cmd == "X":
            pwd = get_non_empty_password()
            change_main_password(db, key, pwd)
            key = hashlib.md5(pwd).digest()

        # Unknown command.
        else:
            info("%s: unknown command." % (cmd))

if __name__ == "__main__":
    main()
