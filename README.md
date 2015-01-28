## gumpswd - a simple password manager ##

The latest version of this document can be found at [here](https://github.com/cctags/gumpswd/blob/master/README.md).

### 1. Introduction ###

It's a very simple password manager. It can also be used as a password generator.

### 2. Build Environment ###

?

### 3. Usage ###

<pre>
$gumpswd --help
usage: main.py [-h] [-f FILE] [-g N] [-v]

simple password manager. v0.2

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  specify the db file
  -g N, --generate N    generate one password in &ltN> characters
  -v, --version         show program's version number and exit

Command action
    d               delete the item
    e               edit the item
    export &ltfile>   export the items to the &ltfile>
    import &ltfile>   import the items from the &ltfile>
    info            show the meta info
    m               print this menu
    n               add a new item
    p               list all items
    p &ltstr>         list all matching items
    p &ltstr> copy    copy the password of the matching item
    p &ltstr> show    show the password of the matching item
    pid &ltid>        list the specified item
    pid &ltid> copy   copy the password of the specified item
    pid &ltid> show   show the password of the specified item
    q               quit without saving changes
    w               write data changes and exit
    X               change the main password
</pre>

### 4. Version History ###

* version 0.2: (January, 2015)
* version 0.1: (February, 2013)
