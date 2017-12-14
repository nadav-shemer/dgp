# -*- coding: utf-8 -*-
"""
    Dgp
    ~~~~~~

    Stuffs

    :copyright: (c) 2017 by dgp author.
    :license: BSD, see LICENSE for more details.
"""

from sqlite3 import dbapi2 as sqlite3
from flask import Blueprint, request, session, g, redirect, url_for, abort, \
     render_template, flash, current_app
from werkzeug.security import pbkdf2_bin, pbkdf2_hex
from Crypto.PublicKey import RSA
import base64
import os


# create our blueprint :)
bp = Blueprint('dgp', __name__)


def connect_db():
    """Connects to the specific database."""
    rv = sqlite3.connect(current_app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv


def init_db():
    """Initializes the database."""
    db = get_db()
    with current_app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_entry(name):
    """Convenience method to look up an entry by name."""
    rv = query_db('select type from entries where name = ?',
                  [name], one=True)
    return rv[0] if rv else None

def get_note(name):
    """Get an entry's note by name."""
    rv = query_db('select note from entries where name = ?',
                  [name], one=True)
    return rv[0] if rv else None

@bp.route('/')
def show_entries():
    db = get_db()
    cur = db.execute('select name, type from entries order by id desc')
    entries = cur.fetchall()
    return render_template('show_entries.html', entries=entries)


@bp.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    old_entry = get_entry(request.form['name'])
    if old_entry:
        flash('Duplicate entry exists')
        return redirect(url_for('dgp.show_entries'))
    if request.form['type'] == "other":
        entry_type = request.form['other']
    else:
        entry_type = request.form['type']
    db.execute('insert into entries (name, type, note) values (?, ?, ?)',
               [request.form['name'], entry_type, request.form['note']])
    db.commit()
    flash('New entry was successfully added')
    return redirect(url_for('dgp.show_entries'))

def bytes_to_int(bytes_rep):
    """convert a string of bytes (in big-endian order) to a long integer

    :param bytes_rep: the raw bytes
    :type bytes_rep: str
    :return: the unsigned integer
    :rtype: long
    """
    return long(base64.b16encode(bytes_rep), 16)

dec_digit_to_base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#base58_digit_to_dec = { b58:dec for dec,b58 in enumerate(dec_digit_to_base58) }

def get_base58(int_data):
    res = ''
    while int_data > 0:
        mod = int_data % 58
        int_data = int_data / 58
        res = res + dec_digit_to_base58[mod]
    return res

# Because password 'strength' checkers are dicks
def is_alnum(string):
    has_lower = False
    has_upper = False
    has_digit = False
    for i in range(len(string)):
        if string[i] >= '0' and string[i] <= '9':
            has_digit = True
        if string[i] >= 'a' and string[i] <= 'z':
            has_lower = True
        if string[i] >= 'A' and string[i] <= 'Z':
            has_upper = True
    return has_digit and has_lower and has_upper

def grab_alnum(int_data, length):
    raw = get_base58(int_data)
    while True:
        # We assume there is a substring that will pass. Otherwise we explode
        assert len(raw) > length
        res = raw[:length]
        if is_alnum(res):
            return res
        raw = raw[1:]

# TODO
def get_seed():
    filename = os.path.join(current_app.root_path, 'seed')
    with open(filename) as f:
        seed = f.read()
    return seed

def gen_large_int(name, secret):
    # keylen=digest-len hashfunc=sha256
    bin_data = pbkdf2_bin(get_seed() + secret, name, iterations=8192)
    int_data = bytes_to_int(bin_data)
    return int_data

def get_wordlist():
    filename = os.path.join(current_app.root_path, 'english.txt')
    with open(filename) as f:
        lines = f.readlines()
    return [line.rstrip() for line in lines]

def get_xkcd(int_data):
    wordlist = get_wordlist()
    res = []
    while int_data > 0:
        mod = int_data % 2048
        int_data = int_data / 2048
        res.append(wordlist[mod])
    return res

def grab_xkcd(int_data, count):
    words = get_xkcd(int_data)
    return ' '.join(words[:count])

def grab_ssh(name, secret):
    counter = [0]
    def get_rand(length):
        res = pbkdf2_bin(get_seed() + secret, '{}{}'.format(name, counter[0]), keylen=length, iterations=8192)
        counter[0] = counter[0] + 1
        return res
    key = RSA.generate(1024, randfunc=get_rand)
    return key.exportKey('OpenSSH')

def generate(name, entry_type, secret):
    if entry_type == 'hex':
        res = pbkdf2_hex(get_seed() + secret, name, iterations=8192)
        res = res[:8]
    elif entry_type == 'hexlong':
        res = pbkdf2_hex(get_seed() + secret, name, iterations=8192)
        res = res[:16]
    elif entry_type == 'alnum':
        int_data = gen_large_int(name, secret)
        res = grab_alnum(int_data, 8)
    elif entry_type == 'alnumlong':
        int_data = gen_large_int(name, secret)
        res = grab_alnum(int_data, 12)
    elif entry_type == 'xkcd':
        int_data = gen_large_int(name, secret)
        res = grab_xkcd(int_data, 4)
    elif entry_type == 'xkcdlong':
        int_data = gen_large_int(name, secret)
        res = grab_xkcd(int_data, 8)
    elif entry_type == 'ssh':
        res = grab_ssh(name, secret)
    else:
        res = 'unknown type'
    flash('Generated: ' + name + ' ' + res)

@bp.route('/gen', methods=['POST'])
def gen_entry():
    if not session.get('logged_in'):
        abort(401)
    if not request.form.get('name'):
        flash('Nothing chosen')
        return redirect(url_for('dgp.show_entries'))
    entry = get_entry(request.form['name'])
    if not entry:
        flash('Error! Entry does not exist')
        return redirect(url_for('dgp.show_entries'))
    note = get_note(request.form['name'])
    if note and note != '':
        flash(note)
    generate(request.form['name'], entry, request.form['secret'])
    return redirect(url_for('dgp.show_entries'))

@bp.route('/custom', methods=['POST'])
def gen_custom():
    if not session.get('logged_in'):
        abort(401)
    generate(request.form['name'], request.form['type'], request.form['secret'])
    return redirect(url_for('dgp.show_entries'))


# TODO: Make something useful here?
@bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != current_app.config['USERNAME']:
            error = 'Invalid username'
        elif request.form['password'] != current_app.config['PASSWORD']:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('dgp.show_entries'))
    return render_template('login.html', error=error)


@bp.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('dgp.show_entries'))
