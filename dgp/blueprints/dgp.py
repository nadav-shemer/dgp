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
import engine


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

# TODO
def get_seed():
    filename = os.path.join(current_app.root_path, 'seed')
    with open(filename) as f:
        seed = f.read()
    return seed

def generate(name, entry_type, secret):
    res = engine.generate(get_seed(), name, entry_type, secret)
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
