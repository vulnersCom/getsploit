#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import division

__version__ = "0.3.1"

import json
import vulners
import re
import os
import six
import texttable
import urllib
from six import string_types
from clint.textui import progress
from os.path import expanduser

if six.PY2:
    import argparse
else:
    from optparse import OptionParser as argparse

if six.PY3:
    unicode_type = str
    bytes_type = bytes
else:
    unicode_type = unicode
    bytes_type = str


SCRIPTNAME = os.path.split(os.path.abspath(__file__))
DBPATH = os.path.join(expanduser("~"), '.getsploit')
DBFILE = os.path.join(DBPATH, 'getsploit.db')
KEYFILE = os.path.join(DBPATH, 'vulners.key')

if not os.path.exists(DBPATH):
	os.makedirs(DBPATH, exist_ok=True)

try:
    import sqlite3
    import zipfile
    LOCAL_SEARCH_AVAILABLE = True
except:
    LOCAL_SEARCH_AVAILABLE = False


class sploitVulners(vulners.Vulners):

    api_endpoints = {
        'search': "/api/v3/search/lucene/",
        'software': "/api/v3/burp/software/",
        'apiKey': "/api/v3/apiKey/valid/",
        'searchsploitdb': "/api/v3/archive/getsploit/"
    }

    def searchExploit(self, query, lookup_fields=None, limit=500, offset=0, fields=None):

        if lookup_fields:
            if not isinstance(lookup_fields, (list, set, tuple)) or not all(isinstance(item, string_types) for item in lookup_fields):
                raise TypeError('lookup_fields list is expected to be a list of strings')
            searchQuery = "bulletinFamily:exploit AND (%s)" % " OR ".join(
                "%s:\"%s\"" % (lField, query) for lField in lookup_fields)
        else:
            searchQuery = "bulletinFamily:exploit AND %s" % query

        total_bulletins = limit or self._Vulners__search(searchQuery, 0, 0, ['id']).get('total')
        total = 0
        dataDocs = []

        for skip in range(offset, total_bulletins, min(self.search_size, limit or self.search_size)):
            results = self._Vulners__search(searchQuery, skip, min(self.search_size, limit or self.search_size), fields or self.default_fields + ['sourceData'])
            total = max(results.get('total'), total)
            for element in results.get('search'):
                dataDocs.append(element.get('_source'))
        return searchQuery, dataDocs

    def downloadGetsploitDb(self, full_path):
        print("Downloading getsploit database archive. Please wait, it may take time. Usually around 5-10 minutes.")
        # {'apiKey':self._Vulners__api_key}
        download_request = self._Vulners__opener.get(self.vulners_urls['searchsploitdb'], stream = True)
        with open(full_path, 'wb') as f:
            total_length = int(download_request.headers.get('content-length'))
            for chunk in progress.bar(download_request.iter_content(chunk_size=1024), expected_size=(total_length / 1024) + 1):
                if chunk:
                    f.write(chunk)
                    f.flush()
        print("\nUnpacking database.")
        zip_ref = zipfile.ZipFile(full_path, 'r')
        zip_ref.extractall(DBPATH)
        zip_ref.close()
        os.remove(full_path)
        return True

def slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-alpha characters,
    and converts spaces to hyphens.
    """
    if six.PY3:
        value = re.sub('[^\w\s-]', '', value).strip().lower()
        value = re.sub('[-\s]+', '-', value)
        return value
    import unicodedata
    value = unicodedata.normalize('NFKD', unicode(value)).encode('ascii', 'ignore')
    value = unicode(re.sub('[^\w\s-]', '', value).strip().lower())
    value = unicode(re.sub('[-\s]+', '-', value))
    return value

def exploitLocalSearch(query, lookupFields = None, limit = 10):
    # Build query
    # CREATE VIRTUAL TABLE exploits USING FTS4(id text, title text, published DATE, description text, sourceData text, vhref text)
    sqliteConnection = sqlite3.connect(DBFILE)
    cursor = sqliteConnection.cursor()
    # Check if FTS4 is supported
    ftsok = False
    for (val,) in cursor.execute('pragma compile_options'):
        if ('FTS4' in val) or ('FTS3' in val):
            ftsok = True
    if not ftsok:
        print("Your SQLite3 library does not support FTS4. Sorry, without this option local search will not work. Recompile SQLite3 with ENABLE_FTS4 option.")
        exit()
    preparedQuery = " AND ".join(['"%s"' % word for word in query.split()])
    searchRawResults = cursor.execute("SELECT * FROM exploits WHERE exploits MATCH ? ORDER BY published LIMIT ?", ('%s' % preparedQuery,limit)).fetchall()
    searchResults = []
    for element in searchRawResults:
        searchResults.append(
                                               {'id':element[0],
                                                'title':element[1],
                                                'published':element[2],
                                                'description':element[3],
                                                'sourceData':element[4],
                                                'vhref':element[5],
                                                })
    # Output must b
    return preparedQuery, searchResults

def main():

    if not os.path.exists(KEYFILE):
        print("To use getsploit you need to obtain Vulners API key at https://vulners.com")
        api_key = six.moves.input("Please, enter API key: ")
    else:
        api_key = open(KEYFILE, 'r').readlines()[0].strip()
    try:
        vulners_lib = sploitVulners(api_key=api_key)
    except ValueError as exc:
        if "Wrong Vulners API key" in "%s" % exc and os.path.exists(KEYFILE):
            os.unlink(KEYFILE)
        raise exc

    vulners_lib._Vulners__opener.headers.update({'User-Agent': 'Vulners Getsploit %s' % __version__})

    with open(KEYFILE, 'w') as key_file:
        key_file.write(api_key)

    # Vulners key is OK, save it to the

    description = 'Exploit search and download utility'
    if six.PY2:
        parser = argparse.ArgumentParser(description)
        addArgumentCall = parser.add_argument
    else:
        parser = argparse(description)
        addArgumentCall = parser.add_option
    #
    if six.PY2:
        addArgumentCall('query', metavar='query', type=str, nargs='*', help='Exploit search query. See https://vulners.com/help for the detailed manual.')

    # Arguments
    addArgumentCall('-t', '--title', action='store_true',
                        help="Search JUST the exploit title (Default is description and source code).")
    addArgumentCall('-j', '--json', action='store_true',
                        help='Show result in JSON format.')
    addArgumentCall('-m', '--mirror', action='store_true',
                        help='Mirror (aka copies) search result exploit files to the subdirectory with your search query name.')
    addArgumentCall('-c', '--count', nargs=1, type=int, default=10,
                        help='Search limit. Default 10.')
    if LOCAL_SEARCH_AVAILABLE:
        addArgumentCall('-l', '--local', action='store_true',
                        help='Perform search in the local database instead of searching online.')
        addArgumentCall('-u', '--update', action='store_true',
                        help='Update getsploit.db database. Will be downloaded in the script path.')

    if six.PY2:
        options = parser.parse_args()
        searchQuery = " ".join(options.query)
    else:
        options, args = parser.parse_args()
        searchQuery = " ".join(args)

    if isinstance(options.count, list):
        options.count = options.count[0]

    # Update goes first
    if LOCAL_SEARCH_AVAILABLE and options.update:
        vulners_lib.downloadGetsploitDb(os.path.join(DBPATH, "getsplit.db.zip"))
        print("Database download complete. Now you may search exploits using --local key './getsploit.py -l wordpress 4.7'")
        exit()

    # Check that there is a query
    if not searchQuery:
        print("No search query provided. Type software name and version to find exploit.")
        exit()


    # Select propriate search method for the search. Local/remote
    if LOCAL_SEARCH_AVAILABLE and options.local:
        if not os.path.exists(DBFILE):
            print("There is no local database file near getsploit. Run './getsploit.py --update'")
            exit()
        finalQuery, searchResults = exploitLocalSearch(searchQuery, lookupFields=['title'] if options.title else None, limit = options.count)
    else:
        finalQuery, searchResults = vulners_lib.searchExploit(searchQuery, lookup_fields=['title'] if options.title else None, limit = options.count)

    outputTable = texttable.Texttable()
    outputTable.set_cols_dtype(['t', 't', 't'])
    outputTable.set_cols_align(['c', 'l', 'c'])
    outputTable.set_cols_width(['20', '30', '100'])
    tableRows = [['ID', 'Exploit Title', 'URL']]
    jsonRows = []
    for bulletin in searchResults:
        bulletinUrl = bulletin.get('vref') or 'https://vulners.com/%s/%s' % (bulletin.get('type'), bulletin.get('id'))
        tableRows.append([bulletin.get('id'), bulletin.get('title'), bulletinUrl])
        if options.json:
            jsonRows.append({'id':bulletin.get('id'), 'title':bulletin.get('title'), 'url':bulletinUrl})
        if options.mirror:
            pathName = './%s' % slugify(searchQuery)
            # Put results it the dir
            if not os.path.exists(pathName):
                os.mkdir(pathName)
            with open("./%s/%s.txt" % (pathName, slugify(bulletin.get('id'))), 'w') as exploitFile:
                exploitData = bulletin.get('sourceData') or bulletin.get('description')
                if not six.PY3:
                    exploitData = exploitData.encode('utf-8').strip()
                exploitFile.write(exploitData)
    if options.json:
        # Json output
        print(json.dumps(jsonRows))
    else:
        # Text output
        print("Total found exploits: %s" % len(searchResults))
        if not six.PY3:
            quoteStringHandler = urllib.quote_plus
        else:
            quoteStringHandler = urllib.parse.quote_plus
        print("Web-search URL: https://vulners.com/search?query=%s" % quoteStringHandler(finalQuery))
        # Set max coll width by len of the url for better copypaste
        maxWidth = max(len(element[2]) for element in tableRows)
        outputTable.set_cols_width([20, 30, maxWidth])
        outputTable.add_rows(tableRows)
        if not six.PY3:
            # Just pass non-ascii
            print(outputTable.draw().encode('ascii', 'ignore'))
        else:
            # Any better solution here?
            print(outputTable.draw().encode('ascii', 'ignore').decode())

if __name__ == '__main__':
    from getsploit import __version__ as getsploit_version
    main()
