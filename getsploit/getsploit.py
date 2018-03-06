#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import division
from __init__ import __version__

try:
    import urllib.request as urllib2
except ImportError:
    import urllib2
import json
import ssl
import sys
import urllib
import platform
import unicodedata
import re
import os

vulnersURL = {
    'searchAPI' : 'https://vulners.com/api/v3/search/lucene/',
    'updateAPI' : 'https://vulners.com/api/v3/archive/getsploit/',
    'idAPI' : 'https://vulners.com/api/v3/search/id/',
    }

pythonVersion = float(".".join(platform.python_version().split(".")[:2]))

if pythonVersion > 2.6:
    import argparse
else:
    from optparse import OptionParser as argparse

__all__ = ["Texttable", "ArraySizeError"]

try:
    if pythonVersion >= 2.3:
        import textwrap
    elif pythonVersion >= 2.2:
        from optparse import textwrap
    else:
        from optik import textwrap
except ImportError:
    sys.stderr.write("Can't import textwrap module!\n")
    raise

if pythonVersion >= 2.7:
    from functools import reduce

if pythonVersion >= 3.0:
    unicode_type = str
    bytes_type = bytes
else:
    unicode_type = unicode
    bytes_type = str


DBPATH, SCRIPTNAME = os.path.split(os.path.abspath(__file__))
DBFILE = os.path.join(DBPATH, 'getsploit.db')

try:
    import sqlite3
    import zipfile
    LOCAL_SEARCH_AVAILABLE = True
except:
    LOCAL_SEARCH_AVAILABLE = False

def obj2unicode(obj):
    """Return a unicode representation of a python object
    """
    if isinstance(obj, unicode_type):
        return obj
    elif isinstance(obj, bytes_type):
        try:
            return unicode_type(obj, 'utf-8')
        except UnicodeDecodeError as strerror:
            sys.stderr.write("UnicodeDecodeError exception for string '%s': %s\n" % (obj, strerror))
            return unicode_type(obj, 'utf-8', 'replace')
    else:
        return unicode_type(obj)


def lenNg(iterable):
    """Redefining len here so it will be able to work with non-ASCII characters
    """
    if isinstance(iterable, bytes_type) or isinstance(iterable, unicode_type):
        unicode_data = obj2unicode(iterable)
        if hasattr(unicodedata, 'east_asian_width'):
            w = unicodedata.east_asian_width
            return sum([w(c) in 'WF' and 2 or 1 for c in unicode_data])
        else:
            return unicode_data.__len__()
    else:
        return iterable.__len__()


class ArraySizeError(Exception):
    """Exception raised when specified rows don't fit the required size
    """

    def __init__(self, msg):
        self.msg = msg
        Exception.__init__(self, msg, '')

    def __str__(self):
        return self.msg


class Texttable:

    BORDER = 1
    HEADER = 1 << 1
    HLINES = 1 << 2
    VLINES = 1 << 3

    def __init__(self, max_width=80):
        """Constructor

        - max_width is an integer, specifying the maximum width of the table
        - if set to 0, size is unlimited, therefore cells won't be wrapped
        """

        if max_width <= 0:
            max_width = False
        self._max_width = max_width
        self._precision = 3

        self._deco = Texttable.VLINES | Texttable.HLINES | Texttable.BORDER | \
            Texttable.HEADER
        self.set_chars(['-', '|', '+', '='])
        self.reset()

    def reset(self):
        """Reset the instance

        - reset rows and header
        """

        self._hline_string = None
        self._row_size = None
        self._header = []
        self._rows = []

    def set_chars(self, array):
        """Set the characters used to draw lines between rows and columns

        - the array should contain 4 fields:

            [horizontal, vertical, corner, header]

        - default is set to:

            ['-', '|', '+', '=']
        """

        if lenNg(array) != 4:
            raise ArraySizeError("array should contain 4 characters")
        array = [ x[:1] for x in [ str(s) for s in array ] ]
        (self._char_horiz, self._char_vert,
            self._char_corner, self._char_header) = array

    def set_deco(self, deco):
        """Set the table decoration

        - 'deco' can be a combinaison of:

            Texttable.BORDER: Border around the table
            Texttable.HEADER: Horizontal line below the header
            Texttable.HLINES: Horizontal lines between rows
            Texttable.VLINES: Vertical lines between columns

           All of them are enabled by default

        - example:

            Texttable.BORDER | Texttable.HEADER
        """

        self._deco = deco

    def set_cols_align(self, array):
        """Set the desired columns alignment

        - the elements of the array should be either "l", "c" or "r":

            * "l": column flushed left
            * "c": column centered
            * "r": column flushed right
        """

        self._check_row_size(array)
        self._align = array

    def set_cols_valign(self, array):
        """Set the desired columns vertical alignment

        - the elements of the array should be either "t", "m" or "b":

            * "t": column aligned on the top of the cell
            * "m": column aligned on the middle of the cell
            * "b": column aligned on the bottom of the cell
        """

        self._check_row_size(array)
        self._valign = array

    def set_cols_dtype(self, array):
        """Set the desired columns datatype for the cols.

        - the elements of the array should be either "a", "t", "f", "e" or "i":

            * "a": automatic (try to use the most appropriate datatype)
            * "t": treat as text
            * "f": treat as float in decimal format
            * "e": treat as float in exponential format
            * "i": treat as int

        - by default, automatic datatyping is used for each column
        """

        self._check_row_size(array)
        self._dtype = array

    def set_cols_width(self, array):
        """Set the desired columns width

        - the elements of the array should be integers, specifying the
          width of each column. For example:

                [10, 20, 5]
        """

        self._check_row_size(array)
        try:
            array = list(map(int, array))
            if reduce(min, array) <= 0:
                raise ValueError
        except ValueError:
            sys.stderr.write("Wrong argument in column width specification\n")
            raise
        self._width = array

    def set_precision(self, width):
        """Set the desired precision for float/exponential formats

        - width must be an integer >= 0

        - default value is set to 3
        """

        if not type(width) is int or width < 0:
            raise ValueError('width must be an integer greater then 0')
        self._precision = width

    def header(self, array):
        """Specify the header of the table
        """

        self._check_row_size(array)
        self._header = list(map(obj2unicode, array))

    def add_row(self, array):
        """Add a row in the rows stack

        - cells can contain newlines and tabs
        """

        self._check_row_size(array)

        if not hasattr(self, "_dtype"):
            self._dtype = ["a"] * self._row_size

        cells = []
        for i, x in enumerate(array):
            cells.append(self._str(i, x))
        self._rows.append(cells)

    def add_rows(self, rows, header=True):
        """Add several rows in the rows stack

        - The 'rows' argument can be either an iterator returning arrays,
          or a by-dimensional array
        - 'header' specifies if the first row should be used as the header
          of the table
        """

        # nb: don't use 'iter' on by-dimensional arrays, to get a
        #     usable code for python 2.1
        if header:
            if hasattr(rows, '__iter__') and hasattr(rows, 'next'):
                self.header(rows.next())
            else:
                self.header(rows[0])
                rows = rows[1:]
        for row in rows:
            self.add_row(row)

    def draw(self):
        """Draw the table

        - the table is returned as a whole string
        """

        if not self._header and not self._rows:
            return
        self._compute_cols_width()
        self._check_align()
        out = ""
        if self._has_border():
            out += self._hline()
        if self._header:
            out += self._draw_line(self._header, isheader=True)
            if self._has_header():
                out += self._hline_header()
        length = 0
        for row in self._rows:
            length += 1
            out += self._draw_line(row)
            if self._has_hlines() and length < lenNg(self._rows):
                out += self._hline()
        if self._has_border():
            out += self._hline()
        return out[:-1]

    def _str(self, i, x):
        """Handles string formatting of cell data

            i - index of the cell datatype in self._dtype
            x - cell data to format
        """
        try:
            f = float(x)
        except:
            return obj2unicode(x)

        n = self._precision
        dtype = self._dtype[i]

        if dtype == 'i':
            return str(int(round(f)))
        elif dtype == 'f':
            return '%.*f' % (n, f)
        elif dtype == 'e':
            return '%.*e' % (n, f)
        elif dtype == 't':
            return obj2unicode(x)
        else:
            if f - round(f) == 0:
                if abs(f) > 1e8:
                    return '%.*e' % (n, f)
                else:
                    return str(int(round(f)))
            else:
                if abs(f) > 1e8:
                    return '%.*e' % (n, f)
                else:
                    return '%.*f' % (n, f)

    def _check_row_size(self, array):
        """Check that the specified array fits the previous rows size
        """

        if not self._row_size:
            self._row_size = lenNg(array)
        elif self._row_size != lenNg(array):
            raise ArraySizeError("array should contain %d elements" \
                % self._row_size)

    def _has_vlines(self):
        """Return a boolean, if vlines are required or not
        """

        return self._deco & Texttable.VLINES > 0

    def _has_hlines(self):
        """Return a boolean, if hlines are required or not
        """

        return self._deco & Texttable.HLINES > 0

    def _has_border(self):
        """Return a boolean, if border is required or not
        """

        return self._deco & Texttable.BORDER > 0

    def _has_header(self):
        """Return a boolean, if header line is required or not
        """

        return self._deco & Texttable.HEADER > 0

    def _hline_header(self):
        """Print header's horizontal line
        """

        return self._build_hline(True)

    def _hline(self):
        """Print an horizontal line
        """

        if not self._hline_string:
            self._hline_string = self._build_hline()
        return self._hline_string

    def _build_hline(self, is_header=False):
        """Return a string used to separated rows or separate header from
        rows
        """
        horiz = self._char_horiz
        if (is_header):
            horiz = self._char_header
        # compute cell separator
        s = "%s%s%s" % (horiz, [horiz, self._char_corner][self._has_vlines()],
            horiz)
        # build the line
        l = s.join([horiz * n for n in self._width])
        # add border if needed
        if self._has_border():
            l = "%s%s%s%s%s\n" % (self._char_corner, horiz, l, horiz,
                self._char_corner)
        else:
            l += "\n"
        return l

    def _len_cell(self, cell):
        """Return the width of the cell

        Special characters are taken into account to return the width of the
        cell, such like newlines and tabs
        """

        cell_lines = cell.split('\n')
        maxi = 0
        for line in cell_lines:
            length = 0
            parts = line.split('\t')
            for part, i in zip(parts, list(range(1, lenNg(parts) + 1))):
                length = length + lenNg(part)
                if i < lenNg(parts):
                    length = (length//8 + 1) * 8
            maxi = max(maxi, length)
        return maxi

    def _compute_cols_width(self):
        """Return an array with the width of each column

        If a specific width has been specified, exit. If the total of the
        columns width exceed the table desired width, another width will be
        computed to fit, and cells will be wrapped.
        """

        if hasattr(self, "_width"):
            return
        maxi = []
        if self._header:
            maxi = [ self._len_cell(x) for x in self._header ]
        for row in self._rows:
            for cell,i in zip(row, list(range(lenNg(row)))):
                try:
                    maxi[i] = max(maxi[i], self._len_cell(cell))
                except (TypeError, IndexError):
                    maxi.append(self._len_cell(cell))

        ncols = lenNg(maxi)
        content_width = sum(maxi)
        deco_width = 3*(ncols-1) + [0,4][self._has_border()]
        if self._max_width and (content_width + deco_width) > self._max_width:
            """ content too wide to fit the expected max_width
            let's recompute maximum cell width for each cell
            """
            if self._max_width < (ncols + deco_width):
                raise ValueError('max_width too low to render data')
            available_width = self._max_width - deco_width
            newmaxi = [0] * ncols
            i = 0
            while available_width > 0:
                if newmaxi[i] < maxi[i]:
                    newmaxi[i] += 1
                    available_width -= 1
                i = (i + 1) % ncols
            maxi = newmaxi
        self._width = maxi

    def _check_align(self):
        """Check if alignment has been specified, set default one if not
        """

        if not hasattr(self, "_align"):
            self._align = ["l"] * self._row_size
        if not hasattr(self, "_valign"):
            self._valign = ["t"] * self._row_size

    def _draw_line(self, line, isheader=False):
        """Draw a line

        Loop over a single cell length, over all the cells
        """

        line = self._splitit(line, isheader)
        space = " "
        out = ""
        for i in range(lenNg(line[0])):
            if self._has_border():
                out += "%s " % self._char_vert
            length = 0
            for cell, width, align in zip(line, self._width, self._align):
                length += 1
                cell_line = cell[i]
                fill = width - lenNg(cell_line)
                if isheader:
                    align = "c"
                if align == "r":
                    out += fill * space + cell_line
                elif align == "c":
                    out += (int(fill/2) * space + cell_line \
                            + int(fill/2 + fill%2) * space)
                else:
                    out += cell_line + fill * space
                if length < lenNg(line):
                    out += " %s " % [space, self._char_vert][self._has_vlines()]
            out += "%s\n" % ['', space + self._char_vert][self._has_border()]
        return out

    def _splitit(self, line, isheader):
        """Split each element of line to fit the column width

        Each element is turned into a list, result of the wrapping of the
        string to the desired width
        """

        line_wrapped = []
        for cell, width in zip(line, self._width):
            array = []
            for c in cell.split('\n'):
                if c.strip() == "":
                    array.append("")
                else:
                    array.extend(textwrap.wrap(c, width))
            line_wrapped.append(array)
        max_cell_lines = reduce(max, list(map(len, line_wrapped)))
        for cell, valign in zip(line_wrapped, self._valign):
            if isheader:
                valign = "t"
            if valign == "m":
                missing = max_cell_lines - lenNg(cell)
                cell[:0] = [""] * int(missing / 2)
                cell.extend([""] * int(missing / 2 + missing % 2))
            elif valign == "b":
                cell[:0] = [""] * (max_cell_lines - lenNg(cell))
            else:
                cell.extend([""] * (max_cell_lines - lenNg(cell)))
        return line_wrapped

def slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-alpha characters,
    and converts spaces to hyphens.
    """
    if pythonVersion > 3.0:
        value = re.sub('[^\w\s-]', '', value).strip().lower()
        value = re.sub('[-\s]+', '-', value)
        return value
    import unicodedata
    value = unicodedata.normalize('NFKD', unicode(value)).encode('ascii', 'ignore')
    value = unicode(re.sub('[^\w\s-]', '', value).strip().lower())
    value = unicode(re.sub('[-\s]+', '-', value))
    return value


def progress_callback_simple(downloaded,total):
    sys.stdout.write(
        "\r" +
        (len(str(total)) - len(str(downloaded))) * " " + str(downloaded) + "/%d" % total +
        " [%3.2f%%]" % (100.0 * float(downloaded) / float(total))
    )
    sys.stdout.flush()

def downloadFile(srcurl, dstfilepath, progress_callback=None, block_size=8192):
    def _download_helper(response, out_file, file_size):
        if progress_callback!=None: progress_callback(0,file_size)
        if block_size == None:
            buffer = response.read()
            out_file.write(buffer)

            if progress_callback!=None: progress_callback(file_size,file_size)
        else:
            file_size_dl = 0
            while True:
                buffer = response.read(block_size)
                if not buffer: break

                file_size_dl += len(buffer)
                out_file.write(buffer)

                if progress_callback!=None: progress_callback(file_size_dl,file_size)
    with open(dstfilepath,"wb") as out_file:
        opener = getUrllibOpener()
        req = urllib2.Request(srcurl)
        if pythonVersion > 3:
            with opener.open(req) as response:
                file_size = int(response.getheader("Content-Length"))
                _download_helper(response,out_file,file_size)
        else:
            response = opener.open(req)
            meta = response.info()
            file_size = int(meta.getheaders("Content-Length")[0])
            _download_helper(response,out_file,file_size)

def getUrllibOpener():
    if pythonVersion > 3.0:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx))
        opener.addheaders = [('Content-Type', 'application/json'),('User-Agent', 'vulners-getsploit-v%s' % __version__)]
    else:
        opener = urllib2.build_opener(urllib2.HTTPSHandler())
        opener.addheaders = [('Content-Type', 'application/json'), ('User-Agent', 'vulners-getsploit-v%s' % __version__)]
    return opener


def searchVulnersQuery(searchQuery, limit):
    vulnersSearchRequest = {"query":searchQuery, 'skip':0, 'size':limit}
    req = urllib2.Request(vulnersURL['searchAPI'])
    response = getUrllibOpener().open(req, json.dumps(vulnersSearchRequest).encode('utf-8'))
    responseData = response.read()
    if isinstance(responseData, bytes):
        responseData = responseData.decode('utf8')
    responseData = json.loads(responseData)
    return responseData

def downloadVulnersGetsploitDB(path):
    archiveFileName = os.path.join(path, 'getsploit.db.zip')
    print("Downloading getsploit database archive. Please wait, it may take time. Usually around 5-10 minutes.")
    downloadFile(vulnersURL['updateAPI'], archiveFileName, progress_callback=progress_callback_simple)
    print("\nUnpacking database.")
    zip_ref = zipfile.ZipFile(archiveFileName, 'r')
    zip_ref.extractall(DBPATH)
    zip_ref.close()
    os.remove(archiveFileName)
    return True

def getVulnersExploit(exploitId):
    vulnersSearchRequest = {"id":exploitId}
    req = urllib2.Request(vulnersURL['idAPI'])
    response = getUrllibOpener().open(req, json.dumps(vulnersSearchRequest).encode('utf-8'))
    responseData = response.read()
    if isinstance(responseData, bytes):
        responseData = responseData.decode('utf8')
    responseData = json.loads(responseData)
    return responseData

def exploitSearch(query, lookupFields = None, limit = 10):
    # Build query
    if lookupFields:
        searchQuery = "bulletinFamily:exploit AND (%s)" % " OR ".join("%s:\"%s\"" % (lField, query) for lField in lookupFields)
    else:
        searchQuery = "bulletinFamily:exploit AND %s" % query
    searchResults = searchVulnersQuery(searchQuery, limit).get('data')
    return searchQuery, searchResults

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
    searchCount = cursor.execute("SELECT Count(*) FROM exploits WHERE exploits MATCH ? ORDER BY published LIMIT ?", ('%s' % preparedQuery,limit)).fetchone()
    searchResults = {'total':searchCount,'search':[]}
    for element in searchRawResults:
        searchResults['search'].append({'_source':
                                               {'id':element[0],
                                                'title':element[1],
                                                'published':element[2],
                                                'description':element[3],
                                                'sourceData':element[4],
                                                'vhref':element[5],
                                                }
                                        })
    # Output must b
    return query, searchResults

def main():
    description = 'Exploit search and download utility'
    if pythonVersion > 2.6:
        parser = argparse.ArgumentParser(description)
        addArgumentCall = parser.add_argument
    else:
        parser = argparse(description)
        addArgumentCall = parser.add_option
    #
    if pythonVersion > 2.6:
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

    if pythonVersion > 2.6:
        options = parser.parse_args()
        searchQuery = " ".join(options.query)
    else:
        options, args = parser.parse_args()
        searchQuery = " ".join(args)

    if isinstance(options.count, list):
        options.count = options.count[0]

    # Update goes first
    if LOCAL_SEARCH_AVAILABLE and options.update:
        downloadVulnersGetsploitDB(DBPATH)
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
        finalQuery, searchResults = exploitSearch(searchQuery, lookupFields=['title'] if options.title else None, limit = options.count)

    outputTable = Texttable()
    outputTable.set_cols_dtype(['t', 't', 't'])
    outputTable.set_cols_align(['c', 'l', 'c'])
    outputTable.set_cols_width(['20', '30', '100'])
    tableRows = [['ID', 'Exploit Title', 'URL']]
    jsonRows = []
    for bulletinSource in searchResults.get('search'):
        bulletin = bulletinSource.get('_source')
        bulletinUrl = bulletin.get('vref') or 'https://vulners.com/%s/%s' % (bulletin.get('type'), bulletin.get('id'))
        tableRows.append([bulletin.get('id'), bulletin.get('title'), bulletinUrl])
        if options.json:
            jsonRows.append({'id':bulletin.get('id'), 'title':bulletin.get('title'), 'url':bulletinUrl})
        if options.mirror:
            pathName = './%s' % slugify(searchQuery)
            # Put results it the dir
            if not os.path.exists(pathName):
                os.mkdir(pathName)
            with open("./%s/%s.txt" % (pathName,slugify(bulletin.get('id'))), 'w') as exploitFile:
                exploitData = bulletin.get('sourceData') or bulletin.get('description')
                if pythonVersion < 3.0:
                    exploitData = exploitData.encode('utf-8').strip()
                exploitFile.write(exploitData)
    if options.json:
        # Json output
        print(json.dumps(jsonRows))
    else:
        # Text output
        print("Total found exploits: %s" % searchResults.get('total'))
        if pythonVersion < 3:
            quoteStringHandler = urllib.quote_plus
        else:
            quoteStringHandler = urllib.parse.quote_plus
        print("Web-search URL: https://vulners.com/search?query=%s" % quoteStringHandler(finalQuery))
        # Set max coll width by len of the url for better copypaste
        maxWidth = max(len(element[2]) for element in tableRows)
        outputTable.set_cols_width([20, 30, maxWidth])
        outputTable.add_rows(tableRows)
        if pythonVersion < 3.0:
            # Just pass non-ascii
            print(outputTable.draw().encode('ascii', 'ignore'))
        else:
            # Any better solution here?
            print(outputTable.draw().encode('ascii', 'ignore').decode())

if __name__ == '__main__':
    main()
