import json
import random
import re
import string
import time
import sys
import pandas as pd
from pandas.plotting import table 
import functools
import matplotlib.pyplot as plt
import numpy as np
import six
import os
import plotly.graph_objects as go

from base64 import b64decode
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from zlib import decompress
import argparse

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--file', required=True, type=str, help='path to .har file')
parser.add_argument('--pic_dir', required=True, type=str, help='path to store png file')

def entry_cmp(e1, e2):
    pid_1 = int(e1['pageref'][5:])
    pid_2 = int(e2['pageref'][5:])
    if pid_1 == pid_2:
        if e1['startedDateTime'] < e2['startedDateTime']:
            return -1
        elif e1['startedDateTime'] > e2['startedDateTime']:
            return 1
        else:
            return 0
    elif pid_1 < pid_2:
        return -1
    else:
        return 1

class FileImporter():
    def __init__(self, har_path):
        self.har_path = har_path
        self.har_raw = None
        self.import_start = None
        self.har_summary = {}
        self.har_parsed = []
        self.main()

    def main(self):
        self._openFile()
        self._validateFile()
        self._parseFile()
        self._populateTable()
        self._finalise()

    def _openFile(self):
        """Open an explorer window to allow the user to select a HAR file to be
        imported. Store the absolute path reference to the selected file."""
        if not self.har_path:
            sys.exit(1)

    def _validateFile(self):
        """File validation. We need to ensure that the user has selected a
        valid JSON file conforming to the HAR 1.1/1.2 specification."""

        print('Importing HAR file...')
        self.import_start = time.time()

        # catch decoding issues
        try:
            with open(self.har_path, 'r', encoding='utf-8-sig') as har_file:
                self.har_raw = json.load(har_file)
        except json.decoder.JSONDecodeError:
            print('[ERROR] Unable to import the selected '
                                           'file due to invalid encoding. Please '
                                           'check the HAR file for errors.')
            sys.exit(1)
        except UnicodeDecodeError:
            print('[ERROR] Unable to import the selected file, '
                                           'please open a valid HAR file.')
            sys.exit(1)

        # catch syntax issues
        try:
            if not self.har_raw['log']['entries']:
                print('[ERROR] HAR file contains no entries.')
                sys.exit(1)
        except KeyError:
            print('[ERROR] HAR file contains no entries.')
            sys.exit(1)

    def _parseFile(self):
        """Take the raw HAR file and extract the relevant information to be used
        to populate the entries table and details panels.
        """

        self.har_summary['log_version'] = self.har_raw['log'].get('version', 'Unknown')
        self.har_summary['log_creator_name'] = self.har_raw['log'].get('creator', {}).get('name', 'Unknown')
        self.har_summary['log_creator_version'] = self.har_raw['log'].get('creator', {}).get('version', 'Unknown')
        self.har_summary['browser_name'] = self.har_raw['log'].get('browser', {}).get('name', 'Unknown')
        self.har_summary['browser_version'] = self.har_raw['log'].get('browser', {}).get('version', 'Unknown')

        for entry in self.har_raw['log']['entries']:

            entry_parsed = {}

            entry_parsed['startedDateTime'] = entry.get('startedDateTime', '')
            entry_parsed['time'] = entry.get('time', 0)
            entry_parsed['serverIPAddress'] = entry.get('serverIPAddress', '')
            entry_parsed['connection'] = entry.get('connection', '')
            entry_parsed['pageref'] = entry.get('pageref', '')
            if len(entry_parsed['pageref']) == 0:
                continue

            entry_parsed['request_method'] = entry.get('request', {}).get('method', '')
            entry_parsed['request_url'] = entry.get('request', {}).get('url', '')
            entry_parsed['request_httpVersion'] = entry.get('request', {}).get('httpVersion', '')
            entry_parsed['request_cookies'] = entry.get('request', {}).get('cookies', [])
            entry_parsed['request_headers'] = entry.get('request', {}).get('headers', [])
            entry_parsed['request_queryString'] = entry.get('request', {}).get('queryString', [])
            entry_parsed['request_postData'] = entry.get('request', {}).get('postData', {})
            entry_parsed['request_postData_mimeType'] = entry_parsed['request_postData'].get('mimeType', '')
            entry_parsed['request_postData_params'] = entry_parsed['request_postData'].get('params', [])
            entry_parsed['request_postData_text'] = entry_parsed['request_postData'].get('text', '')
            entry_parsed['request_headersSize'] = entry.get('request', {}).get('headersSize', -1)
            entry_parsed['request_bodySize'] = entry.get('request', {}).get('bodySize', -1)

            entry_parsed['response_status'] = entry.get('response', {}).get('status', -1)
            entry_parsed['response_statusText'] = entry.get('response', {}).get('statusText', '')
            entry_parsed['response_httpVersion'] = entry.get('response', {}).get('httpVersion', '')
            entry_parsed['response_cookies'] = entry.get('response', {}).get('cookies', [])
            entry_parsed['response_headers'] = entry.get('response', {}).get('headers', [])
            entry_parsed['response_content'] = entry.get('response', {}).get('content', [])
            entry_parsed['response_content_size'] = entry_parsed['response_content'].get('size', -1)
            entry_parsed['response_content_compression'] = entry_parsed['response_content'].get('compression', -1)
            entry_parsed['response_content_mimeType'] = entry_parsed['response_content'].get('mimeType', '')
            entry_parsed['response_content_text'] = entry_parsed['response_content'].get('text', '')
            entry_parsed['response_content_encoding'] = entry_parsed['response_content'].get('encoding', '')
            entry_parsed['response_redirectURL'] = entry.get('response', {}).get('redirectURL', '')
            entry_parsed['response_headersSize'] = entry.get('response', {}).get('headersSize', -1)
            entry_parsed['response_bodySize'] = entry.get('response', {}).get('bodySize', -1)

            entry_parsed['timings_blocked'] = entry.get('timings', {}).get('blocked', -1)
            entry_parsed['timings_dns'] = entry.get('timings', {}).get('dns', -1)
            entry_parsed['timings_connect'] = entry.get('timings', {}).get('connect', -1)
            entry_parsed['timings_send'] = entry.get('timings', {}).get('send', -1)
            entry_parsed['timings_wait'] = entry.get('timings', {}).get('wait', -1)
            entry_parsed['timings_receive'] = entry.get('timings', {}).get('receive', -1)
            entry_parsed['timings_ssl'] = entry.get('timings', {}).get('ssl', -1)

            # not using cache information at the moment

            #if entry.get('cache', {}).get('beforeRequest', {}) is not None:
            #    entry_parsed['cache_beforeRequest_expires'] = entry.get('cache', {}).get('beforeRequest', {}).get('expires', '')
            #    entry_parsed['cache_beforeRequest_lastAccess'] = entry.get('cache', {}).get('beforeRequest', {}).get('lastAccess', '')
            #    entry_parsed['cache_beforeRequest_eTag'] = entry.get('cache', {}).get('beforeRequest', {}).get('eTag', '')
            #    entry_parsed['cache_beforeRequest_hitCount'] = entry.get('cache', {}).get('beforeRequest', {}).get('hitCount', -1)
            #else:
            #    entry_parsed['cache_beforeRequest_expires'] = 'None'
            #    entry_parsed['cache_beforeRequest_lastAccess'] = 'None'
            #    entry_parsed['cache_beforeRequest_eTag'] = 'None'
            #    entry_parsed['cache_beforeRequest_hitCount'] = 'None'

            #if entry.get('cache', {}).get('afterRequest', {}) is not None:
            #    entry_parsed['cache_afterRequest_expires'] = entry.get('cache', {}).get('afterRequest', {}).get('expires', '')
            #    entry_parsed['cache_afterRequest_lastAccess'] = entry.get('cache', {}).get('afterRequest', {}).get('lastAccess', '')
            #    entry_parsed['cache_afterRequest_eTag'] = entry.get('cache', {}).get('afterRequest', {}).get('eTag', '')
            #    entry_parsed['cache_afterRequest_hitCount'] = entry.get('cache', {}).get('afterRequest', {}).get('hitCount', -1)
            #else:
            #    entry_parsed['cache_afterRequest_expires'] = 'None'
            #    entry_parsed['cache_afterRequest_lastAccess'] = 'None'
            #    entry_parsed['cache_afterRequest_eTag'] = 'None'
            #    entry_parsed['cache_afterRequest_hitCount'] = 'None'

            ##################################
            # start of custom HAR parsing logic
            ##################################

            # HAR file may contain unexpected field types
            if entry_parsed['time'] is None:
                entry_parsed['time'] = 0
            if entry_parsed['response_bodySize'] is None:
                entry_parsed['response_bodySize'] = -1

            # slice up the URL into its components
            url = urlparse(entry_parsed['request_url'], scheme='Unknown', allow_fragments=False)
            
            entry_parsed['request_protocol'] = url.scheme
            entry_parsed['request_hostname'] = url.hostname

            if url.query:
                entry_parsed['request_path'] = url.path + '?' + url.query
            else:
                entry_parsed['request_path'] = url.path

            if url.port:
                entry_parsed['request_port'] = url.port
            elif url.scheme == 'https':
                entry_parsed['request_port'] = '443'
            elif url.scheme == 'http':
                entry_parsed['request_port'] = '80'
            # TODO use default ports for protocols other than http/s
            else:
                entry_parsed['request_port'] = ''

            # extract cookie info from headers if cookies object is empty
            if not entry_parsed['request_cookies']:
                entry_parsed['request_cookies'] = self._parseCookies(entry_parsed['request_headers'])
            if not entry_parsed['response_cookies']:
                entry_parsed['response_cookies'] = self._parseCookies(entry_parsed['response_headers'])

            # SAML requests and responses
            entry_parsed['saml_request'] = ''
            entry_parsed['saml_response'] = ''
                
            # HAR files don't have a unique ID for each request so let's make one to be used
            # for indexing later.
            # uid = ''.join(random.choice(string.ascii_lowercase) for i in range(8))

            ##################################
            # end of custom HAR parsing logic
            ##################################

            self.har_parsed.append(entry_parsed)

    def _populateTable(self):
        """Sort the main entries table from the parsed HAR data."""
        self.har_parsed = sorted(self.har_parsed, key=functools.cmp_to_key(entry_cmp))

    def _finalise(self):

        import_stop = time.time()
        elapsed_time = import_stop - self.import_start

        print('[OK] Imported {} entries in {:.1f} seconds'.format("XXX", elapsed_time))

    @staticmethod
    def _parseCookies(headers):
        """If there is no cookie object included for a request/response, try to construct
        one from the HTTP headers if we find Cookie or Set-Cookie headers.
        """
        cookie_object = []

        for header in headers:
            if header['name'].lower() == 'cookie':
                cookie_object.append(header['value'].split('; '))
            elif header['name'].lower() == 'set-cookie':
                cookie_object.append(header['value'].split('\n'))

        cookie_object = [item for sublist in cookie_object for item in sublist]
        return cookie_object

    @staticmethod
    def _parseSaml(saml, saml_type):
        """Decode any SAML request/response messages found in  the query string (HTTP-Redirect binding)
        or body text (HTTP-POST binding).
        """

        if saml_type == 'request':
            for param in saml:
                # query strings with no names may be recorded as null in HAR (looking at you Fiddler)
                if param['name'] is not None and param['name'].lower() == 'samlrequest':
                    try:
                        request_encoded = param['value'].replace('%2B', '+') \
                                                        .replace('%2F', '/') \
                                                        .replace('%3D', '=') \
                                                        .replace('%0A', '') \
                                                        .replace('%0D', '')
                        request_decoded = b64decode(request_encoded)
                        request_decompressed = decompress(request_decoded, -15).decode('utf-8')
                        request_formatted = BeautifulSoup(request_decompressed, 'xml').prettify()
                        return request_formatted
                    except:
                        return 'Couldn\'t parse SAML request.'

        elif saml_type == 'response':
            saml_response = re.search(r'(?<=SAMLResponse\=)[A-Za-z0-9\%\+\=\/]+', saml)
            if saml_response:
                response_encoded = saml_response.group()
                response_encoded = response_encoded.replace('%2B', '+') \
                                                   .replace('%2F', '/') \
                                                   .replace('%3D', '=') \
                                                   .replace('%0A', '') \
                                                   .replace('%0D', '')
                try:
                    response_decoded = b64decode(response_encoded).decode('utf-8')
                    response_formatted = BeautifulSoup(response_decoded, 'xml').prettify()
                    return response_formatted
                except:
                    return 'Couldn\'t parse SAML response.'

        return ''

def buildPageTable(entry_list, st, en):
    url_list = list()
    block_list = list()
    dns_list = list()
    connect_list = list()
    send_list = list()
    wait_list = list()
    receive_list = list()
    ssl_list = list()
    total_list = list()
    for i in range(st, en):
        url_list.append(entry_list[i]['request_url'][:min(25, len(entry_list[i]['request_url']))])
        block_list.append(entry_list[i]['timings_blocked'])
        dns_list.append(entry_list[i]['timings_dns'])
        connect_list.append(entry_list[i]['timings_connect'])
        send_list.append(entry_list[i]['timings_send'])
        wait_list.append(entry_list[i]['timings_wait'])
        receive_list.append(entry_list[i]['timings_receive'])
        ssl_list.append(entry_list[i]['timings_ssl'])

        cnt = 0
        cnt += max(0, entry_list[i]['timings_blocked'])
        cnt += max(0, entry_list[i]['timings_dns'])
        cnt += max(0, entry_list[i]['timings_connect'])
        cnt += max(0, entry_list[i]['timings_send'])
        cnt += max(0, entry_list[i]['timings_wait'])
        cnt += max(0, entry_list[i]['timings_receive'])
        cnt += max(0, entry_list[i]['timings_ssl'])
        total_list.append(cnt)

        
    return list(zip(url_list, block_list, dns_list, connect_list, send_list, wait_list, receive_list, ssl_list, total_list)), total_list



def render_mpl_table(data, col_width=3.5, row_height=0.625, font_size=14,
                     header_color='#40466e', row_colors=['#f1f1f2', 'w'], edge_color='w',
                     bbox=[0, 0, 1, 1], header_columns=0,
                     ax=None, **kwargs):
    if ax is None:
        size = (np.array(data.shape[::-1]) + np.array([0, 1])) * np.array([col_width, row_height])
        fig, ax = plt.subplots(figsize=size)
        ax.axis('off')

    mpl_table = ax.table(cellText=data.values, bbox=bbox, colLabels=data.columns, **kwargs)

    mpl_table.auto_set_font_size(False)
    mpl_table.set_fontsize(font_size)

    for k, cell in  six.iteritems(mpl_table._cells):
        cell.set_edgecolor(edge_color)
        if k[0] == 0 or k[1] < header_columns:
            cell.set_text_props(weight='bold', color='w')
            cell.set_facecolor(header_color)
        else:
            cell.set_facecolor(row_colors[k[0]%len(row_colors) ])
    return fig

def drawTable(table_entry, path):
    df = pd.DataFrame(table_entry, columns=['Request', 'Blocked', 'DNS', 'Connect', 'Send', 'Wait', 'Receive', 'SSL', 'Total'])

    """ax = plt.subplot(111, frame_on=False) # no visible frame
    ax.xaxis.set_visible(False)  # hide the x axis
    ax.yaxis.set_visible(False)  # hide the y axis

    table(ax, df)  # where df is your data frame

    plt.savefig(path + '.png', dpi=400)"""
    fig = render_mpl_table(df)
    fig.savefig(path)

def drawWaterfall(total_list, path):
    
    fig = go.Figure()
    fig.add_trace(go.Waterfall(
        x = list(range(len(total_list))),
        orientation = "h",
        measure=['absolute'] + ['relative' for i in range(len(total_list) - 1)],
        base=0,
        decreasing = {"marker":{"color":"Maroon", "line":{"color":"red", "width":2}}},
        increasing = {"marker":{"color":"Teal"}},
    ))

    fig.update_layout(title="Waterfall", waterfallgap=0.3)

    # fig.show()

    fig.write_image(path + "_waterfall.png")


if __name__ == "__main__":
    args = parser.parse_args()

    importer = FileImporter(args.file)

    """for i in range(10):
        print(importer.har_parsed[i]['pageref'], importer.har_parsed[i]['request_hostname'])"""

    """df = pd.DataFrame(list(importer.har_parsed[keys[900]].items()), columns=["Type", "Value"])
    print(df)"""

    page_st = importer.har_parsed[0]['pageref']
    page_en = importer.har_parsed[0]['pageref']
    id_st = 0
    for i in range(len(importer.har_parsed)):
        page_en = importer.har_parsed[i]['pageref']
        if page_en != page_st or i == len(importer.har_parsed) - 1:
            print("Processing {}...".format(page_st), end='\r')
            table_entry, total_list = buildPageTable(importer.har_parsed, id_st, i)
            drawTable(table_entry, os.path.join(args.pic_dir, page_st))
            drawWaterfall(total_list, os.path.join(args.pic_dir, page_st))
            id_st = i
            page_st = page_en
