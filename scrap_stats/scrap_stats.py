import sys
import gc
import os
import re
from urllib.request import urlopen
import threading
from bs4 import BeautifulSoup


# Setup folders
print('Creating directories for results')

url_file_dir = os.path.join(os.getcwd(), 'urls')
if not os.path.exists(url_file_dir):
    os.makedirs(url_file_dir)

results_file_dir = os.path.join(os.getcwd(), 'results')
if not os.path.exists(results_file_dir):
    os.makedirs(results_file_dir)


class MyThread(threading.Thread):
    def __init__(self, target, *args, **kwargs):
        self._target = target
        self._args = args
        self._kwargs = kwargs
        threading.Thread.__init__(self)

    def run(self):
        self._target(*self._args, **self._kwargs)


def find_dirname_from_level(dir_path=None, level=0):
    return '-'.join(dir_path.split('/')[-level - 1:])


# Get links from page
def get_stats_from_page(webpage, results_file_dir=None):
    """
    Reads the webpage and goes to each child link, extracts the stats from
    page and writes the to a csv file in results_dir
    :param webpage: url for webpage containing child page's links
    :param results_dir: directory to store results.
    :return:
    """
    try:
        print('Processing url={0}'.format(webpage))
        soup = BeautifulSoup(urlopen(webpage), 'lxml')
        count = 0
        if results_file_dir:
            results_dir=os.path.join(results_file_dir,
                                     find_dirname_from_level(webpage, level=2))
            if not os.path.exists(results_dir):
                os.makedirs(results_dir)
        else:
            results_dir=os.path.join(os.getcwd(),
                                     find_dirname_from_level(webpage, level=2))
            if not os.path.exists(results_dir):
                os.makedirs(results_dir)
        print('directory created at %s' % results_dir)

        # results_file = os.path.join(results_dir, find_dirname_from_level(
        #     webpage, level=2) + '.csv')
        # fr = open(results_file, 'w')
        for link in soup.findAll('a'):
            try:
                child_link = os.path.join(webpage, link.get('href'))
                soup = BeautifulSoup(urlopen(child_link), 'lxml')
                count += 1
                # Open file to write the results
                results_file = os.path.join(
                    results_dir,
                    os.path.basename(child_link).replace('.html', '.csv'))
                fr = open(results_file, 'w')
                for a in soup.findAll('pre')[-1]:
                    b = str(a.encode('ascii').decode('ascii'))
                    ip6_flag = False
                    for line in b.split('\n'):
                        if not line.startswith('-'):
                            values = [val.replace(' ', '')
                                      for val in re.split(r'\s+', line.lstrip())
                                      if not val.startswith(
                                    '(') and not val.endswith('%)')]
                            # put identifier for ip6 packets
                            if not ip6_flag:
                                if values[0] == 'tcp6':
                                    ip6_flag = True
                            else:
                                values[0] += '-6'
                            if len(values) > 1:
                                fr.write(','.join(values))
                            fr.write('\n')
                fr.close()
                gc.collect()
            except Exception as el2:
                print(el2)
                pass
        print("{0} links extracted from {1}".format(count, webpage))
    except Exception as el1:
        print(el1)

# Get trace information from page
def get_trace_info_from_page(webpage, results_file=None):
    """
    Reads the webpage and goes to each child link, extracts the stats from
    page and writes the to a csv file in results_dir
    :param webpage: url for webpage containing child page's links
    :param results_file: file to store stats
    :return:
    """
    try:
        print('Processing url={0}'.format(webpage))
        soup = BeautifulSoup(urlopen(webpage), 'lxml')
        count = 0
        for link in soup.findAll('a'):
            try:
                child_link = os.path.join(webpage, link.get('href'))
                soup = BeautifulSoup(urlopen(child_link), 'lxml')
                count += 1
                trace_values = []
                for strong_tag in soup.find_all('b'):
                    # print(strong_tag.text, strong_tag.next_sibling)
                    val = strong_tag.next_sibling
                    if val is not None:
                        try:
                            val = val.strip()
                        except:
                            # Skip <br/>
                            continue
                        extra_val = None
                        if 'CapLen' in val:
                            extra_val = val[val.find('CapLen'):].split(':')[1].strip().split(' ')[0]
                            val = val.split(' ')[0]
                        if 'stddev' in val:
                            extra_val = val[val.find('stddev'):].split(':')[1].strip().split(' ')[0]
                            # remove M from stddev
                            extra_val = extra_val[:-1]
                            val = val.split(' ')[0]
                        # print(strong_tag, type(strong_tag))
                        # if 'StartTime' in strong_tag or 'EndTime' in strong_tag:
                        #     print('a')
                        #     val = _convert_date_to_seconds(val)
                        if '(' in val:
                            val = val[:val.find('(')].strip()
                        if val.endswith('seconds'):
                            val = val.split(' ')[0]
                        if val.endswith('Mbps'):
                            val = val[:-4]
                        if val.endswith('MB'):
                            val = val[:-2]
                        if 'stdev' in val:
                            val = val[:val.find('stdev')]
                        trace_values.append(val.strip())
                        if extra_val:
                            trace_values.append(extra_val)
                fr = open(results_file, 'a+')
                fr.write(','.join(trace_values)+'\n')
                fr.close()
                gc.collect()
            except ValueError as el2:
                print(el2)
                pass
        print("{0} links extracted from {1}".format(count, webpage))
    except ValueError as el1:
        print(el1)


def _convert_date_to_seconds(input_date):
    """
    Convert the date from 'Week-Day Month Month-Date HH:MM:SS YYYY' to seconds since epoch
    :param input_date: date object in given format
    :return: unixtimestamp in seconds since epoch (float object)
    """
    import time
    from datetime import datetime
    o_date = input_date[:11] + input_date[-4:]
    o_time = input_date[11:-4]
    r_date = o_date + ' ' + o_time

    ds = time.strptime(r_date, "%a %b %d %Y %H:%M:%S ")
    dt = datetime.fromtimestamp(time.mktime(ds))
    epoch = datetime.utcfromtimestamp(0)
    return int((dt - epoch).total_seconds())


# Get all URLs
def get_all_stats(url_list, results_file_dir=None):
    """
    This function reads url_list and for each url, it finds all child links
    to stats and writes them to a files in url_file_dir directory
    :param url_list: text file containing list of URLs for parents pages of
    traces.
    :param results_file_dir: directory for storing text files containing links.
    """
    try:
        results_file = os.path.join(os.getcwd(), 'trace_results-2.csv')
        f = open(results_file,  'w')
        # write headers
        f.write('dumpfile,filesize,id,starttime,endtime,total_time(s),total_cap_size,cap_length,'
                '# of packets,Avg_rate,avg_rate_stddev,# of flows,# of ipv4 packets,# of ipv6 packets,\n')
        f.close()
        count = 0
        with open(url_list, 'r') as f:
            lines = f.readlines()
            for l in lines:
                if not l.startswith('#'):           # shows comments
                    # get_stats_from_page(webpage=l.rstrip(),
                    #                     results_file_dir=results_file_dir)
                    get_trace_info_from_page(webpage=l.rstrip(),
                                             results_file=results_file)

                    sys.exit()
                    count += 1
            print('Links retrieved successfully from {0} '
                  'webpages'.format(count))
    except ValueError as el1:
        print('Unable to get trace from url_list file. Error={0}'.format(el1))

if __name__ == '__main__':
    # convert_pre_to_csv(
    #     url='http://mawi.wide.ad.jp/mawi/samplepoint-F/2006/200610031400.html',
    #     fp='200610031400-1.txt'
    # )
    get_all_stats(url_list='url_list.txt', results_file_dir=results_file_dir)

