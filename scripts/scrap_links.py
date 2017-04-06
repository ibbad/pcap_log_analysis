# Main script for running all files
import os
import time
import logging
import threading
from analyzer import *
from multiprocessing import Process
# Setup folder paths

logging.info('Creating directories for data and results...')
extracted_file_dir = os.path.join(os.path.dirname(os.getcwd()), 'extracted')
if not os.path.exists(extracted_file_dir):
    os.makedirs(extracted_file_dir)
url_file_dir = os.path.join(os.path.dirname(os.getcwd()), 'urls')
if not os.path.exists(url_file_dir):
    os.makedirs(url_file_dir)
data_file_dir = os.path.join(os.path.dirname(os.getcwd()), 'data')
if not os.path.exists(data_file_dir):
    os.makedirs(data_file_dir)
results_file_dir = os.path.join(os.path.dirname(os.getcwd()), 'results')
if not os.path.exists(results_file_dir):
    os.makedirs(results_file_dir)


def download_extract_analyze(url, trace_count=0):
    # Download the file
    try:
        logging.info("Processing link=%s",  url)
        t0 = time.time()
        t1 = time.time()
        downloaded_fp = download_file(file_link=url, download_dir=data_file_dir)
        if downloaded_fp is None:
            return
        logging.info("Downloaded file=%s in seconds=%s" %
                     (downloaded_fp, str(time.time()-t1)))
        logging.info("Extracting file=%s" % downloaded_fp)
        # Extract the file
        t1 = time.time()
        extracted_fp = extract_file(file_path=downloaded_fp,
                                    extracted_dir=extracted_file_dir)
        if extracted_fp is None:
            return
        logging.info("Extracted file=%s in seconds=%s" %
                     (downloaded_fp, str(time.time()-t1)))
        logging.info("Analyzing file=%s" % extracted_fp)
        t1 = time.time()
        # Analyze the file
        analysis_res = analyze(filename=extracted_fp,
                               output_dir=results_file_dir,
                               trace_count=trace_count)
        os.remove(extracted_fp)
        logging.info("Analyzed file=%s in seconds=%s\n" %
                     (extracted_fp, str(time.time()-t1)))
        logging.debug('Extracted pcap file=%s successfully removed' %
                      extracted_fp)
        logging.info("Finished processing link=%s in seconds=%s" %
                     (url, str(time.time()-t0)))
        return analysis_res
    except ImportError as el1:
        logging.error('Unable to download_extract_analyze url=%s. Error=%s' %
                      (url, el1))
        return None


def scrap_all_links(url_list):
    """
    This function takes a list of URLs and scraps links of *.dump.gz all those
    webpages.
    :param url_list: (txt file) list of URLs
    :return:
    """
    try:
        count = 0
        with open(url_list, 'r') as f:
            lines = f.readlines()
            for url in lines:
                if not url.startswith('#'):
                    file_link = scrap_links(webpage=url.rstrip(),
                                            url_directory=url_file_dir)
                    count += 1
            print ('Links to dump files extracted from %s webpages.' % count)
    except Exception as el1:
        print('Unable to scrap links from file=%s. Error=%s' % (url_list, el1))
        return


def analyze_all_links(scrapped_dumps):
    """
    This function takes the list of scrapped links from the file, downloads
    all links, downloads, extracts, analyzes them and write the results to a
    csv file.
    :param scrapped_dumps: csv file containing the data scrapped from web pages.
    :return:
    """
    try:
        results = open(os.path.join(results_file_dir,
                                    'result-'+os.path.basename(scrapped_dumps)),
                       'w')
        # Write headers
        results.write('filename,total_packets,ip_packets,non_ip4_packets,'
                      'tcp_packets,udp_packets,unprocessed')

        with open(scrapped_dumps, 'r') as f:
            for line in f:
                # skip header
                if not line.startswith('http'):
                    continue
                (url, total, ip, tcp, udp) = line.split(',')
                result = download_extract_analyze(url,
                                                  trace_count=total)
                results.write(','.join(str(element)
                                       for element in [result['file'],
                                                       result['total'],
                                                       result['ip'],
                                                       result['non_ip4'],
                                                       result['tcp'],
                                                       result['udp'],
                                                       result['unprocessed']])
                              + '\n')
                break
        results.close()
    except ImportError as el1:
        print('Unable to analyze dumps in file=%s. Error=%s' %
              (scrapped_dumps, el1))
        if result is not None:
            result.close()
        return


def analyze_all_files(url_directory=None, n_threads=6):
    """
    This function processes all files in the urls directory, downloads each
    file and processes it.
    :param url_directory: path to directory containing files containing urls
    of trace dumps.
    :param n_threads: number of threads.
    :return:
    """
    # read all files
    for fname in os.listdir(url_directory):
        links = []
        f = open(os.path.join(url_directory, fname), 'r')
        f.readline()     # Skip headers
        for l in f.readlines():
            links.append((l.split(',')[0], l.split(',')[1]))
        logging.info('%s links extracted from file=%s' % (len(links), fname))
        # Start n threads simultaneously to perform download, extract, analyze
        for i in range(0, len(links), n_threads):
            try:
                threads = []
                for j in range(n_threads):
                    if i+j < len(links):
                        threads.append(MyThread(target=download_extract_analyze,
                                                url=links[i+j][0],
                                                trace_count=int(links[i+j][1])))
                for t in threads:
                    t.start()
                # Wait for the threads to complete
                for t in threads:
                    t.join()
            except ImportError as el3:
                logging.error('Error=%s during processing url=%s' %
                              (el3, links[i][0]))
                pass


def analyze_all_files_processes(url_directory=None, n_processes=6):
    """
    This function processes all files in the urls directory, downloads each
    file and processes it.
    :param url_directory: path to directory containing files containing urls
    of trace dumps.
    :param n_threads: number of threads.
    :return:
    """
    # read all files
    for fname in os.listdir(url_directory):
        links = []
        f = open(os.path.join(url_directory, fname), 'r')
        f.readline()     # Skip headers
        for l in f.readlines():
            links.append((l.split(',')[0], l.split(',')[1]))
        logging.info('%s links extracted from file=%s' % (len(links), fname))
        # Start n threads simultaneously to perform download, extract, analyze
        for i in range(0, len(links), n_processes):
            try:
                processes = []
                for j in range(n_processes):
                    if i+j < len(links):
                        processes.append(Process(
                            target=download_extract_analyze,
                            args=(links[i+j][0], int(links[i+j][1]))))
                for p in processes:
                    p.start()
                # Wait for the threads to complete
                for p in processes:
                    p.join()
            except ImportError as el3:
                logging.error('Error=%s during processing url=%s' %
                              (el3, links[i][0]))
                pass


class MyThread(threading.Thread):
    def __init__(self, target, *args, **kwargs):
        self._target = target
        self._args = args
        self._kwargs = kwargs
        threading.Thread.__init__(self)

    def run(self):
        self._target(*self._args, **self._kwargs)


if __name__ == '__main__':
    # Scrap all links from child pages of urls listed in url_list.txt file.
    # scrap_all_links(url_list='url_list.txt')

    # walk through the directory containing files with links to dump files.
    # analyze_all_links(scrapped_dumps='/home/hafeez/PycharmProjects'
    #                                  '/log_analyzer/urls'
    #                                  '/samplepoint-F-2006-.csv')
    analyze_all_files_processes(url_directory=url_file_dir, n_processes=4)
    # download_file(file_link='http://mawi.nezu.wide.ad.jp/mawi/ditl/ditl2012/201203302300.dump.gz')
    pass

