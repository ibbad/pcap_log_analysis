# Main script for running all files
import os
import time
# Setup folder paths
from analyzer import *

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
        print("Time:",  time.time())
        downloaded_fp = download_file(file_link=url, download_dir=data_file_dir)
        if downloaded_fp is None:
            return
        print("Time:",  time.time())
        # Extract the file
        extracted_fp = extract_file(file_path=downloaded_fp,
                                    extracted_dir=extracted_file_dir)
        if extracted_fp is None:
            return
        print("Time:", time.time())
        # Analyze the file
        analysis_res = analyze(filename=extracted_fp,
                               output_dir=results_file_dir,
                               trace_count=trace_count)
        os.remove(extracted_fp)
        print("Time: %s", time.time())
        print('Extracted pcap file=%s successfully removed' % extracted_fp)
        return analysis_res
    except ImportError as e:
        print('Unable to download_extract_analyze url=%s. Error=%s' % (url, e))
        return None


def scrap_all_links(url_list):
    """
    This function takes a list of URLs and scraps links of *.dump.gz all those
    webpages.
    :param url_list: (txt file) list of URLs
    :return:
    """
    try:
        print('Time:', time.time())
        with open(url_list, 'r') as f:
            lines = f.readlines()
            for url in lines:
                if not url.startswith('#'):
                    file_link = scrap_links(url.rstrip(),
                                            url_directory=url_file_dir)
                    analyze_all_links(scrapped_dumps=file_link)
    except Exception as e:
        print('Unable to scrap links from file=%s. Error=%s' % (url_list, e))
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
    except ImportError as e:
        print('Unable to analyze dumps in file=%s. Error=%s' %
              (scrapped_dumps, e))
        result.close()
        return


if __name__ == '__main__':
    scrap_all_links(url_list='url_list.txt')
    analyze_all_links(scrapped_dumps='/home/hafeez/PycharmProjects'
                                     '/log_analyzer/urls'
                                     '/samplepoint-F-2006-.csv')

