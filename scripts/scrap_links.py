# Main script for running all files
import os
# Setup folder paths
from analyzer import *

extracted_file_dir = os.path.join(os.path.dirname(os.getcwd()), 'extracted')
url_file_dir = os.path.join(os.path.dirname(os.getcwd()), 'urls')
data_file_dir = os.path.join(os.path.dirname(os.getcwd()), 'data')
results_file_dir = os.path.join(os.path.dirname(os.getcwd()), 'results')


def download_extract_analyze(url, trace_count=0):
    # Download the file
    try:
        downloaded_fp = download_file(file_link=url, download_dir=data_file_dir)
        if downloaded_fp is None:
            return
        # Extract the file
        extracted_fp = extract_file(file_path=downloaded_fp,
                                    extracted_dir=extracted_file_dir)
        if extracted_fp is None:
            return
        # Analyze the file
        analysis_res = analyze(filename=extracted_fp, trace_count=trace_count)
        os.remove(extracted_fp)
        print('Extracted pcap file=%s successfully removed' % extracted_fp)
        return analysis_res
    except Exception as e:
        print('Unable to download_extract_analyze url=%s. Error=%s' % (url, e))
        return None

if __name__ == '__main__':
    print download_extract_analyze(
        url='http://mawi.nezu.wide.ad.jp/mawi/samplepoint-B/2000/200012281400.dump.gz', trace_count=124936)

