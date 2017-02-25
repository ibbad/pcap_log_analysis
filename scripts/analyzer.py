"""
Analyze the log file.
"""
import os
import re
import socket
import binascii
import urllib2
from BeautifulSoup import BeautifulSoup
from progressbar import *
try:
    import dpkt
    import dpkt.udp as UDP
    import dpkt.tcp as TCP
except ImportError as e:
    print e
    print('dpkt installation required.')


def extract_mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
   :param address: (str) a MAC address in hex form (e.g.
   '\x01\x02\x03\x04\x05\x06')
   :return MAC: (str) Printable/readable MAC address
    """
    return ':'.join([binascii.hexlify(address)[i:i+2]
                     for i in range(0, len(binascii.hexlify(address)), 2)])


def extract_dscp(tos):
    """
    Extract DSCP from TOS byte in IP header
    :param tos: (int) TOS byte from IP header
    :return DSCP: (int) DSCP field
    """
    return tos >> 2


def analyze(filename=None, output_file=None, trace_count=0):
    # Check if its a dump file
    # if filename is None or filename[-5:].lower() != '.dump':
    #     print('Invalid file. Expecting .dump')
    #     return
    if output_file is None:
        output_file = os.path.basename(filename).split('.')[0]+'.csv'
    try:
        # Open file
        pcap_file = open(filename, 'rb')
        captures = dpkt.pcap.Reader(pcap_file)

        results = open(output_file, 'w')
        # Write headers
        results.write('timestamp,source_ip,source_port,destination_ip,'
                      'destination_port,dscp,tos\n')

        # Initialize progress bar
        bar = "["
        percent = 0.0
        widgets = ['Progress: ', Percentage(), ' ',
                   Bar(marker=RotatingMarker()), ' ', ETA(), ' ',
                   FileTransferSpeed()]
        pbar = ProgressBar(widgets=widgets, maxval=100).start()

        # Counters
        total_packets = 0
        ip_packets = 0
        tcp_packets = 0
        udp_packets = 0
        unprocessed_packets = 0
        # Process each packet.
        for ts, buff in captures:
            try:
                total_packets += 1
                # Get source and destination mac addresses
                eth = dpkt.ethernet.Ethernet(buff)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    # Skip if packet is not IP
                    continue

                # Get source and destination IP addresses
                ip = eth.data
                ip_packets += 1
                # Get port numbers
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    # TCP packet
                    tcp_packets += 1
                    results.write(','.join([str(i)
                                            for i in [ts,
                                                      socket.inet_ntoa(ip.src),
                                                      ip.data.sport,
                                                      socket.inet_ntoa(ip.dst),
                                                      ip.data.dport,
                                                      extract_dscp(ip.tos),
                                                      ip.tos]]) + '\n')
                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    # UDP packet
                    udp_packets += 1
                    results.write(','.join([str(i)
                                            for i in [ts,
                                                      socket.inet_ntoa(ip.src),
                                                      ip.data.sport,
                                                      socket.inet_ntoa(ip.dst),
                                                      ip.data.dport,
                                                      extract_dscp(ip.tos),
                                                      ip.tos]]) + '\n')
                else:
                    # Skip un-required packets
                    pass
                # Update progress bar
                percent += + 100.0/trace_count
                pbar.update(percent)
            except AttributeError:
                # In case UDP datagram is empty. Case in fragmented packets.
                unprocessed_packets += 1
                results.write(','.join([str(i)
                                        for i in [ts,
                                                  socket.inet_ntoa(ip.src),
                                                  0,
                                                  socket.inet_ntoa(ip.dst),
                                                  0,
                                                  extract_dscp(ip.tos),
                                                  ip.tos]]) + '\n')
            except Exception as e:
                print (e)
        pbar.finish()
        results.close
        print('file=%s analysis completed' % filename)
        return {
            "file": filename,
            "total": total_packets,
            "ip": ip_packets,
            "tcp": tcp_packets,
            "udp": udp_packets,
            "unprocessed": unprocessed_packets
        }
    except Exception as e:
        print('Unable to analyze file=%s. Error=%s' % (filename, e))
        return None


def find_dirname_until_level(dir_path=None, level=0):
    return '-'.join(dir_path.split('/')[-level-1:])


def scrap_links(webpage, url_directory=None):
    """
    This function scraps links from the web page.
    :param webpage: (str) URL for scrapping links from
    :param url_directory: (str) path to directory where the files containing
    the urls must be stored.
    :return urls: (list[str]) List of links scrapped from URL
    """
    try:
        page = urllib2.urlopen(webpage)
        soup = BeautifulSoup(page)
        count = 0
        url_directory = url_directory or os.getcwd()
        scrapped_links_fp = os.path.join(url_directory,
                                         find_dirname_until_level(webpage,
                                                                  level=2) +
                                         '.csv')
        f = open(scrapped_links_fp, 'w')
        # Write headers
        f.write('url,total,ip,tcp,udp\n')
        for link in soup.findAll('a'):
            child_link = os.path.join(webpage, link.get('href'))
            soup = BeautifulSoup(urllib2.urlopen(child_link))
            file_link = None
            for l in soup.findAll('a'):
                if '.gz' in l.get('href'):
                    file_link = l.get('href')
            if file_link is None:
                # We suppose that there is going to be only 1 link for
                # downloadable dump file.
                continue
            for a in soup.findAll('pre')[-1]:
                total = int(re.split(r'\s+',
                                     a[a.find('total'):])[1].split(' ')[0])
                ip = int(re.split(r'\s+', a[a.find('ip'):])[1].split(' ')[0])
                tcp = int(re.split(r'\s+', a[a.find('tcp'):])[1].split(' ')[0])
                udp = int(re.split(r'\s+', a[a.find('udp'):])[1].split(' ')[0])
                f.write(','.join([str(i)
                                  for i in [file_link, total, ip, tcp,
                                            udp]])+'\n')
            count += 1
            print('%s (child)-links processed.' % count)
        f.close()
        print('%s links extracted from %s' % (count, webpage))
        return scrapped_links_fp
    except Exception as e:
        print('Unable to get links from webpage=%s. Error=%s' % (webpage, e))
        f.close()
        return None


def download_file(file_link, download_dir=None):
    try:
        # if download_dir not specified.
        download_dir = download_dir or os.getcwd()
        print ('Downloading file=%s' % file_link)
        downloaded_fp = os.path.join(download_dir, os.path.basename(file_link))
        f = open(downloaded_fp, 'wb')
        f.write(urllib2.urlopen(file_link).read())
        f.close()
        print ('Successfully downloaded file=%s' % file_link)
        return downloaded_fp
    except Exception as e:
        print ('Could not download file=%s. Error=%s' % (file_link, e))
        return None


def extract_file(file_path, extracted_dir=None):
    try:
        import gzip
        extracted_dir = extracted_dir or os.getcwd()
        org_file = gzip.open(filename=file_path, mode='rb')
        extracted_fp = os.path.join(extracted_dir,
                                    os.path.basename(file_path).split('.')[0])
        extracted_file = open(extracted_fp, 'wb')
        extracted_file.write(org_file.read())
        org_file.close()
        extracted_file.close()
        print('Successfully extracted zipfile=%s to file=%s' % (file_path,
                                                                extracted_fp))
        # Delete the zip file
        os.remove(file_path)
        print ('Successfully removed zipfile=%s from disk after '
               'extraction' % file_path)
        return extracted_fp
    except ImportError:
        print('Unable to extract file. please install gzip library.')
        return None
    except Exception as e:
        print('Unable to extract file=%s. Error=%s' % (file_path, e))
        return None


if __name__ == '__main__':
    analyze(filename='/home/hafeez/PycharmProjects/log_analyzer/data/'
                     '200803172345.dump',
            output_file='/home/hafeez/PycharmProjects/log_analyzer/results/'
                        '200803172345.csv',
            trace_count=14405984)
