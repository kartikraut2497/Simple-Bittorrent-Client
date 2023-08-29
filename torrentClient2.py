import logging
import socket
import torrent_parser as tp
import hashlib
import struct
import random
import ipaddress
import errno
from bcoding import bencode, bdecode
from urllib.parse import urlparse
from struct import pack, unpack
import time

def get_tracker_urls(torrent_data):
    if 'announce-list' in torrent_data:
        return torrent_data['announce-list']
    else:
        return [[torrent_data['announce']]]


def get_message(conn_id, action, trans_id, info_hash, peer_id):
    conn_id = pack('>Q', conn_id)
    downloaded = pack('>Q', 0)
    left = pack('>Q', 0)
    uploaded = pack('>Q', 0)

    event = pack('>I', 0)
    ip = pack('>I', 0)
    key = pack('>I', 0)
    num_want = pack('>i', -1)
    port = pack('>h', 8000)

    msg = (conn_id + action + trans_id + info_hash + peer_id + downloaded +
           left + uploaded + event + ip + key + num_want + port)

    return msg

def read_from_socket(sock):
    data = b''

    while True:
        try:
            buff = sock.recv(4096)
            if len(buff) <= 0:
                break

            data += buff
        except socket.error as e:
            err = e.args[0]
            if err != errno.EAGAIN or err != errno.EWOULDBLOCK:
                logging.debug("Wrong errno {}".format(err))
            break
        except Exception:
            logging.exception("Recv failed")
            break

    return data


def parse_sock_addr(raw_bytes):
    socks_addr = []

    # socket address : <IP(4 bytes)><Port(2 bytes)>
    # len(socket addr) == 6 bytes
    for i in range(int(len(raw_bytes) / 6)):
        start = i * 6
        end = start + 6
        ip = socket.inet_ntoa(raw_bytes[start:(end - 2)])
        raw_port = raw_bytes[(end - 2):end]
        port = raw_port[1] + raw_port[0] * 256

        socks_addr.append((ip, port))

    return socks_addr


def get_response_from_socket(sock):
    try:
        response = read_from_socket(sock)
    except socket.timeout as e:
        logging.debug("Timeout : %s" % e)
        return
    except Exception as e:
        logging.exception("Unexpected error when sending message : %s" % e.__str__())
        return

    return response

def get_peer_list_from_udp_tracker(tracker_url, info_hash):
    parsed = urlparse(tracker_url)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(4)

    ip, port = socket.gethostbyname(parsed.hostname), parsed.port

    conn_id = pack('>Q', 0x41727101980)
    action = pack('>I', 0)
    trans_id = pack('>I', random.randint(0, 100000))

    tracker_message = conn_id + action + trans_id
    size = len(tracker_message)

    # print('IP : ', ip, ', Port : ', port)
    conn = (ip, port)
    sock.sendto(tracker_message, conn)

    response = get_response_from_socket(sock)

    if len(response) < size:
        logging.debug("Did not get full message.")

    if action != response[0:4] or trans_id != response[4:8]:
        logging.debug("Transaction or Action ID did not match")

    # print('Response : ', response)

    conn_id, = unpack('>Q', response[8:])
    peer_id = generate_peer_id()

    trans_id = pack('>I', random.randint(0, 100000))
    action = pack('>I', 1)

    message = get_message(conn_id, action, trans_id, info_hash, peer_id)

    sock.sendto(message, conn)

    response = get_response_from_socket(sock)

    list_sock_addr = parse_sock_addr(response[20:])

    return list_sock_addr


def generate_peer_id():
    seed = str(time.time())
    return hashlib.sha1(seed.encode('utf-8')).digest()

if __name__ == "__main__":

    torrent_file_path = 'Mission-Impossible-Fallout.torrent'
    with open(torrent_file_path, 'rb') as file:
        contents = bdecode(file)

    torrent_data = contents
    raw_info_hash = bencode(torrent_data['info'])
    info_hash = hashlib.sha1(raw_info_hash).digest()
    # print('Info hash : ', info_hash)
    tracker_urls = get_tracker_urls(torrent_data)

    peers_list = []
    for tracker in tracker_urls:
        try:
            print(tracker[0])
            curr_peers = get_peer_list_from_udp_tracker(tracker[0], info_hash)
            if len(curr_peers) > 0:
                peers_list.append(curr_peers)
        except Exception as e:
            logging.error("UDP scraping failed: %s " % e.__str__())

    print(peers_list)
