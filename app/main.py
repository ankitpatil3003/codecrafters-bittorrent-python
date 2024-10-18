import json
import sys
import hashlib
import bencodepy
import requests
import socket
import struct
import urllib.parse
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_string(bencoded_value):
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    length = int(bencoded_value[:first_colon_index].decode())
    start_index = first_colon_index + 1
    try:
        return bencoded_value[start_index:start_index + length].decode('utf-8'), bencoded_value[start_index+length:]
    except:
        return bencoded_value[start_index:start_index + length], bencoded_value[start_index+length:]
def decode_integer(bencoded_value):
    first_e_index = bencoded_value.find(b"e")
    if first_e_index == -1:
        raise ValueError("Invalid encoded value")
    decoded_string = bencoded_value[1:first_e_index].decode()
    return int(decoded_string), bencoded_value[first_e_index+1:]
def decode_list(bencoded_value):
    decoded_list = []
    i = 1
    while bencoded_value[i] != ord('e'):
        element, remaining = decode_bencode(bencoded_value[i:])
        decoded_list.append(element)
        i = len(bencoded_value) - len(remaining)
    return decoded_list, bencoded_value[i+1:]
def decode_dict(bencoded_value):
    decoded_dict = {}
    i = 1
    while bencoded_value[i] != ord('e'):
        key, remaining = decode_bencode(bencoded_value[i:])
        i = len(bencoded_value) - len(remaining)
        value, remaining = decode_bencode(bencoded_value[i:])
        i = len(bencoded_value) - len(remaining)
        decoded_dict[key] = value
    return decoded_dict, bencoded_value[i+1:]
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        return decode_string(bencoded_value)
    elif chr(bencoded_value[0]) == 'i':
        return decode_integer(bencoded_value)
    elif chr(bencoded_value[0]) == 'l':
        return decode_list(bencoded_value)    
    elif chr(bencoded_value[0]) == 'd':
        return decode_dict(bencoded_value)
    else:
        raise NotImplementedError("Only strings and numbers are supported at the moment")
def get_decoded_value(bencoded_file):
    f = open(bencoded_file, "rb")
    bencoded_value = f.read()
    f.close()
    decoded_value,_ = decode_bencode(bencoded_value)
    return decoded_value
def announce_url(decoded_value):
    return decoded_value['announce']
def get_info_dict(decoded_value):
    return decoded_value['info']
def get_sha_info(info_dict):
    bencoded_info_dict = bencodepy.encode(info_dict)
    return hashlib.sha1(bencoded_info_dict).hexdigest()
def url_encode(info_hash):
    split_string = ''.join(['%' + info_hash[i:i+2] for i in range(0,len(info_hash),2)])
    return split_string
def ping_peer_torrent(peer_ip, peer_port, info_hash, peer_id, s):
    info_hash = bytes.fromhex(info_hash)
    s.connect((peer_ip,peer_port))
    protocol_length = 19
    protocol_length_bytes = protocol_length.to_bytes(1,byteorder='big')
    s.sendall(protocol_length_bytes)
    message = 'BitTorrent protocol'
    s.sendall(message.encode('utf-8'))
    reserved_bytes = b'\x00' * 8
    s.sendall(reserved_bytes)
    s.sendall(info_hash)
    s.sendall(peer_id.encode('utf-8'))
    s.recv(1)
    s.recv(19)
    s.recv(8)
    s.recv(20)
    return s.recv(20).hex()

def ping_peer_magnet(peer_ip, peer_port, info_hash, peer_id, s):
    info_hash = bytes.fromhex(info_hash)
    s.connect((peer_ip,peer_port))
    protocol_length = 19
    protocol_length_bytes = protocol_length.to_bytes(1,byteorder='big')
    s.sendall(protocol_length_bytes)
    message = 'BitTorrent protocol'
    s.sendall(message.encode('utf-8'))
    reserved_bytes = b'\x00\x00\x00\x00\x00\x10\x00\x00'
    s.sendall(reserved_bytes)
    s.sendall(info_hash)
    s.sendall(peer_id.encode('utf-8'))
    s.recv(1)
    s.recv(19)
    s.recv(8)
    s.recv(20)
    return s.recv(20).hex()
def get_peer_address_torrent(bencoded_file):
    decoded_value = get_decoded_value(bencoded_file)
    url = announce_url(decoded_value)
    info_dict = get_info_dict(decoded_value)
    sha_info_hash = get_sha_info(info_dict)
    encoded_hash = url_encode(sha_info_hash)
    peer_id = '3a5f9c1e2d4a8e3b0f6c'
    port = 6881
    uploaded = 0
    downloaded = 0
    left = info_dict['length']
    compact = 1
    query_string = (
        f"info_hash={encoded_hash}&"
        f"peer_id={peer_id}&"
        f"port={port}&"
        f"uploaded={uploaded}&"
        f"downloaded={downloaded}&"
        f"left={left}&"
        f"compact={compact}"
    )
    complete_url = f"{url}?{query_string}"
    r = requests.get(complete_url)
    decoded_dict,_ = decode_bencode(r.content)
    peers = decoded_dict['peers']
    decimal_values = [byte for byte in peers]
    ip_address_list = []
    for i in range(0,len(decimal_values),6):
        ip_address = '.'.join(str(num) for num in decimal_values[i:i+4])
        ip_address += f":{int.from_bytes(decimal_values[i+4:i+6], byteorder='big', signed=False)}"
        ip_address_list.append(ip_address)
    return ip_address_list
def get_peer_address_magnet(url, sha_info_hash):
    encoded_hash = url_encode(sha_info_hash)
    peer_id = '3a5f9c1e2d4a8e3b0f6c'
    port = 6881
    uploaded = 0
    downloaded = 0
    left = 999
    compact = 1
    query_string = (
        f"info_hash={encoded_hash}&"
        f"peer_id={peer_id}&"
        f"port={port}&"
        f"uploaded={uploaded}&"
        f"downloaded={downloaded}&"
        f"left={left}&"
        f"compact={compact}"
    )
    complete_url = f"{url}?{query_string}"
    r = requests.get(complete_url)
    decoded_dict,_ = decode_bencode(r.content)
    peers = decoded_dict['peers']
    decimal_values = [byte for byte in peers]
    ip_address_list = []
    for i in range(0,len(decimal_values),6):
        ip_address = '.'.join(str(num) for num in decimal_values[i:i+4])
        ip_address += f":{int.from_bytes(decimal_values[i+4:i+6], byteorder='big', signed=False)}"
        ip_address_list.append(ip_address)
    return ip_address_list
def receive_large_data(s,size):
    result_data = b''
    curr_size = 0
    while curr_size < size:
        data_size_to_receive = min(4096,size-curr_size)
        temp_data = s.recv(data_size_to_receive)
        curr_size += len(temp_data)
        result_data += temp_data
    return result_data
def integer_to_byte(integer):
    return struct.pack('>I', integer)
def byte_to_integer(byte):
    return struct.unpack('>I', byte)[0]
def send_data(s,piece_offset,block_offset,data_length):
    s.sendall(b'\x00\x00\x00\x0d')
    s.sendall(b'\x06')
    s.sendall(integer_to_byte(piece_offset))
    s.sendall(integer_to_byte(block_offset))
    s.sendall(integer_to_byte(data_length))
def receive_data(s):
    payload_size = byte_to_integer(s.recv(4))
    s.recv(1)
    s.recv(4)
    s.recv(4)
    return receive_large_data(s,payload_size-9)
def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        decoded_value,_ = decode_bencode(bencoded_value)
        print(json.dumps(decoded_value, default=bytes_to_str))
    elif command == 'info':
        bencoded_file = sys.argv[2]
        decoded_value = get_decoded_value(bencoded_file)
        url = announce_url(decoded_value)
        info_dict = get_info_dict(decoded_value)
        sha_info_hash = get_sha_info(info_dict)
        pieces = info_dict['pieces']
        hex_string = pieces.hex()
        print(f'Tracker URL: {url}')
        print(f'Length: {info_dict["length"]}')
        print(f'Info Hash: {sha_info_hash}')
        print(f'Piece Length: {info_dict["piece length"]}')
        print('Piece Hashes:')
        for i in range(0,len(hex_string),40):
            print(hex_string[i:i+40]) 
    elif command == 'peers':
        bencoded_file = sys.argv[2]
        ip_address_list = get_peer_address_torrent(bencoded_file)
        for ip_address in ip_address_list:
            print(ip_address)
    elif command == 'handshake':
        bencoded_file = sys.argv[2]
        peer_details = sys.argv[3]
        peer_ip, peer_port = peer_details.split(':')
        peer_port = int(peer_port)
        decoded_value = get_decoded_value(bencoded_file)
        url = announce_url(decoded_value)
        info_dict = get_info_dict(decoded_value)
        sha_info_hash = get_sha_info(info_dict)
        peer_id = '3a5f9c1e2d4a8e3b0f6c'
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        response_peer_id = ping_peer_torrent(peer_ip,peer_port,sha_info_hash,peer_id, s)
        print(f'Peer ID: {response_peer_id}')
        
    elif command == 'download_piece':
        download_location = sys.argv[3]
        torrent_file = sys.argv[4]
        piece = int(sys.argv[5])
        decoded_value = get_decoded_value(torrent_file)
        url = announce_url(decoded_value)
        info_dict = get_info_dict(decoded_value)
        sha_info_hash = get_sha_info(info_dict)
        ip_addresses = get_peer_address_torrent(torrent_file)
        peer_ip, peer_port = ip_addresses[0].split(':')
        peer_port = int(peer_port)
        peer_id = '3a5f9c1e2d4a8e3b0f6c'
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        response_peer_id = ping_peer_torrent(peer_ip,peer_port,sha_info_hash,peer_id, s)
        
        total_length = info_dict['length']
        piece_length = info_dict['piece length']
        piece_length = min(piece_length,total_length - piece*piece_length)
        # Bitfield
        s.recv(4)
        s.recv(1)
        s.recv(4)
        # Interested
        s.sendall(b'\x00\x00\x00\x01')
        s.sendall(b'\x02')
        # Unchoke
        s.recv(4)
        s.recv(1)
        block_size = 2**14
        curr_sent_data_size = 0
        iterations = 0
        while curr_sent_data_size < piece_length:
            data_size_to_send = min(block_size,piece_length-curr_sent_data_size)
            curr_sent_data_size += data_size_to_send
            send_data(s,piece,iterations*block_size,data_size_to_send)
            iterations += 1
        result_data = b''
        for i in range(0,iterations):
            result_data += receive_data(s)
        with open(download_location, "wb") as f:  # Use "wb" for binary write mode
            f.write(result_data)  # No need to decode
    elif command=='download':
        download_location = sys.argv[3]
        torrent_file = sys.argv[4]
        decoded_value = get_decoded_value(torrent_file)
        url = announce_url(decoded_value)
        info_dict = get_info_dict(decoded_value)
        sha_info_hash = get_sha_info(info_dict)
        ip_addresses = get_peer_address_torrent(torrent_file)
        peer_ip, peer_port = ip_addresses[0].split(':')
        peer_port = int(peer_port)
        peer_id = '3a5f9c1e2d4a8e3b0f6c'
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        response_peer_id = ping_peer_torrent(peer_ip,peer_port,sha_info_hash,peer_id, s)
        
        total_length = info_dict['length']
        piece_length = info_dict['piece length']
        # Bitfield
        s.recv(4)
        s.recv(1)
        s.recv(4)
        # Interested
        s.sendall(b'\x00\x00\x00\x01')
        s.sendall(b'\x02')
        # Unchoke
        s.recv(4)
        s.recv(1)
        for i in range(0,total_length,piece_length):
            curr_piece_length = min(piece_length,total_length-i)
            block_size = 2**14
            curr_sent_data_size = 0
            iterations = 0
            while curr_sent_data_size < curr_piece_length:
                data_size_to_send = min(block_size,curr_piece_length-curr_sent_data_size)
                curr_sent_data_size += data_size_to_send
                send_data(s,i//piece_length,iterations*block_size,data_size_to_send)
                iterations += 1
            result_data = b''
            for i in range(0,iterations):
                result_data += receive_data(s)
            with open(download_location, "ab") as f:
                f.write(result_data)
    elif command == 'magnet_parse':
        magnet_link = sys.argv[2]
        info_hash_location = magnet_link.find('btih:') + 5
        info_hash = magnet_link[info_hash_location:info_hash_location+40]
        url_location = magnet_link.find('tr=') + 3
        url = magnet_link[url_location:]
        print(f'Tracker URL: {urllib.parse.unquote(url)}') 
        print(f'Info Hash: {info_hash}')  
    elif command == 'magnet_handshake':
        magnet_link = sys.argv[2]  
        info_hash_location = magnet_link.find('btih:') + 5
        info_hash = magnet_link[info_hash_location:info_hash_location+40]
        url_location = magnet_link.find('tr=') + 3
        url = magnet_link[url_location:]
        url = urllib.parse.unquote(url)
        ip_addresses = get_peer_address_magnet(url,info_hash)
        peer_ip, peer_port = ip_addresses[0].split(':')
        peer_port = int(peer_port)
        peer_id = '3a5f9c1e2d4a8e3b0f6c'
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        response_peer_id = ping_peer_magnet(peer_ip,peer_port,info_hash,peer_id, s)
        print(f'Peer ID: {response_peer_id}')
        
        # Bitfield
        s.recv(4)
        s.recv(1)
        s.recv(4)
        magnet_dict = {"m": {
            "ut_metadata": 18
        }}
        encoded_magnet_dict = bencodepy.encode(magnet_dict)
        s.sendall(integer_to_byte(len(encoded_magnet_dict) + 2))
        s.sendall(b'\x14')
        s.sendall(b'\x00')
        s.sendall(encoded_magnet_dict)
        payload_size = byte_to_integer(s.recv(4)) - 2
        s.recv(1)
        s.recv(1)
        handshake_message = s.recv(payload_size)
        handshake_message = decode_bencode(handshake_message)
        print(f'Peer Metadata Extension ID: {handshake_message[0]['m']['ut_metadata']}')
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()