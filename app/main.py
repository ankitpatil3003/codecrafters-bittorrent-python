import json
import sys
import hashlib
import bencodepy
import requests
from urllib.parse import unquote
import struct
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import threading

def list_decode(bencoded_value):
    decode_list = []
    while chr(bencoded_value[0]) != "e":
        value, bencoded_value = _decode_bencode(bencoded_value)
        decode_list += [value]
    return decode_list, bencoded_value[1:]

def str_decode(bencoded_value):
    first_colon_index = bencoded_value.find(b":")
    key_length = int((bencoded_value[:first_colon_index]))
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    key = bencoded_value[first_colon_index + 1 : first_colon_index + key_length + 1]
    bencoded_value = bencoded_value[first_colon_index + key_length + 1 :]
    return key, bencoded_value

def int_decode(bencoded_value):
    int_len = bencoded_value.find(b"e")
    value = int(bencoded_value[:int_len])
    bencoded_value = bencoded_value[int_len + 1 :]
    return value, bencoded_value

def dict_decode(bencoded_value):
    # print(bencoded_value)
    decoded_dict = {}
    while chr(bencoded_value[0]) != "e":
        key, bencoded_value = _decode_bencode(bencoded_value)
        # print(key,":",bencoded_value)
        value, bencoded_value = _decode_bencode(bencoded_value)
        decoded_dict[key] = value
    # print(decoded_dict)
    return decoded_dict, bencoded_value[1:]

def _decode_bencode(bencoded_value):
    # print("decode 2",bencoded_value)
    if chr(bencoded_value[0]).isdigit():
        return str_decode(bencoded_value)
    elif chr(bencoded_value[0]) == "i":
        return int_decode(bencoded_value[1:])
    elif chr(bencoded_value[0]) == "d":
        return dict_decode(bencoded_value[1:])
    elif chr(bencoded_value[0]) == "l":
        return list_decode(bencoded_value[1:])
    elif chr(bencoded_value[0]) == "e":
        return _decode_bencode(bencoded_value[1:])
    
def decode_bencode(bencoded_value):
    return_value = []
    while len(bencoded_value) > 0:
        # print("before : ",bencoded_value,len(bencoded_value))
        value, bencoded_value = _decode_bencode(bencoded_value)
        # print("value in decode ",value)
        return_value += [value]
        # print("after : ",bencoded_value,len(bencoded_value))
    if len(return_value) == 1:
        return return_value[0]
    else:
        return return_value
    
def decode_file(file):
    with open(file, "rb") as pointer:
        data = pointer.read()
    return decode_bencode(data)
def extractInfo(data):
    info = bencodepy.encode(data[b"info"])
    info_hash = hashlib.sha1(info).hexdigest()
    url = bytes_to_str(data[b"announce"])
    length = data[b"info"][b"length"]
    piece_length = data[b"info"][b"piece length"]
    pieces = data[b"info"][b"pieces"]
    # print("pieces : ",len(pieces))
    # Each piece is of 20 bytes therefore the following
    hash_length = 20
    # pieces_sep = [pieces[num:num+hash_length] for num in range(0,len(pieces),20)]
    # #Hashes for the above
    # pieces_hash = "".join(peice.hex()+"\n" for peice in pieces_sep)
    pieces_hash = "".join(
        pieces[index : index + 20].hex() + "\n" for index in range(0, len(pieces), 20)
    )
    # print(f"Tracker URL: {url} ")
    # print(f"Length: {length}")
    # print(f"Info Hash: {info_hash}")
    # print(f"Piece Length: {piece_length}")
    # # print("Length of Pieces : ",len(pieces))
    # print(f"Piece Hashes:\n{pieces_hash}")
    return (url, length, info_hash, piece_length, pieces_hash)
def discoverPeers(data):
    url, length, info_hash, piece_length, pieces_hash = extractInfo(data)
    # url = bytes_to_str(data[b'announce'])
    # length = data[b"info"][b"length"]
    info = bencodepy.encode(data[b"info"])
    info_hash = hashlib.sha1(info).digest()
    # print(info)
    params = {
        "info_hash": info_hash,
        "peer_id": "12345678901234567890",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": length,
        "compact": 1,
    }
    response = requests.get(url, params=params)
    response_dict = decode_bencode(response.content)
    peers = response_dict.get(b"peers")
    # print(peers)
    peers_lst = {}
    for i in range(0, len(peers), 6):
        ip = ".".join(str(b) for b in peers[i : i + 4])
        port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
        peers_lst[ip] = port
        # print(f"Peer: {ip}:{port}")
    return peers_lst

def bytes_to_str(data):
    if isinstance(data, bytes):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            # If decoding fails, return a fallback representation of the bytes
            return repr(data)
    elif isinstance(data, dict):
        return {bytes_to_str(key): bytes_to_str(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [bytes_to_str(item) for item in data]
    else:
        return data
    
def tcpHandshake(data, ip, port, timeout=5):
    info = bencodepy.encode(data[b"info"])
    info_hash = hashlib.sha1(info).digest()
    """hanshake consist of 19+BitTorrent Protocol+8 zeros+info_hash+peerID"""
    handshake = (
        b"\x13"
        + b"BitTorrent protocol"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        + info_hash
        + b"01234567890123456789")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(25)
    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((ip, int(port)))
    sock.send(handshake)
    data = sock.recv(68)
    # sock.close()
    """ 48 because 1byte(19)+19bytes(BitTorrent Protocol)+8bytes(0's)+20bytes(info hash) then we have the peerID"""
    peer_id = data[48:].hex()
    # print("Peer ID:",peer_id)
    return peer_id, sock
def create_peer_message(message_id, length_prefix=1, payload=b""):
    # Calculate the length prefix as the length of the message ID + payload
    length_prefix = length_prefix
    length_prefix_bytes = length_prefix.to_bytes(4, byteorder="big")
    # Construct the message
    message = length_prefix_bytes + bytes([message_id]) + payload
    return message

def generate_send(
    piece_index,
    piece_length,
    msg_socket,
    file_length,
    total_pieces,
    block_size=16 * 1024,
):
    data_length = piece_length
    # Handle the last piece size if it's smaller than the standard piece length
    if piece_index == total_pieces - 1:
        data_length = file_length % piece_length
        # print(f"Last piece length: {data_length}")
    total_blocks = (
        data_length + block_size - 1
    ) // block_size  # Correct number of blocks for the last piece
    # print(f"Total Blocks = {total_blocks}")
    # print("data length ",data_length)
    DATA = bytearray()
    for block in range(total_blocks):
        begin = block * block_size
        length = min(block_size, data_length - begin)
        # Create the payload for the request message
        payload = (
            piece_index.to_bytes(4, byteorder="big")
            + begin.to_bytes(4, byteorder="big")
            + length.to_bytes(4, byteorder="big")
        )
        # Send the request to the peer
        msg_socket.sendall(
            create_peer_message(
                message_id=6, length_prefix=1 + 4 + 4 + 4, payload=payload
            )
        )
        # Receive the length of the incoming data
        len_byte = msg_socket.recv(4)
        Tlength = int.from_bytes(len_byte, byteorder="big")
        # Receive the actual data
        data = msg_socket.recv(Tlength)
        while len(data) < Tlength:
            data += msg_socket.recv(Tlength - len(data))
        # Append the data to the bytearray (ignore the header bytes if present)
        DATA.extend(data[9:])
    print(f"data got for peice {piece_index} of length", len(DATA))
    # if type(DATA)==bytearray and DATA:
    # print("DOne Here")
    return DATA
def download_piece(data, piece_index, msg_socket=None):
    url, length, info_hash, piece_length, pieces_hash = extractInfo(data)
    total_pieces = len(pieces_hash.splitlines())
    if total_pieces <= piece_index:
        print("piece index out of range")
        return
    # print(pieces_hash.splitlines()[piece_index])
    if msg_socket == None:
        peers_lst = discoverPeers(data)
        ip, port = list(peers_lst.keys()), list(peers_lst.values())
        peer_id, msg_socket = tcpHandshake(data, ip[0], port[0])
    recv = msg_socket.recv(1024)
    message_id = recv[4]  # --> 5 read and ignore
    # print(" bit field received message ID : ",message_id)
    msg_interested = create_peer_message(2)
    msg_socket.send(msg_interested)
    # print("interested sent")
    while message_id != 1:
        recv = msg_socket.recv(1024)
        message_id = recv[4]
        # message_id = int.from_bytes(recv[:4], byteorder='big')
        # print(recv[1],"\nreceived  : ",message_id)
    # print("received unchoke : ",message_id)
    piece_data = generate_send(
        piece_index=piece_index,
        piece_length=piece_length,
        msg_socket=msg_socket,
        file_length=length,
        total_pieces=total_pieces,
    )  # ,num_blocks=len(pieces_hash.splitlines()))
    # print(hashlib.sha1(data).hexdigest())
    if hashlib.sha1(piece_data).hexdigest() == pieces_hash.splitlines()[piece_index]:
        # print("Got the data perfectly")
        return piece_data
    else:
        return b""
    
def get_data(data, peers_lst, piece_index, max_retries=3):
    """Attempts to download a piece from the list of peers with retries."""
    # retries = 0
    # while retries < max_retries:
    # Make sure there are peers available to try
    if not peers_lst:
        print(f"No available peers to download piece {piece_index}")
        # break
        return None, peers_lst
    for ip, port in list(
        peers_lst.items()
    ):  # Make a list copy of peers to avoid modification issues
        try:
            _, msg_socket = tcpHandshake(data, ip, port)
            piece_data = download_piece(data, piece_index, msg_socket)
            if piece_data:
                return piece_data, peers_lst  # Successfully downloaded piece
        except Exception as e:
            print(f"Exception occurred with peer {ip}:{port}: {e}")
    return None, peers_lst  # Return None if all retries fail
def download_torrent(data, dest_file):
    file_data = {}
    url, length, info_hash, piece_length, pieces_hash = extractInfo(data)
    total_pieces = len(pieces_hash.splitlines())
    with open(dest_file, "ab") as temp:
        peers_lst = discoverPeers(data)
        lst_pieces = list(range(total_pieces))
        while lst_pieces:
            if not peers_lst:
                print("No peers left to attempt downloading pieces.")
                break  # Exit if there are no peers available
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_data = {
                    executor.submit(get_data, data, peers_lst, piece_index): piece_index
                    for piece_index in lst_pieces
                }
                for future in as_completed(future_data):
                    piece_index = future_data[future]
                    try:
                        piece_data, peers_lst = future.result()
                        if piece_data:
                            file_data[piece_index] = piece_data
                            lst_pieces.remove(
                                piece_index
                            )  # Only remove the piece if it was successfully downloaded
                    except Exception as e:
                        print(
                            f"Exception occurred while processing piece {piece_index}: {e}"
                        )
        # Write the downloaded pieces to the file in order
        if len(file_data) == total_pieces:
            for i in range(total_pieces):
                temp.write(file_data[i])
            print("Download completed successfully.")
        else:
            print(f"Download incomplete. {len(lst_pieces)} pieces failed to download.")
def extract_magnet_info(magnet_url):
    string_url = magnet_url.split("&")
    # print(f"String Url {string_url}")
    # parsed_url = urlparse(magnet_url)
    # params = parse_qs(parsed_url.query)
    info_hash = string_url[0].split(":")[-1]
    display_name = string_url[1].split("=")[-1]
    tracker = unquote(string_url[2].split("=")[-1])
    return {"info_hash": info_hash, "display_name": display_name, "tracker": tracker}

def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        print(json.dumps(bytes_to_str(decode_bencode(bencoded_value))))
    elif command == "info":
        file = sys.argv[2]
        url, length, info_hash, piece_length, pieces_hash = extractInfo(
            decode_file(file)
        )
        print(f"Tracker URL: {url} ")
        print(f"Length: {length}")
        print(f"Info Hash: {info_hash}")
        print(f"Piece Length: {piece_length}")
        print(f"Piece Hashes:\n{pieces_hash}")
    elif command == "peers":
        file = sys.argv[2]
        peers_lst = discoverPeers(decode_file(file))
        for ip, port in peers_lst.items():
            print(f"Peer: {ip}:{port}")
    elif command == "handshake":
        file = sys.argv[2]
        ip, port = sys.argv[3].split(":")
        peer_id, _ = tcpHandshake(decode_file(file), ip, port)
        print("Peer ID:", peer_id)
    elif command == "download_piece" and len(sys.argv) >= 5:
        # print("Download piece impl")
        # -o /tmp/test-piece-0 sample.torrent 0
        tag = sys.argv[2]
        dest_file = sys.argv[3]
        file = sys.argv[4]
        piece_index = int(sys.argv[5])
        if tag == "-o":
            data = download_piece(decode_file(file), piece_index)
            if data != None:
                with open(dest_file, "wb") as dest:
                    dest.write(data)
                    dest.close()
    elif command == "download" and len(sys.argv) >= 4:
        tag = sys.argv[2]
        dest_file = sys.argv[3]
        file = sys.argv[4]
        if tag == "-o":
            data = download_torrent(decode_file(file), dest_file)
    elif command == "magnet_parse":
        magnet_url = sys.argv[2]
        # print(magnet_url)
        magnet_extract = extract_magnet_info(magnet_url)
        print(
            f"Tracker URL: {magnet_extract['tracker']}\nInfo Hash: {magnet_extract['info_hash']}"
        )
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()