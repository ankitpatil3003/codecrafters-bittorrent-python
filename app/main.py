import json
import sys
import hashlib
import requests
import socket
import struct
import math
# Examples:
#
# - decode_bencode(b"5:hello") -> "hello"
# - decode_bencode(b"i52e") -> 52
# - decode_bencode(b"l5:helloi52ee") -> ["hello", 52]
# - decode_bencode(b"d3:foo3:bar5:helloi52ee") -> {"foo":"bar","hello":52}
def decode_bencode(bencoded_value):
    first_char = chr(bencoded_value[0])
    match identify_bencode_type(first_char):
        case "string":
            return decode_bencode_string(bencoded_value)
        case "int":
            return decode_bencode_int(bencoded_value)
        case "list":
            return decode_bencode_list(bencoded_value)
        case "dict":
            return decode_bencode_dict(bencoded_value)
        case _:
            raise ValueError("Invalid encoded type")
def identify_bencode_type(first_char):
    if first_char.isdigit():
        return "string"
    elif first_char == "i":
        return "int"
    elif first_char == "l":
        return "list"
    elif first_char == "d":
        return "dict"
    else:
        raise ValueError("Invalid encoded value")
def decode_bencode_string(bencoded_value):
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    length = first_colon_index + int(bencoded_value[:first_colon_index]) + 1
    return bencoded_value[first_colon_index + 1 : length], length
def decode_bencode_int(bencoded_value):
    end_token_index = bencoded_value.find(b"e")
    length = end_token_index + 1
    return int(bencoded_value[1:end_token_index]), length
def decode_bencode_list(bencoded_value):
    index, result = 1, []
    while bencoded_value[index] != ord("e"):
        decoded_value, length = decode_bencode(bencoded_value[index:])
        index += length
        result.append(decoded_value)
    return result, index + 1
def decode_bencode_dict(bencoded_value):
    index, result = 1, {}
    while bencoded_value[index] != ord("e"):
        key, length = decode_bencode_string(bencoded_value[index:])
        index += length
        value, length = decode_bencode(bencoded_value[index:])
        index += length
        result[key.decode()] = value
    return result, index + 1
def extract_info_hash(bencoded_value):
    _, bencoded_value_from_info = bencoded_value.split(b"info")
    _, dict_length = decode_bencode_dict(bencoded_value_from_info)
    return bencoded_value_from_info[:dict_length]
def extract_pieces_hashes(pieces_hashes):
    index, result = 0, []
    while index < len(pieces_hashes):
        result.append(pieces_hashes[index : index + 20].hex())
        index += 20
    return result
def get_peers(decoded_data, info_hash):
    params = {
        "info_hash": info_hash,
        "peer_id": "PC0001-7694471987235",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": decoded_data["info"]["length"],
        "compact": 1,
    }
    response = requests.get(decoded_data["announce"].decode(), params=params)
    return decode_peers(decode_bencode(response.content)[0]["peers"])
def decode_peers(peers):
    index, result = 0, []
    while index < len(peers):
        ip = ".".join([str(peers[index + offset]) for offset in range(4)])
        # The port is encoded as a 16-bit big-endian integer.
        # So, we need to multiply the first byte by 256 and add the second byte.
        port = peers[index + 4] * 256 + peers[index + 5]
        result.append(f"{ip}:{port}")
        index += 6
    return result
def get_peer_id(ip, port, info_hash):
    protocol_name_length = struct.pack(">B", 19)
    protocol_name = b"BitTorrent protocol"
    reserved_bytes = b"\x00" * 8
    peer_id = b"PC0001-7694471987235"
    payload = (
        protocol_name_length + protocol_name + reserved_bytes + info_hash + peer_id
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ip, port))
        sock.sendall(payload)
        response = sock.recv(1024)
        return response[48:].hex()
    finally:
        sock.close()
def download_piece(decoded_data, info_hash, piece_index, output_file):
    peers = get_peers(decoded_data, info_hash)
    peer_ip, peer_port = peers[0].split(":")
    peer_port = int(peer_port)
    get_peer_id(peer_ip, peer_port, info_hash)
    protocol_name_length = struct.pack(">B", 19)
    protocol_name = b"BitTorrent protocol"
    reserved_bytes = b"\x00" * 8
    peer_id = b"PC0001-7694471987235"
    payload = (
        protocol_name_length + protocol_name + reserved_bytes + info_hash + peer_id
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((peer_ip, peer_port))
        sock.sendall(payload)
        response = sock.recv(68)
        message = receive_message(sock)
        while int(message[4]) != 5:
            message = receive_message(sock)
        interested_payload = struct.pack(">IB", 1, 2)
        sock.sendall(interested_payload)
        message = receive_message(sock)
        while int(message[4]) != 1:
            message = receive_message(sock)
        file_length = decoded_data["info"]["length"]
        total_number_of_pieces = len(
            extract_pieces_hashes(decoded_data["info"]["pieces"])
        )
        default_piece_length = decoded_data["info"]["piece length"]
        if piece_index == total_number_of_pieces - 1:
            piece_length = file_length - (default_piece_length * piece_index)
        else:
            piece_length = default_piece_length
        number_of_blocks = math.ceil(piece_length / (16 * 1024))
        data = bytearray()
        for block_index in range(number_of_blocks):
            begin = 2**14 * block_index
            print(f"begin: {begin}")
            block_length = min(piece_length - begin, 2**14)
            print(
                f"Requesting block {block_index + 1} of {number_of_blocks} with length {block_length}"
            )
            request_payload = struct.pack(
                ">IBIII", 13, 6, piece_index, begin, block_length
            )
            print("Requesting block, with payload:")
            print(request_payload)
            print(struct.unpack(">IBIII", request_payload))
            print(int.from_bytes(request_payload[:4]))
            print(int.from_bytes(request_payload[4:5]))
            print(int.from_bytes(request_payload[5:9]))
            print(int.from_bytes(request_payload[17:21]))
            sock.sendall(request_payload)
            message = receive_message(sock)
            data.extend(message[13:])
        with open(output_file, "wb") as f:
            f.write(data)
    finally:
        sock.close()
    return True
def receive_message(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    # If we didn't receive the full message for some reason, keep gobbling.
    while len(message) < int.from_bytes(length):
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message
def main():
    command = sys.argv[1]
    match command:
        case "decode":
            bencoded_value = sys.argv[2].encode()
            # json.dumps() can't handle bytes, but bencoded "strings" need to be
            # bytestrings since they might contain non utf-8 characters.
            #
            # Here we convert them to strings for printing to the console.
            def bytes_to_str(data):
                if isinstance(data, bytes):
                    return data.decode()
                raise TypeError(f"Type not serializable: {type(data)}")
            print(json.dumps(decode_bencode(bencoded_value)[0], default=bytes_to_str))
        case "info":
            torrent_file = sys.argv[2]
            with open(torrent_file, "rb") as f:
                torrent_data = f.read()
            decoded_data = decode_bencode(torrent_data)[0]
            print(f"Tracker URL: {decoded_data['announce'].decode()}")
            print(f"Length: {decoded_data['info']['length']}")
            print(
                f"Info Hash: {hashlib.sha1(extract_info_hash(torrent_data)).hexdigest()}"
            )
            print(f"Piece Length: {decoded_data['info']['piece length']}")
            print(
                f"Piece Hashes: {extract_pieces_hashes(decoded_data['info']['pieces'])}"
            )
        case "peers":
            torrent_file = sys.argv[2]
            with open(torrent_file, "rb") as f:
                torrent_data = f.read()
            decoded_data = decode_bencode(torrent_data)[0]
            for peer in get_peers(
                decoded_data, hashlib.sha1(extract_info_hash(torrent_data)).digest()
            ):
                print(peer)
        case "handshake":
            peer_ip, peer_port = sys.argv[3].split(":")
            torrent_file = sys.argv[2]
            with open(torrent_file, "rb") as f:
                torrent_data = f.read()
            decoded_data = decode_bencode(torrent_data)[0]
            print(
                f"Peer ID: {get_peer_id(peer_ip, int(peer_port), hashlib.sha1(extract_info_hash(torrent_data)).digest())}"
            )
        case "download_piece":
            output_file = sys.argv[3]
            piece_index = int(sys.argv[5])
            torrent_file = sys.argv[4]
            with open(torrent_file, "rb") as f:
                torrent_data = f.read()
            decoded_data = decode_bencode(torrent_data)[0]
            if download_piece(
                decoded_data,
                hashlib.sha1(extract_info_hash(torrent_data)).digest(),
                piece_index,
                output_file,
            ):
                print(f"Piece {piece_index} downloaded to {output_file}.")
            else:
                raise RuntimeError("Failed to download piece")
        case _:
            raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()