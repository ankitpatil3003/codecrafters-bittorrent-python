import json
import sys
import socket
import hashlib
import requests
import struct
import os
def decode_string(bencoded_value):
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Not a string")
    length_string = int(bencoded_value[:first_colon_index])
    decoded_string = bencoded_value[
        first_colon_index + 1 : first_colon_index + 1 + length_string
    ]
    bencoded_remainder = bencoded_value[first_colon_index + 1 + length_string :]
    return decoded_string, bencoded_remainder
def decode_int(bencoded_value):
    if chr(bencoded_value[0]) != "i":
        raise ValueError("Not an integer")
    end_int = bencoded_value.find(b"e")
    if end_int == -1:
        raise ValueError("Not an integer")
    decoded_int = int(bencoded_value[1:end_int])
    bencoded_remainder = bencoded_value[end_int + 1 :]
    return decoded_int, bencoded_remainder
def decode_list(bencoded_value):
    if chr(bencoded_value[0]) != "l":
        raise ValueError("Not a list")
    bencoded_remainder = bencoded_value[1:]
    decoded_list = []
    while chr(bencoded_remainder[0]) != "e":
        decoded_value, bencoded_remainder = decode_bencode(bencoded_remainder)
        decoded_list.append(decoded_value)
    return decoded_list, bencoded_remainder[1:]
def decode_dict(bencoded_value):
    if chr(bencoded_value[0]) != "d":
        raise ValueError("Not a dict")
    bencoded_remainder = bencoded_value[1:]
    decoded_dict = {}
    while chr(bencoded_remainder[0]) != "e":
        decoded_key, bencoded_remainder = decode_string(bencoded_remainder)
        decoded_value, bencoded_remainder = decode_bencode(bencoded_remainder)
        decoded_dict[decoded_key.decode()] = decoded_value
    return decoded_dict, bencoded_remainder[1:]
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        return decode_string(bencoded_value)
    elif chr(bencoded_value[0]) == "i":
        return decode_int(bencoded_value)
    elif chr(bencoded_value[0]) == "l":
        return decode_list(bencoded_value)
    elif chr(bencoded_value[0]) == "d":
        return decode_dict(bencoded_value)
    else:
        raise NotImplementedError(
            f"We only support strings, integers, lists, and dicts."
        )
def bencode_string(unencoded_value):
    length = len(unencoded_value)
    return (str(length) + ":" + unencoded_value).encode()
def bencode_bytes(unencoded_value):
    length = len(unencoded_value)
    return str(length).encode() + b":" + unencoded_value
def bencode_int(unencoded_value):
    return ("i" + str(unencoded_value) + "e").encode()
def bencode_list(unencoded_value):
    result = b"l"
    for i in unencoded_value:
        result += bencode(i)
    return result + b"e"
def bencode_dict(unencoded_value):
    result = b"d"
    for k in unencoded_value:
        result += bencode(k) + bencode(unencoded_value[k])
    return result + b"e"
def bencode(unencoded_value):
    if isinstance(unencoded_value, str):
        return bencode_string(unencoded_value)
    elif isinstance(unencoded_value, bytes):
        return bencode_bytes(unencoded_value)
    elif isinstance(unencoded_value, int):
        return bencode_int(unencoded_value)
    elif isinstance(unencoded_value, list):
        return bencode_list(unencoded_value)
    elif isinstance(unencoded_value, dict):
        return bencode_dict(unencoded_value)
    else:
        raise ValueError("Can only bencode strings, ints, lists, or dicts.")
def decode_torrentfile(filename):
    with open(filename, "rb") as f:
        bencoded_content = f.read()
        decoded_value, remainder = decode_bencode(bencoded_content)
        if remainder:
            raise ValueError("Undecoded remainder.")
        return decoded_value
# Use list comprehension to return a split string of hashes.
def piece_hashes(pieces):
    n = 20
    if len(pieces) % n != 0:
        raise ValueError("Piece hashes do not add up to a multiple of", n, "bytes.")
    return [pieces[i : i + n] for i in range(0, len(pieces), n)]
def print_info(filename):
    decoded_value = decode_torrentfile(filename)
    print("Tracker URL:", decoded_value["announce"].decode())
    print("Length:", decoded_value["info"]["length"])
    info_hash = hashlib.sha1(bencode(decoded_value["info"])).hexdigest()
    print("Info Hash:", info_hash)
    print("Piece Length:", decoded_value["info"]["piece length"])
    print("Piece Hashes:")
    hashes = piece_hashes(decoded_value["info"]["pieces"])
    for h in hashes:
        print(h.hex())
def get_peers(filename):
    decoded_value = decode_torrentfile(filename)
    # Note: The requests library automatically encodes these parameters properly, including the info_hash
    tracker_url = decoded_value["announce"].decode()
    info_hash = hashlib.sha1(bencode(decoded_value["info"])).digest()
    peer_id = "00112233445566778899"
    port = 6881
    uploaded = 0
    downloaded = 0
    left = decoded_value["info"]["length"]
    compact = 1
    params = dict(
        info_hash=info_hash,
        peer_id=peer_id,
        port=port,
        uploaded=uploaded,
        downloaded=downloaded,
        left=left,
        compact=compact,
    )
    result = requests.get(tracker_url, params=params)
    decoded_result = decode_bencode(result.content)[0]
    return decoded_result["peers"]
def split_peers(peers):
    if len(peers) % 6 != 0:
        raise ValueError(
            "Peer list from tracker does not divide into 6 bytes; did you use compact?"
        )
    uncompacted_peers = []
    for peer in [peers[i : i + 6] for i in range(0, len(peers), 6)]:
        ip = str(peer[0]) + "." + str(peer[1]) + "." + str(peer[2]) + "." + str(peer[3])
        port = str(int.from_bytes(peer[4:], byteorder="big", signed=False))
        uncompacted_peers.append(ip + ":" + port)
    return uncompacted_peers
def init_handshake(filename, peer):
    decoded_value = decode_torrentfile(filename)
    peer_colon = peer.find(":")
    ip = peer[:peer_colon]
    port = int(peer[peer_colon + 1 :])
    length_prefix = struct.pack(">B", 19)
    protocol_string = b"BitTorrent protocol"
    reserved_bytes = b"\x00" * 8
    info_hash = hashlib.sha1(bencode(decoded_value["info"])).digest()
    peer_id = b"00112233445566778899"
    message = length_prefix + protocol_string + reserved_bytes + info_hash + peer_id
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(message)
    # Only grab the first 68 bytes, that's the handshake. Anything after this is the start of the bitfield.
    received_message = s.recv(68)
    return s, received_message
# The payload needs to already be in bytes.
def construct_message(message_id, payload):
    message_id = message_id.to_bytes(1)
    message = message_id + payload
    length = len(message)
    length_prefix = length.to_bytes(4, byteorder="big")
    message = length_prefix + message
    return message
def verify_message(message, message_id):
    if message[4] != message_id:
        raise ValueError(
            "Expected message of id %s, but received id %s" % (message_id, message[4])
        )
    if int.from_bytes(message[:4]) != len(message[4:]):
        raise ValueError("Message wrong length.")
def request_block(s, piece_index, block_index, length):
    index = piece_index
    begin = block_index * 2**14
    length = length
    payload = (
        struct.pack(">I", index) + struct.pack(">I", begin) + struct.pack(">I", length)
    )
    message = construct_message(6, payload)
    s.send(message)
    piece_message = receive_message(s)
    while piece_message[4] != 7:
        piece_message = receive_message(s)
    # Verify that the block has the payload we expect:
    verify_message(piece_message, 7)
    received_index = int.from_bytes(piece_message[5:9])
    received_begin = int.from_bytes(piece_message[9:13])
    if received_index != index or received_begin != begin:
        raise ValueError("Piece message does not have expected payload.")
    block = piece_message[13:]
    return block
def receive_message(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    # If we didn't receive the full message for some reason, keep gobbling.
    while len(message) < int.from_bytes(length):
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message
def download_piece(outputfile, filename, piececount):
    decoded_value = decode_torrentfile(filename)
    peers = split_peers(get_peers(filename))
    # For the sake of simplicity, at this stage, just use the first peer:
    peer = peers[1]
    s, received_message = init_handshake(filename, peer)
    # Wait for bitfield message:
    # It's only sent once, so no need to do a while here.
    bitfield = receive_message(s)
    verify_message(bitfield, 5)
    # Build and send interested message
    interested = construct_message(2, b"")
    s.send(interested)
    # Wait for unchoke message
    unchoke = receive_message(s)
    while unchoke[4] != 1:
        unchoke = receive_message(s)
    verify_message(unchoke, 1)
    # Calculate number of blocks, figuring out if we are the last piece
    last_piece_remainder = (
        decoded_value["info"]["length"] % decoded_value["info"]["piece length"]
    )
    total_pieces = len(piece_hashes(decoded_value["info"]["pieces"]))
    if piececount + 1 == total_pieces and last_piece_remainder > 0:
        length = last_piece_remainder
    else:
        length = decoded_value["info"]["piece length"]
    block_size = 16 * 1024
    full_blocks = length // block_size
    final_block = length % block_size
    # Send request for a block. This is painfully duplicated at the moment
    # to handle corner case where only have a small block.
    piece = b""
    sha1hash = hashlib.sha1()
    if full_blocks == 0:
        block = request_block(s, piececount, 0, final_block)
        piece += block
        sha1hash.update(block)
    else:
        for i in range(full_blocks):
            block = request_block(s, piececount, i, block_size)
            piece += block
            sha1hash.update(block)
        if final_block > 0:
            block = request_block(s, piececount, i + 1, final_block)
            piece += block
            sha1hash.update(block)
    # Verify piece hash
    piece_hash = piece_hashes(decoded_value["info"]["pieces"])[piececount]
    local_hash = sha1hash.digest()
    if piece_hash != local_hash:
        raise ValueError("Piece hash mismatch.")
    # Write piece to disk
    with open(outputfile, "wb") as piece_file:
        piece_file.write(piece)
    # Clean up
    s.close()
    # Return piece completed and location
    return piececount, outputfile
# TODO: Refactor download_pieces to use a buffer instead of intermediate files.
# TODO: Use a work queue to retry pieces and try different peers.
def download(outputfile, filename):
    decoded_value = decode_torrentfile(filename)
    total_pieces = len(piece_hashes(decoded_value["info"]["pieces"]))
    piecefiles = []
    for piece in range(0, total_pieces):
        p, o = download_piece("/tmp/test-" + str(piece), filename, piece)
        piecefiles.append(o)
    with open(outputfile, "ab") as result_file:
        for piecefile in piecefiles:
            with open(piecefile, "rb") as piece_file:
                result_file.write(piece_file.read())
            os.remove(piecefile)
# json.dumps() can't handle bytes, but bencoded "strings" need to be
# bytestrings since they might contain non utf-8 characters.
#
# Let's convert them to strings for printing to the console.
def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()
    raise TypeError(f"Type not serializable: {type(data)}")
def main():
    command = sys.argv[1]
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        decoded_value, remainder = decode_bencode(bencoded_value)
        if remainder:
            raise ValueError("Undecoded remainder.")
        print(json.dumps(decoded_value, default=bytes_to_str))
    elif command == "info":
        if len(sys.argv) != 3:
            raise NotImplementedError(f"Usage: {sys.argv[0]} info filename")
        filename = sys.argv[2]
        print_info(filename)
    elif command == "peers":
        if len(sys.argv) != 3:
            raise NotImplementedError(f"Usage: {sys.argv[0]} peers filename")
        filename = sys.argv[2]
        peers = split_peers(get_peers(filename))
        for p in peers:
            print(p)
    elif command == "handshake":
        if len(sys.argv) != 4:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} handshake filename <peer_ip>:<peer_port>"
            )
        filename = sys.argv[2]
        peer = sys.argv[3]
        peer_socket, received_message = init_handshake(filename, peer)
        received_id = received_message[48:68].hex()
        print("Peer ID:", received_id)
        peer_socket.close()
    elif command == "download_piece":
        if len(sys.argv) != 6:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} download_piece -o output filename piececount"
            )
        outputfile = sys.argv[3]
        filename = sys.argv[4]
        piececount = sys.argv[5]
        p, o = download_piece(outputfile, filename, int(piececount))
        print("Piece %i downloaded to %s" % (p, o))
    elif command == "download":
        if len(sys.argv) != 5:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} download -o output filename"
            )
        outputfile = sys.argv[3]
        filename = sys.argv[4]
        download(outputfile, filename)
        print("Download %s to %s" % (filename, outputfile))
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()