import json
import sys
# import bencodepy - available if you need it!
# import requests - available if you need it!
# Encode info dict
import bencodepy
import hashlib
# import binascii
import requests
import socket
import struct
import random
# Packages for Download
import concurrent.futures
import queue
# Packages for magnet link
from urllib.parse import unquote
pending_pieces = queue.Queue()
free_peers = queue.Queue()
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    # ll4:casaei4ee
    # ERROR
    # We can't remove last e, don't know when list will finish
    # l4:casaei4e
    # decode(4:casa, ei4e) !!!
    # print(f"Decoding: {bencoded_value}")
    if len(bencoded_value) < 1:
        return None
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        size = int((bencoded_value[0:first_colon_index]))
        # print(f"Size: {size}");
        # print(f"String: {bencoded_value[first_colon_index+1:first_colon_index+size+1]}")
        item = bencoded_value[first_colon_index + 1 : first_colon_index + size + 1]
        bencoded_value = bencoded_value[first_colon_index + size + 1 :]
        return item, bencoded_value
    elif chr(bencoded_value[0]) == "i":
        first_e_index = bencoded_value.find(b"e")
        if first_e_index == -1:
            raise ValueError("Invalid encoded value integer")
        # print(f"Decoding Integer: {bencoded_value} First_e_index: {first_e_index}")
        item = int(bencoded_value[1:first_e_index])
        bencoded_value = bencoded_value[first_e_index + 1 :]
        # print(f"Item: {item} bencoded_value: {bencoded_value}")
        return item, bencoded_value
    elif chr(bencoded_value[0]) == "l":
        bencoded_value = bencoded_value[1:]
        items = []
        if chr(bencoded_value[0]) == "e":
            # print("End list reached: ", bencoded_value)
            bencoded_value = bencoded_value[1:]
            return items, bencoded_value
        while True:
            item, bencoded_value = decode_bencode(bencoded_value)
            if item is not None:
                items.append(item)
                # print('Items: ', items)
            # print('Bucle: ', bencoded_value)
            if chr(bencoded_value[0]) == "e":
                # print("End list reached: ", bencoded_value)
                bencoded_value = bencoded_value[1:]
                return items, bencoded_value
    elif chr(bencoded_value[0]) == "d":
        bencoded_value = bencoded_value[1:]
        items = {}
        if chr(bencoded_value[0]) == "e":
            bencoded_value = bencoded_value[1:]
            return items, bencoded_value
        while True:
            key, bencoded_value = decode_bencode(bencoded_value)
            if not isinstance(key, bytes):
                raise TypeError("Key must be bytes")
            value, bencoded_value = decode_bencode(bencoded_value)
            items[key.decode()] = value
            if chr(bencoded_value[0]) == "e":
                bencoded_value = bencoded_value[1:]
                return items, bencoded_value
    else:
        print("ERROR: ", bencoded_value, bencoded_value[0], chr(bencoded_value[0]))
        raise NotImplementedError("Only strings are supported at the moment")
def info(file):
    f = open(file, "rb")
    benc = f.read()
    # Usar bencodepy.decode ??
    data, benc = decode_bencode(benc)
    """
    print("Tracker URL:", data['announce'].decode(encoding='UTF-8',errors='ignore'))
    print("Length:", data['info']['length'])
    print("[DEBUG] data[info] keys: ", data['info'].keys())
    """
    encoded = bencodepy.encode(data["info"])
    hash = hashlib.sha1(encoded)
    """
    print("Info Hash:", hash.hexdigest()) 
    print("Piece Length:", data['info']['piece length'])
    print("Piece Hashes:")
    
    phashes = data['info']['pieces']
    i = 0
    
    while i < len(phashes):
        print(binascii.hexlify(phashes[i:i+20]).decode())
        i += 20
    """
    return hash.digest(), data
def peers(digest, data):
    # Stage 8 Discover peers
    payload = {
        "info_hash": digest,
        "peer_id": "99887766554433221100",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": data["info"]["length"],
        "compact": 1,
    }
    r = requests.get(data["announce"], params=payload)
    response = bencodepy.decode(r.content)
    peers_list = []
    for i in range(0, len(response[b"peers"]), 6):
        peer_ip = response[b"peers"][i : i + 4]
        peer_port = response[b"peers"][i + 4 : i + 6]
        peers_list.append(
            (
                ".".join([str(peer_ip[i]) for i in range(4)]),
                peer_port[0] * 256 + peer_port[1],
            )
        )
        line = (
            ".".join([str(peer_ip[i]) for i in range(4)])
            + ":"
            + str(peer_port[0] * 256 + peer_port[1])
        )
        # print(line)
    return peers_list
def handshake(digest, ip, port, reserved=b"\x00\x00\x00\x00\x00\x00\x00\x00"):
    packet = b"\x13"
    packet += b"BitTorrent protocol"
    packet += reserved
    packet += digest
    packet += b"CRAZY-ASS-TORRENT999"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    s.sendall(packet)
    answer = s.recv(68)
    peer = answer[48:]
    # print("Peer ID:", peer.hex())
    s.close()
    ext_support = answer[25] == b"\x10"
    return peer.hex(), ext_support
def download_piece(digest, data, peer, index):
    (ip, port) = peer
    port = int(port)
    index = int(index).to_bytes(4)
    # Call handshake()
    # Does not work?
    # s = handshake(digest, ip, port)
    packet = b"\x13"
    packet += b"BitTorrent protocol"
    packet += b"\x00\x00\x00\x00\x00\x00\x00\x00"
    packet += digest
    packet += b"zz993R-CR9ZY-T0RR3NT"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
        s.sendall(packet)
        # Handshake back
        answer = s.recv(68)
        peer = answer[-20:]
        # print("Peer ID:", peer.hex())
        # Recv bitfield
        received = False
        while not received:
            length = s.recv(4)
            if length and int.from_bytes(length):
                bitfield = s.recv(int.from_bytes(length))
                type = bitfield[0]
                if type == 5:
                    while len(bitfield) < int.from_bytes(length):
                        bitfield += s.recv(int.from_bytes(length) - len(bitfield))
                    received = True
        # print("<<< BITFIELD")
        # if (int(bitfield[1]) & 128) == 128:
        #    print("Peer has piece 0")
        # Check if peer has piece
        piece_idx = int.from_bytes(index)
        byte_num = int(piece_idx // 8)
        bit_num = 1 << (7 - int(piece_idx % 8))
        # print(f"DEBUG {piece_idx} Bitfield len {len(bitfield)} Piece at ({byte_num},{bit_num})")
        if not (bit_num & bitfield[byte_num + 1] == bit_num):
            # print(f"Bitfield[{byte_num}+1] = {bitfield[byte_num]}")
            s.close()
            return False, 0
        # Send interested
        # message length prefix (4b)
        # type interested
        # Message type (1byte) included in message length
        packet = b"\x00\x00\x00\x01\x02"
        s.sendall(packet)
        # print(">>> INTERESTED")
        # Recv unchoke
        received = False
        while not received:
            length = s.recv(4)
            if length and int.from_bytes(length):
                msg = s.recv(int.from_bytes(length))
                type = msg[0]
                if type == 1:
                    while len(msg) < int.from_bytes(length):
                        msg += s.recv(int.from_bytes(length) - len(msg))
                    received = True
                    # print(f"(Packet size {len(bitfield)}) length {bitfield[0:4]}")
                    # print(bitfield)
        # print("<<< UNCHOKE")
        # TODO: Multiple requests
        # Use bytearray(<size>) and data[pos:pos+len(block)] = block
        # with type(block) = <class bytes>
        # type(total) = <class bytearray>
        file_length = data["info"]["length"]
        num_pieces = int(len(data["info"]["pieces"]) / 20)
        default_piece_length = data["info"]["piece length"]
        # Watcha!!!!
        # Previously:
        #   index = int(index).to_bytes(4)
        if int.from_bytes(index) == num_pieces - 1:
            piece_length = file_length - (int.from_bytes(index) * default_piece_length)
        else:
            piece_length = default_piece_length
        num_blocks = piece_length // (16 * 1024)
        rest_size = piece_length % (16 * 1024)
        # print(f"File length {file_length} Num pieces {num_pieces}")
        # print(f"DEFAULT Piece length {data['info']['piece length']} ACTUAL piece length {piece_length}")
        # print(f"Number of complete blocks {num_blocks} rest_size {rest_size}")
        piece = bytearray(piece_length)
        block_size = 16 * 1024
        begin = 0
        for i in range(num_blocks):
            # Send request
            packet = b"\x06"  # message type 6 - request
            packet += index  # piece index
            # begin = i * 2 ** 14
            packet += int(begin).to_bytes(
                4
            )  # begin block of piece 0 first, 2**14 sec, 2 * 2**14
            # block size 2**14 all packets, except last one
            # ARGh!!! 2**14 = \x00\x00@\x00'
            # NOOT ¡¡ packet += b'\x04\x00\x00\x00'       !!!
            # packet += int(2 ** 14).to_bytes(4)       # block size 2**14 all packets, except last one
            packet += b"\x00\x00@\x00"
            # packet_size = int(13).to_bytes(4)
            packet_size = b"\x00\x00\x00\r"
            packet = packet_size + packet
            # print(">>> REQUEST block: ", i)
            # print(packet)
            s.sendall(packet)
            # Receive
            received = False
            while not received:
                length = s.recv(4)
                if length and int.from_bytes(length):
                    # print(int.from_bytes(length))
                    msg = s.recv(int.from_bytes(length))
                    type = msg[0]
                    if type == 7:
                        while len(msg) < int.from_bytes(length):
                            msg += s.recv(int.from_bytes(length) - len(msg))
                        received = True
                        # print(f"(Packet size {len(msg)}) includes type(1), index(4), begin(4), piece(rest)")
                    else:
                        print("Received NOT piece(7) msg:", type)
            # print("<<< DATA BLOCK")
            # data_block = msg[9:]
            # Later
            # f.write(data_block)
            piece[begin : begin + block_size] = msg[9:]
            begin += block_size
        # Last block, different size
        # TODO: don't repeat everything except block size
        # Send request
        if rest_size > 0:
            # print(f"Last block size {rest_size}")
            packet = b"\x06"  # message type 6 - request
            packet += index  # piece index
            begin = piece_length - rest_size
            packet += int(begin).to_bytes(
                4
            )  # begin block of piece 0 first, 2**14 sec, 2 * 2**14
            packet += int(rest_size).to_bytes(
                4
            )  # block size 2**14 all packets, except last one
            packet_size = int(13).to_bytes(4)
            # packet = b'\x00\x00\x00\x07' + packet
            packet = packet_size + packet
            s.sendall(packet)
            # Receive
            received = False
            while not received:
                length = s.recv(4)
                if length and int.from_bytes(length):
                    # print(int.from_bytes(length))
                    msg = s.recv(int.from_bytes(length))
                    type = msg[0]
                    if type == 7:
                        while len(msg) < int.from_bytes(length):
                            msg += s.recv(int.from_bytes(length) - len(msg))
                        received = True
                        # print(f"(Packet size {len(bitfield)}) length {bitfield[0:4]}")
                        # print(bitfield)
                    else:
                        print("Received NOT piece(7) msg:", type)
            # Later
            # data_block = msg[9:]
            # f.write(data_block)
            piece[begin:] = msg[9:]
    except (ConnectionError, ConnectionResetError, TimeoutError) as cnxerr:
        print(f"Connection error {cnxerr} with {ip}:{port}")
        if s:
            s.close()
        return False, 0
    except Exception as err:
        print(f"Unexpected {err=}")
        if s:
            s.close()
        raise
    finally:
        s.close()
    return True, piece
def dwn_worker(digest, data, dummy):
    peer = free_peers.get()
    if pending_pieces.empty():
        return False, -1, 0, peer
    else:
        piece_idx = pending_pieces.get()
    # print(f"Download {piece_idx} from {peer}")
    status, piece_data = download_piece(digest, data, peer, piece_idx)
    return status, piece_idx, piece_data, peer
def download(digest, data, peers_list, output_file):
    # print("TODO")
    print(f"File length: {data['info']['length']}")
    print(f"Output_file: {output_file}")
    num_peers = len(peers_list)
    print(f"{num_peers} peers")
    num_pieces = int(len(data["info"]["pieces"]) / 20)
    print(f"{num_pieces} pieces")
    default_piece_length = data["info"]["piece length"]
    print(f"Default piece length {default_piece_length}")
    for p in peers_list:
        free_peers.put(p)
    for i in range(num_pieces):
        pending_pieces.put(i)
    # Create empty file of size data['info']['length']
    with open(output_file, "wb") as f:
        for i in range(data["info"]["length"] // default_piece_length):
            f.write(b"\xde\xad\xbe\xef" * (default_piece_length // 4))
            f.write(b"\xde\xad\xbe\xef"[0 : (default_piece_length % 4)])
        # Last piece
        last_piece_length = data["info"]["length"] % default_piece_length
        f.write(b"\xde\xad\xbe\xef" * (last_piece_length // 4))
        f.write(b"\xde\xad\xbe\xef"[0 : (last_piece_length % 4)])
    num_downloads = 0
    total = num_pieces
    file = bytearray(data["info"]["length"])
    while not pending_pieces.empty():
        # Max_workers = size(peers)
        # with concurrent.futures.ThreadPoolExecutor(max_workers=len(peers_list)) as executor:
        # print("max_workers=3 submit 9")
        # Local max_workers=3, remote=8 ?
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(peers_list)
        ) as executor:
            # Tasks = number pending pieces
            future_to_arg = {
                executor.submit(dwn_worker, digest, data, i): i
                for i in range(num_pieces - num_downloads)
            }
            for future in concurrent.futures.as_completed(future_to_arg):
                downloaded, p_idx, piece_data, peer = future.result()
                # print(f"Finished status: {downloaded} piece {p_idx} peer {peer}")
                if downloaded:
                    piece_hash = data["info"]["pieces"][
                        p_idx * 20 : p_idx * 20 + 20
                    ].hex()
                    dwn_hash = hashlib.sha1(piece_data).hexdigest()
                    if dwn_hash != piece_hash:
                        print(f"Piece hash mismatch dwn: {dwn_hash} data: {piece_hash}")
                        # Download again
                        pending_pieces.put(p_idx)
                    else:
                        # FIXME
                        # Create first empty file
                        # WATCHA!!!!
                        """
                        with open(output_file, "ab") as f:
                        https://docs.python.org/3/library/functions.html#open
                        ...
                        'a' for appending (which on some Unix systems, means that all writes append
                        to the end of the file regardless of the current seek position)
                        """
                        """
                        1 write / file
                        with open(output_file, "r+b") as f:
                            f.seek(p_idx * default_piece_length)
                            # print("Cursor at: ", f.tell())
                            nb = f.write(piece_data)
                            # print("File cursor at: ", f.tell(), ", ", nb, " bytes written of piece: ", p_idx)
                        """
                        file[
                            p_idx
                            * default_piece_length : (
                                p_idx * default_piece_length + default_piece_length
                            )
                        ] = piece_data
                        num_downloads += 1
                        print(f"Downloaded piece {p_idx} from {peer}")
                else:
                    pending_pieces.put(p_idx)
                free_peers.put(peer)
    with open(output_file, "r+b") as f:
        f.seek(0)
        nb = f.write(file)
        print(nb, " bytes written to file")
def magnet_parse(link):
    _, params = link.split("?")
    params = params.split("&")
    print(params)
    dparams = {}
    for p in params:
        (key, value) = p.split("=")
        # xt=urn:btih:<info-hash>
        if key == "xt":
            if value[0:9] == "urn:btih:":
                value = value[9:]
        if key == "tr":
            value = unquote(value)
        dparams[key] = value
    if "tr" in dparams and "xt" in dparams:
        return dparams["tr"], dparams["xt"]
    else:
        return None, None
def magnet_handshake(s: socket, digest):
    # >>> HANDSHAKE
    packet = b"\x13"
    packet += b"BitTorrent protocol"
    # We support extensions
    packet += int(0x100000).to_bytes(8)
    packet += digest
    packet += b"CRAZY-ASS-TORRENT999"
    s.sendall(packet)
    answer = s.recv(68)
    peer = answer[48:]
    print("Peer ID:", peer.hex())
    ext_support = answer[25] == 0x10
    # <<< BITFIELD
    received = False
    while not received:
        length = s.recv(4)
        if length and int.from_bytes(length):
            bitfield = s.recv(int.from_bytes(length))
            type = bitfield[0]
            if type == 5:
                while len(bitfield) < int.from_bytes(length):
                    bitfield += s.recv(int.from_bytes(length) - len(bitfield))
                received = True
    print("<<< BITFIELD")
    if ext_support:
        # <<< EXTENSION HANDSHAKE
        received = False
        ext_id = 0
        while not received:
            length = s.recv(4)
            if length and int.from_bytes(length):
                extension = s.recv(int.from_bytes(length))
                # print(f"Received {int.from_bytes(length)} bytes")
                type = extension[0]
                if type == 20:
                    print("<<< EXTENSION HANDSHAKE")
                    # print(extension[2:])
                    payload = bencodepy.decode(extension[2:])
                    # print(payload)
                    if b"m" in payload:
                        if b"ut_metadata" in payload[b"m"]:
                            # print("Extension id:", payload[b"m"][b"ut_metadata"])
                            ext_id = payload[b"m"][b"ut_metadata"]
                            received = True
                    if b"metadata_size" in payload:
                        metadata_size = payload[b"metadata_size"]
        # >>> EXTENSION HANDSHAKE
        payload = {}
        payload["m"] = {}
        payload["m"]["ut_metadata"] = 1
        enc_payload = bencodepy.encode(payload)
        packet_header = int(len(enc_payload) + 1 + 1).to_bytes(4)
        """
        [your_program] Extension id: 245
        [tester::#XI4] Received extension handshake with payload: �d1:md11:ut_metadatai1eee
        [tester::#XI4] expected extension handshake message id: 0, actual: 245.
        First byte of payload indicates extension message id and it needs to be zero for extension handshake
        """
        packet = packet_header + b"\x14\x00" + enc_payload
        s.sendall(packet)
        # print("Peer Metadata Extension ID:", ext_id)
        return ext_id, metadata_size
    return None
def magnet_info(s: socket, ext_id: int, metadata_size: int):
    # >>> METADATA_REQUEST
    packet = b"\x14" + ext_id.to_bytes()
    payload = {"msg_type": 0, "piece": 0}
    enc_payload = bencodepy.encode(payload)
    packet += enc_payload
    packet = int(2 + len(enc_payload)).to_bytes(4) + packet
    s.sendall(packet)
    # <<< METADATA_DATA
    received = False
    while not received:
        length = s.recv(4)
        if length and int.from_bytes(length):
            data = s.recv(int.from_bytes(length))
            if data[0] == 20:
                ext_id = data[1]
                # In general, piece = 16k except last one
                # In codecrafters metadata fits in 1 piece
                print(f"Total length {int.from_bytes(length)}")
                print(f"Metadata size: {metadata_size}")
                print("RAW")
                print(data[2:])
                print("-" * 20)
                ext_dict = data[2 : int.from_bytes(length) - metadata_size]
                dec_ext_dict = bencodepy.decode(ext_dict)
                metadata = data[2 + len(ext_dict) :]
                dec_metadata = bencodepy.decode(metadata)
                received = True
    return dec_metadata
def magnet_download_piece(s: socket, data, index):
    # Send interested
    # message length prefix (4b)
    # type interested
    # Message type (1byte) included in message length
    index = int(index).to_bytes(4)
    packet = b"\x00\x00\x00\x01\x02"
    s.sendall(packet)
    # Recv unchoke
    received = False
    while not received:
        length = s.recv(4)
        if length and int.from_bytes(length):
            msg = s.recv(int.from_bytes(length))
            type = msg[0]
            if type == 1:
                while len(msg) < int.from_bytes(length):
                    msg += s.recv(int.from_bytes(length) - len(msg))
                received = True
    file_length = data["info"]["length"]
    num_pieces = int(len(data["info"]["pieces"]) / 20)
    default_piece_length = data["info"]["piece length"]
    # Watcha!!!!
    # Previously:
    #   index = int(index).to_bytes(4)
    if int.from_bytes(index) == num_pieces - 1:
        piece_length = file_length - (int.from_bytes(index) * default_piece_length)
    else:
        piece_length = default_piece_length
    num_blocks = piece_length // (16 * 1024)
    rest_size = piece_length % (16 * 1024)
    # print(f"File length {file_length} Num pieces {num_pieces}")
    # print(f"DEFAULT Piece length {data['info']['piece length']} ACTUAL piece length {piece_length}")
    # print(f"Number of complete blocks {num_blocks} rest_size {rest_size}")
    piece = bytearray(piece_length)
    block_size = 16 * 1024
    begin = 0
    for i in range(num_blocks):
        # Send request
        packet = b"\x06"  # message type 6 - request
        packet += index  # piece index
        # begin = i * 2 ** 14
        packet += int(begin).to_bytes(
            4
        )  # begin block of piece 0 first, 2**14 sec, 2 * 2**14
        # block size 2**14 all packets, except last one
        # ARGh!!! 2**14 = \x00\x00@\x00'
        # NOOT ¡¡ packet += b'\x04\x00\x00\x00'       !!!
        # packet += int(2 ** 14).to_bytes(4)       # block size 2**14 all packets, except last one
        packet += b"\x00\x00@\x00"
        # packet_size = int(13).to_bytes(4)
        packet_size = b"\x00\x00\x00\r"
        packet = packet_size + packet
        # print(">>> REQUEST block: ", i)
        # print(packet)
        s.sendall(packet)
        # Receive
        received = False
        while not received:
            length = s.recv(4)
            if length and int.from_bytes(length):
                # print(int.from_bytes(length))
                msg = s.recv(int.from_bytes(length))
                type = msg[0]
                if type == 7:
                    while len(msg) < int.from_bytes(length):
                        msg += s.recv(int.from_bytes(length) - len(msg))
                    received = True
                    # print(f"(Packet size {len(msg)}) includes type(1), index(4), begin(4), piece(rest)")
                else:
                    print("Received NOT piece(7) msg:", type)
        # print("<<< DATA BLOCK")
        # data_block = msg[9:]
        # Later
        # f.write(data_block)
        piece[begin : begin + block_size] = msg[9:]
        begin += block_size
    # Last block, different size
    # TODO: don't repeat everything except block size
    # Send request
    if rest_size > 0:
        # print(f"Last block size {rest_size}")
        packet = b"\x06"  # message type 6 - request
        packet += index  # piece index
        begin = piece_length - rest_size
        packet += int(begin).to_bytes(
            4
        )  # begin block of piece 0 first, 2**14 sec, 2 * 2**14
        packet += int(rest_size).to_bytes(
            4
        )  # block size 2**14 all packets, except last one
        packet_size = int(13).to_bytes(4)
        # packet = b'\x00\x00\x00\x07' + packet
        packet = packet_size + packet
        s.sendall(packet)
        # Receive
        received = False
        while not received:
            length = s.recv(4)
            if length and int.from_bytes(length):
                # print(int.from_bytes(length))
                msg = s.recv(int.from_bytes(length))
                type = msg[0]
                if type == 7:
                    while len(msg) < int.from_bytes(length):
                        msg += s.recv(int.from_bytes(length) - len(msg))
                    received = True
                    # print(f"(Packet size {len(bitfield)}) length {bitfield[0:4]}")
                    # print(bitfield)
                else:
                    print("Received NOT piece(7) msg:", type)
        # Later
        # data_block = msg[9:]
        # f.write(data_block)
        piece[begin:] = msg[9:]
    return True, piece
def main():
    command = sys.argv[1]
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")
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
        # Uncomment this block to pass the first stage
        item, decoded = decode_bencode(bencoded_value)
        print(json.dumps(item, default=bytes_to_str))
    elif command == "info":
        digest, data = info(sys.argv[2].encode())
        print(
            "Tracker URL:", data["announce"].decode(encoding="UTF-8", errors="ignore")
        )
        print("Length:", data["info"]["length"])
        encoded = bencodepy.encode(data["info"])
        hash = hashlib.sha1(encoded)
        print("Info Hash:", hash.hexdigest())
        print("Piece Length:", data["info"]["piece length"])
        print("Piece Hashes:")
        for i in range(0, len(data["info"]["pieces"]), 20):
            print(data["info"]["pieces"][i : i + 20].hex())
    elif command == "peers":
        digest, data = info(sys.argv[2].encode())
        peers_list = peers(digest, data)
        for i in peers_list:
            (ip, port) = i
            print(f"{ip}:{port}")
    elif command == "handshake":
        ip, port = sys.argv[3].split(":")
        digest, data = info(sys.argv[2].encode())
        peer, ext_support = handshake(digest, ip, port)
        print("Peer ID:", peer)
    elif command == "download_piece":
        digest, data = info(sys.argv[4].encode())
        peers_list = peers(digest, data)
        num_pieces = int(len(data["info"]["pieces"]) / 20)
        if int(sys.argv[5]) >= num_pieces:
            raise ValueError("Piece index out range")
        downloaded, piece = download_piece(
            digest, data, peers_list[0], index=sys.argv[5]
        )
        if downloaded:
            with open(sys.argv[3], "wb") as f:
                f.write(piece)
                f.close()
        elif piece is not None:
            print(f"f{peers_list[0]} has not piece {sys.argv[5]}")
    elif command == "download":
        # ./your_bittorrent.sh download -o /tmp/test.txt sample.torrent
        digest, data = info(sys.argv[4].encode())
        peers_list = peers(digest, data)
        download(digest, data, peers_list, output_file=sys.argv[3])
    elif command == "magnet_parse":
        tracker, hash = magnet_parse(sys.argv[2])
        if not tracker is None and not hash is None:
            print("Tracker URL:", tracker)
            print("Info Hash:", hash)
        else:
            print("Magnet link decoding error: ", link)
    elif command == "magnet_handshake":
        tracker, hexdigest = magnet_parse(sys.argv[2])
        # Watcha...40 bytes hex to 20 bytes digest
        digest = bytes.fromhex(hexdigest)
        data = {}
        data["announce"] = tracker
        data["info"] = {}
        data["info"]["length"] = 1024
        peers_list = peers(digest, data)
        (ip, port) = peers_list[0]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, int(port)))
            if tracker is not None:
                ext_id, metadata_size = magnet_handshake(s, digest)
                print("Peer Metadata Extension ID:", ext_id)
                print("Metadata size:", metadata_size)
        finally:
            s.close()
    elif command == "magnet_info":
        tracker, hexdigest = magnet_parse(sys.argv[2])
        # Watcha...40 bytes hex to 20 bytes digest
        digest = bytes.fromhex(hexdigest)
        data = {}
        data["announce"] = tracker
        data["info"] = {}
        data["info"]["length"] = 1024
        peers_list = peers(digest, data)
        (ip, port) = peers_list[0]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, int(port)))
            if not tracker is None:
                ext_id, metadata_size = magnet_handshake(s, digest)
                print("Peer Metadata Extension ID:", ext_id)
                if not metadata_size is None:
                    print("Metadata size:", metadata_size)
                if not ext_id is None:
                    metadata = magnet_info(s, ext_id, metadata_size)
        finally:
            s.close()
        print("Tracker URL:", tracker)
        print("Length:", metadata[b"length"])
        print("Info Hash:", hexdigest)
        print("Piece Length:", metadata[b"piece length"])
        print("Piece Hashes:")
        for i in range(0, len(metadata[b"pieces"]), 20):
            print(metadata[b"pieces"][i : i + 20].hex())
        print("Magnet info hash:", hexdigest)
    elif command == "magnet_download_piece":
        # TODO: magnet_info in function
        tracker, hexdigest = magnet_parse(sys.argv[4])
        # Watcha...40 bytes hex to 20 bytes digest
        digest = bytes.fromhex(hexdigest)
        data = {}
        data["announce"] = tracker
        data["info"] = {}
        data["info"]["length"] = 1024
        peers_list = peers(digest, data)
        (ip, port) = peers_list[0]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, int(port)))
            if not tracker is None:
                ext_id, metadata_size = magnet_handshake(s, digest)
                print("Peer Metadata Extension ID:", ext_id)
                if not metadata_size is None:
                    print("Metadata size:", metadata_size)
                if not ext_id is None:
                    metadata = magnet_info(s, ext_id, metadata_size)
            print("Tracker URL:", tracker)
            print("Length:", metadata[b"length"])
            print("Info Hash:", hexdigest)
            print("Piece Length:", metadata[b"piece length"])
            print("Piece Hashes:")
            for i in range(0, len(metadata[b"pieces"]), 20):
                print(metadata[b"pieces"][i : i + 20].hex())
            print("Magnet info hash:", hexdigest)
            data = {}
            data["info"] = {}
            data["info"]["length"] = metadata[b"length"]
            data["info"]["pieces"] = metadata[b"pieces"]
            data["info"]["piece length"] = metadata[b"piece length"]
            downloaded, piece_data = magnet_download_piece(s, data, sys.argv[5])
            if downloaded:
                with open(sys.argv[3], "wb") as f:
                    f.write(piece_data)
                    f.close()
            elif piece is not None:
                print(f"f{peers_list[0]} has not piece {sys.argv[5]}")
        finally:
            s.close()
    elif command == "magnet_download":
        tracker, hexdigest = magnet_parse(sys.argv[4])
        # Watcha...40 bytes hex to 20 bytes digest
        digest = bytes.fromhex(hexdigest)
        data = {}
        data["announce"] = tracker
        data["info"] = {}
        data["info"]["length"] = 1024
        peers_list = peers(digest, data)
        (ip, port) = peers_list[0]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, int(port)))
            if not tracker is None:
                ext_id, metadata_size = magnet_handshake(s, digest)
                print("Peer Metadata Extension ID:", ext_id)
                if not metadata_size is None:
                    print("Metadata size:", metadata_size)
                if not ext_id is None:
                    metadata = magnet_info(s, ext_id, metadata_size)
            print("Tracker URL:", tracker)
            print("Length:", metadata[b"length"])
            print("Info Hash:", hexdigest)
            print("Piece Length:", metadata[b"piece length"])
            print("Piece Hashes:")
            for i in range(0, len(metadata[b"pieces"]), 20):
                print(metadata[b"pieces"][i : i + 20].hex())
            print("Magnet info hash:", hexdigest)
            data = {}
            data["info"] = {}
            data["info"]["length"] = metadata[b"length"]
            data["info"]["pieces"] = metadata[b"pieces"]
            data["info"]["piece length"] = metadata[b"piece length"]
        finally:
            s.close()
        download(digest, data, peers_list, output_file=sys.argv[3])
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()