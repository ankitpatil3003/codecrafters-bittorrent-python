import hashlib
import math
import socket
import sys
from typing import Optional
import requests
from app.bencode import decode
from app.types import (
    ExtensionHandshake,
    Metadata,
    MetadataMsgType,
    PeerHandshake,
    TorrentMetainfo,
)
STD_BLOCK_SIZE = 16 * 1024
PEER_ID = 19724808973135933552
BASE_PAYLOAD = {"m": {"ut_metadata": 1}}
def display(value) -> str:
    if type(value) is bytes:
        return f'"{value.decode()}"'
    elif type(value) is str:
        return f'"{value}"'
    elif type(value) is int:
        return f"{value}"
    elif type(value) is list:
        arr = [display(v) for v in value]
        return "[" + ",".join(arr) + "]"
    elif type(value) is dict:
        kvs = [f"{display(k)}:{display(v)}" for k, v in value.items()]
        return "{" + ",".join(kvs) + "}"
    else:
        raise NotImplementedError("[DISLAY] Not supported")
def print_info(metainfo: TorrentMetainfo):
    print(f"Tracker URL: {metainfo.tracker_url}")
    print(f"Length: {metainfo.length}")
    print(f"Info Hash: {metainfo.info_hash.hex()}")
    print(f"Piece Length: {metainfo.piece_length}")
    print("Piece Hashes:")
    for piece_hash in metainfo.piece_hashes:
        print(f"{piece_hash.hex()}")
def fetch_peers(metainfo: TorrentMetainfo) -> list[tuple[str, int]]:
    length = metainfo.length
    if length is None:
        length = 1  # Use dummy default
    query_params = {
        "info_hash": metainfo.info_hash,
        "peer_id": str(PEER_ID),
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": length,
        "compact": 1,
    }
    req = requests.get(metainfo.tracker_url, params=query_params)
    resp = decode(req.content)
    assert isinstance(resp, dict)
    peer_bytes = resp["peers"]
    peers_bytes: list[bytes] = [
        peer_bytes[i : i + 6] for i in range(0, len(peer_bytes), 6)
    ]
    peers = []
    for pb in peers_bytes:
        ip, port = pb[0:4], pb[4:]
        ip_str = ".".join([str(n) for n in ip])
        port = int.from_bytes(port)
        peers.append((ip_str, port))
    return peers
def print_peers(metainfo: TorrentMetainfo):
    peers = fetch_peers(metainfo)
    for p in peers:
        print(f"{p[0]}:{p[1]}")
def get_socket(ip: str, port: int) -> socket.socket:
    s = socket.socket()
    # print(f"Connecting to {ip}:{port}")
    s.connect((ip, int(port)))
    return s
def recv_msg(s: socket.socket) -> bytes:
    msg_len = int.from_bytes(s.recv(4))
    # print(f"Received message of length {msg_len}")
    msg = s.recv(msg_len)
    while len(msg) < msg_len:
        msg += s.recv(msg_len - len(msg))
    return msg
def peer_handshake(
    metainfo: TorrentMetainfo, s: socket.socket, extensions_supported: bool = False
) -> PeerHandshake:
    handshake = PeerHandshake(
        supports_extensions=extensions_supported,
        info_hash=metainfo.info_hash,
        peer_id=PEER_ID,
    ).to_bytes()
    s.send(handshake)
    resp = s.recv(len(handshake))
    return PeerHandshake.from_bytes(resp)
def send_ext_handshake(s: socket.socket) -> ExtensionHandshake:
    ext_handshake = ExtensionHandshake(BASE_PAYLOAD)
    s.send(ext_handshake.to_bytes())
    resp = recv_msg(s)
    return ExtensionHandshake.from_bytes(resp)
def get_metadata_ext_id(s: socket.socket, handshake: PeerHandshake) -> Optional[int]:
    if not handshake.supports_extensions:
        return None
    recv_bitfield_msg(s)
    resp = send_ext_handshake(s)
    ext_id = resp.payload["m"]["ut_metadata"]
    assert isinstance(ext_id, int)
    return ext_id
def send_metadata_ext_req(s: socket.socket, payload: Metadata) -> Metadata:
    s.send(payload.to_bytes())
    resp = recv_msg(s)
    return Metadata.from_bytes(resp)
def recv_bitfield_msg(s: socket.socket):
    msg = recv_msg(s)
    assert msg[0] == 5
def send_interested_msg(s: socket.socket):
    s.send((1).to_bytes(4) + (2).to_bytes(1))
def recv_unchoke_msg(s: socket.socket):
    msg = recv_msg(s)
    assert msg[0] == 1
def setup_download(s: socket.socket):
    recv_bitfield_msg(s)
    send_interested_msg(s)
    recv_unchoke_msg(s)
def send_download_request(
    metainfo: TorrentMetainfo, s: socket.socket, piece_idx: int
) -> bytes:
    if not (metainfo.length and metainfo.piece_length):
        raise ValueError("Metainfo is missing length or piece length")
    # print(f"Downloading piece {piece_idx}")
    # Determine size of requested piece
    piece_size = metainfo.piece_length
    num_pieces = len(metainfo.piece_hashes)
    if piece_idx == num_pieces - 1:
        piece_size = metainfo.length - (piece_size * (num_pieces - 1))
    # Determine number of blocks making up the piece
    num_blocks = math.ceil(piece_size / STD_BLOCK_SIZE)
    # Send request messages for the piece blocks
    for b in range(num_blocks):
        # Smaller block size for last block
        block_size = STD_BLOCK_SIZE
        if b == num_blocks - 1:
            block_size = piece_size - (STD_BLOCK_SIZE * (num_blocks - 1))
        payload = (
            (piece_idx).to_bytes(4)
            + (b * STD_BLOCK_SIZE).to_bytes(4)
            + (block_size).to_bytes(4)
        )
        s.send((1 + len(payload)).to_bytes(4) + (6).to_bytes(1) + payload)
        # print(f"Sent request for piece {piece_idx} block {b}")
    # Wait for piece messages
    recv_blocks = []
    while len(recv_blocks) < num_blocks:
        msg = recv_msg(s)
        assert msg[0] == 7
        begin = int.from_bytes(msg[5:9])
        block = msg[9:]
        # print(f"Received piece {p} block {begin // STD_BLOCK_SIZE}")
        recv_blocks.append((begin, block))
    # Create piece from blocks
    piece = b"".join([block for _, block in recv_blocks])
    # Verify piece hash
    assert hashlib.sha1(piece).digest() == metainfo.piece_hashes[piece_idx]
    return piece
def download_file(
    metainfo: TorrentMetainfo, save_path: str, piece_index: Optional[int] = None
):
    for ip, port in fetch_peers(metainfo):
        try:
            s = get_socket(ip, int(port))
            peer_handshake(metainfo, s)
            setup_download(s)
            file = b""
            if piece_index is not None:
                file = send_download_request(metainfo, s, piece_index)
            else:
                for i in range(len(metainfo.piece_hashes)):
                    piece = send_download_request(metainfo, s, i)
                    file += piece
                    # print(f"Downloaded piece {i}")
            with open(save_path, "wb") as f:
                f.write(file)
                return
        except Exception as e:
            print(e)
def fetch_metadata_from_peer(metainfo: TorrentMetainfo):
    for ip, port in fetch_peers(metainfo):
        try:
            s = get_socket(ip, int(port))
            handshake = peer_handshake(metainfo, s, True)
            ext_id = get_metadata_ext_id(s, handshake)
            if ext_id is not None:
                payload = Metadata(ext_id, MetadataMsgType.REQUEST)
                resp = send_metadata_ext_req(s, payload)
                metadata = resp.metadata
                assert isinstance(metadata, dict)
                metainfo.add_metadata(metadata)
                return
        except Exception as e:
            print(e)
def main():
    command = sys.argv[1]
    match command:
        case "decode":
            bencoded_value = sys.argv[2].encode()
            print(display(decode(bencoded_value)))
        case "info":
            metainfo = TorrentMetainfo.from_torrent_file(sys.argv[2])
            print_info(metainfo)
        case "peers":
            metainfo = TorrentMetainfo.from_torrent_file(sys.argv[2])
            print_peers(metainfo)
        case "handshake":
            metainfo = TorrentMetainfo.from_torrent_file(sys.argv[2])
            peer = sys.argv[3]
            ip, port = peer.split(":")
            s = get_socket(ip, int(port))
            handshake = peer_handshake(metainfo, s)
            peer_id = handshake.peer_id
            print(f"Peer ID: {peer_id.to_bytes(20).hex()}")
        case "download_piece":
            metainfo = TorrentMetainfo.from_torrent_file(sys.argv[4])
            piece_index = int(sys.argv[5])
            save_path = sys.argv[3]
            download_file(metainfo, save_path, piece_index)
        case "download":
            metainfo = TorrentMetainfo.from_torrent_file(sys.argv[4])
            save_path = sys.argv[3]
            download_file(metainfo, save_path)
        case "magnet_parse":
            magnet_link = sys.argv[2]
            metainfo = TorrentMetainfo.from_magnet_link(magnet_link)
            print(f"Tracker URL: {metainfo.tracker_url}")
            print(f"Info Hash: {metainfo.info_hash.hex()}")
        case "magnet_handshake":
            magnet_link = sys.argv[2]
            metainfo = TorrentMetainfo.from_magnet_link(magnet_link)
            peers = fetch_peers(metainfo)
            for ip, port in peers:
                try:
                    s = get_socket(ip, int(port))
                    handshake = peer_handshake(metainfo, s, True)
                    peer_id = handshake.peer_id.to_bytes(20).hex()
                    print(f"Peer ID: {peer_id}")
                    ext_id = get_metadata_ext_id(s, handshake)
                    if ext_id is not None:
                        print(f"Peer Metadata Extension ID: {ext_id}")
                    return
                except Exception as e:
                    print(e)
        case "magnet_info":
            magnet_link = sys.argv[2]
            metainfo = TorrentMetainfo.from_magnet_link(magnet_link)
            fetch_metadata_from_peer(metainfo)
            print_info(metainfo)
        case "magnet_download_piece":
            magnet_link = sys.argv[4]
            metainfo = TorrentMetainfo.from_magnet_link(magnet_link)
            fetch_metadata_from_peer(metainfo)
            piece_index = int(sys.argv[5])
            save_path = sys.argv[3]
            download_file(metainfo, save_path, piece_index)
        case "magnet_download":
            magnet_link = sys.argv[4]
            metainfo = TorrentMetainfo.from_magnet_link(magnet_link)
            fetch_metadata_from_peer(metainfo)
            save_path = sys.argv[3]
            download_file(metainfo, save_path)
        case _:
            raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()