import json
import sys
import hashlib
import bencodepy
# import requests - available if you need it!
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
bc = bencodepy.Bencode(encoding="utf-8")
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        length = int(bencoded_value.split(b":")[0])
        return bencoded_value.split(b":")[1][:length]
    elif bencoded_value.startswith(b"i"):
        return int(bencoded_value[1:-1])
    elif bencoded_value.startswith(b"l"):  # list -> l5:helloi52ee = ['hello', 52]
        return bc.decode(bencoded_value)
    elif bencoded_value.startswith(b"d"):  # dictionary -> d5:helloi52ee = {'hello': 52}
        return bc.decode(bencoded_value)
    else:
        raise NotImplementedError("Only strings are supported at the moment")
def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    elif isinstance(data, int):
        return data
    elif isinstance(data, list):
        return [bytes_to_str(item) for item in data]
    elif isinstance(data, dict):
        return {bytes_to_str(k): bytes_to_str(v) for k, v in data.items()}
    else:
        raise TypeError(f"Type not serializable: {type(data)}")
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
        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        torrent_file_path = sys.argv[2]
        with open(torrent_file_path, "rb") as file:
            content = file.read()
        decoded_content = bencodepy.decode(content)
        info = bytes_to_str(decoded_content)
        info_hash = hashlib.sha1(bencodepy.encode(decoded_content[b"info"])).hexdigest()
        print(f'Tracker URL: {info["announce"]}')
        print(f'Length: {info["info"]["length"]}')
        print(f"Info Hash: {info_hash}")
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()