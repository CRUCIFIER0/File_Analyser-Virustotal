from scapy.all import *
import zlib
import uuid
import re
import sys


def stripurl_pcap(pcap, output_path):
    a = rdpcap(pcap)
    sessions = a.sessions()
    fd = open(output_path, "wb")
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80:
                    payload = bytes(packet[TCP].payload)
                    url_path = payload[payload.index(b"GET ")+4:payload.index(b" HTTP/1.1")].decode("utf8")
                    http_header_raw = payload[:payload.index(b"\r\n\r\n")+2]
                    http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                    url = http_header_parsed["Host"] + url_path + "\n"
                    fd.write(url.encode())
            except:
                pass
    fd.close()



'''def extract_payload(http_headers, payload, output_path):
    payload_type = http_headers["Content-Type"].split("/")[1].split(";")[0]
    try:
        if "Content-Encoding" in http_headers.keys():
            if http_headers["Content-Encoding"] == "gzip":
                file = zlib.decompress(payload, 16+zlib.MAX_WBITS)
            elif http_headers["Content-Encoding"] == "deflate":
                file = zlib.decompress(payload)
            else:
                file = payload
        else:
            file = payload
    except:
        pass

    filename = uuid.uuid4().hex + "." + payload_type
    file_path = output_path + "/" + filename
    fd = open(file_path, "wb")
    fd.write(file)
    fd.close()'''
    
    
