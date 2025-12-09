import pyshark

capture = pyshark.FileCapture('sample2.pcapng')
for i, packet in enumerate(capture):
    if i >= 5:
        break
    print(packet)