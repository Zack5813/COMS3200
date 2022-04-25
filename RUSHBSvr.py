import socket
import os
import time

PORTNUM = 1500
MAX_FILESIZE = 1464


class RUSHBserver():
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(("127.0.0.1", 0))
        self.client = {}

    @staticmethod
    def break_package(data):
        # Break packet from client
        header = data.rstrip(b'\x00')
        header_sqecnum = int.from_bytes(header[0:2], byteorder='big')
        header_acknum = int.from_bytes(header[2:4], byteorder='big')
        header_checksum = int.from_bytes(header[4:6], byteorder='big')
        header_flags = bin(header[6])[2:].zfill(8)[:7]
        header_reverved_vercode = bin(header[7])[2:].zfill(9)
        payload = header[8:].decode()

        print("Header information:", header)
        print("Squence Number:", header_sqecnum)
        print("Acknowlegement Number:", header_acknum)
        print("Checksum:", header_checksum)
        print("Flags:", header_flags)
        print("Reserved and version code:", header_reverved_vercode)
        print("Flags:", header_flags)
        print("Payload information:", payload, '\n')

        return header_sqecnum, header_acknum, header_checksum, header_flags, \
               header_reverved_vercode, payload

    def creat_user(self, addr, filecontent, sequence, acknowlege, checksum):
        self.client[addr] = {}
        self.client[addr]['address'] = addr
        self.client[addr]['file'] = filecontent
        self.client[addr]['sequenceNum'] = sequence
        self.client[addr]['ackNum'] = acknowlege
        self.client[addr]['checksum'] = checksum
        self.client[addr]['finish'] = False
        self.client[addr]['time'] = None
        self.client[addr]['packet'] = None
        print("USER ", addr, "created with", self.client[addr]['file'], self.client[addr]['sequenceNum'], \
              self.client[addr]['ackNum'], self.client[addr]['checksum'])

    def user_setfile(self, addr, filecontent):
        self.client[addr]['file'] = filecontent
        print('User file updated!')

    def user_setsequence(self, addr):
        self.client[addr]['sequenceNum'] += 1
        print('User sequence number:', self.client[addr]['sequenceNum'])

    def user_setfinish(self, addr):
        self.client[addr]['finish'] = True

    def user_settime(self, current_time, addr):
        self.client[addr]['time'] = current_time

    def user_setpacket(self, packet, addr):
        self.client[addr]['packet'] = packet

    def user_getfile(self, addr):
        return self.client[addr]['file']

    def user_getpacket(self, addr):
        return self.client[addr]['packet']

    def user_gettime(self, addr):
        return self.client[addr]['time']

    def run(self):
        print(self.server.getsockname()[1])
        while True:
            try:
                data, addr = self.server.recvfrom(1500)
                sqecnum, acknum, checksum, flag, reversed_vercode, massage = self.break_package(data)
            except:
                if time.time() - self.user_gettime(addr) > 4:
                    self.resend_packet(addr)
                continue

            if flag == '0010000':  # GET
                try:
                    request, filename = massage.split("/")
                    fileslist = os.listdir("./files")
                    print("System files:", fileslist)
                    print("Get request type:", request)
                    print("File name:", filename, '\n')
                except ValueError:
                    print("GET request error!")
                    continue
                if filename not in fileslist:
                    print("File required not exist!!!")
                    continue
                elif filename in fileslist:
                    # Open the file and read
                    print('Send DAT')
                    file = open(f"./files/{filename}")
                    filecontent = file.read()
                    self.creat_user(addr, filecontent, 1, 0, 0)
                    file.close()
                    self.send_packet(1, 0, "0001000", filecontent, addr)
                    continue
                else:
                    continue

            if flag == '1001000':  # DAT/ACK
                print('Send DAT or FIN')
                current_client_sequence = self.client[addr]['sequenceNum']
                client_finish = self.client[addr]['finish']
                if acknum != current_client_sequence:
                    continue
                elif acknum == current_client_sequence:
                    if client_finish:
                        self.user_setsequence(addr)
                        self.send_packet(current_client_sequence + 1, 0, "0000100", '', addr)
                    else:
                        self.user_setsequence(addr)
                        self.send_packet(current_client_sequence + 1, 0, "0001000",
                                         filecontent[(MAX_FILESIZE * (sqecnum)):], addr)
                        continue
                else:
                    continue

            if flag == '0101000':  # DAT/NAK
                print('Send DAT repeat')
                self.user_settime(time.time(), addr)
                current_client_sequence = self.client[addr]['sequenceNum']
                current_client_file = self.client[addr]['file']
                if acknum == current_client_sequence:
                    self.send_packet(current_client_sequence, 0, "0001000", current_client_file, addr)
                    continue

            if flag == '1000100':  # FIN/ACK
                print('Send FIN/ACK')
                current_client_sequence = self.client[addr]['sequenceNum']
                if acknum == current_client_sequence:
                    self.user_setsequence(addr)
                    self.send_packet(current_client_sequence + 1, sqecnum, "1000100", '', addr)
                    continue
                else:
                    continue

    @staticmethod
    def generate_packet(sqecnum, acknum, checksum, flags, reserv, payload):
        header = str(bin(sqecnum)[2:]).zfill(16) + (bin(acknum)[2:]).zfill(16) + \
                 str(checksum).zfill(16) + flags + reserv
        print("header info", header)
        header = bytes([int(header[i:i + 8], 2) for i in range(0, 64, 8)])
        # Generate packet
        payload_segment = payload.encode()
        if len(payload_segment) < MAX_FILESIZE:
            payload_segment += bytes(MAX_FILESIZE - len(payload))
        packet = header + payload_segment
        print('Send packet:', packet)
        return packet

    def send_packet(self, sqecnum, acknum, flag, filecontent, address):
        # Header information
        send_sqecnum = sqecnum
        send_acknum = acknum
        send_checksum = 0
        send_flags = flag
        send_reverved_vercode = "000000010"
        file = self.user_getfile(address)[MAX_FILESIZE * (sqecnum - 1):]
        filelength = len(file)
        maxfilesize = 1464

        # Generate packet
        if filelength > maxfilesize:
            print("File size over!!!!!!!")
            send_payload = file[:MAX_FILESIZE]
            send_packet = self.generate_packet(send_sqecnum, send_acknum, send_checksum, send_flags,
                                               send_reverved_vercode, send_payload)

        else:
            print("File size not over")
            print(file)
            send_packet = self.generate_packet(send_sqecnum, send_acknum, send_checksum, send_flags,
                                               send_reverved_vercode, file)
            self.user_setfinish(address)

        # Send packet
        self.user_settime(time.time(), address)
        self.user_setpacket(send_packet, address)
        self.server.sendto(send_packet, address)

    def resend_packet(self, addr):
        resend_packet_info = self.user_getpacket(addr)
        self.user_settime(time.time(), addr)
        self.server.sendto(resend_packet_info, addr)


if __name__ == '__main__':
    RUSHBserver().run()
