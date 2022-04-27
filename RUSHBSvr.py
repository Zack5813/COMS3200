import socket
import os
import time

PORTNUM = 1500
MAX_FILESIZE = 1464
PORT = 23456


class RUSHBserver():
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(("127.0.0.1", PORT))
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

        return header_sqecnum, header_acknum, header_checksum, header_flags, \
               header_reverved_vercode, payload
    @staticmethod
    def carry_around_add(a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)

    def compute_checksum(self, message):
        b_str = message
        if len(b_str) % 2 == 1:
            b_str += b'\0'
        checksum = 0
        for i in range(0, len(b_str), 2):
            w = b_str[i] + (b_str[i + 1] << 8)
            checksum = self.carry_around_add(checksum, w)
        return ~checksum & 0xffff

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
        self.client[addr]['ackorder'] = 0

    def user_setfile(self, addr, filecontent):
        self.client[addr]['file'] = filecontent

    def user_setrequestorder(self, addr):
        self.client[addr]['ackorder'] += 1

    def user_setrequestorder_neg(self, addr):
        self.client[addr]['ackorder'] -= 1

    def user_setsequence(self, addr):
        self.client[addr]['sequenceNum'] += 1

    def user_setsequence_neg(self, addr):
        self.client[addr]['sequenceNum'] -= 1

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

    def user_getrequestorder(self, addr):
        return self.client[addr]['ackorder']

    def run(self):
        print(self.server.getsockname()[1])
        while True:
            try:
                data, addr = self.server.recvfrom(1500)
                sqecnum, acknum, checksum, flag, reversed_vercode, massage = self.break_package(data)

            except socket.timeout:
                for clientinfo in self.client:
                    print(clientinfo)
                    clienttime = self.client[clientinfo]['time']
                    if time.time() - clienttime > 4:
                        self.resend_packet(clientinfo)
                continue
            self.server.settimeout(1)

            if flag == '0010000' and checksum == 0:  # GET
                try:
                    request, filename = massage.split("/")
                    fileslist = os.listdir("./files")
                except ValueError:
                    print("GET request error!")
                    continue
                if filename not in fileslist:
                    print("File required not exist!!!")
                    continue
                elif filename in fileslist:
                    # Open the file and read
                    file = open(f"./files/{filename}")
                    filecontent = file.read()
                    self.creat_user(addr, filecontent, 1, 0, 0)
                    file.close()
                    self.user_setrequestorder(addr)
                    self.send_packet(1, 0, "0001000", filecontent, addr)
                    continue
                else:
                    continue

            elif flag == '0010010':  # GET/CHK
                if self.compute_checksum(massage.encode('ascii')) == checksum:
                    try:
                        request, filename = massage.split("/")
                        fileslist = os.listdir("./files")
                    except ValueError:
                        print("GET request error!")
                        continue
                    if filename not in fileslist:
                        print("File required not exist!!!")
                        continue
                    elif filename in fileslist:
                        file = open(f"./files/{filename}")
                        filecontent = file.read()
                        self.creat_user(addr, filecontent, 1, 0, 0)
                        file.close()
                        self.user_setrequestorder(addr)
                        self.send_packet(1, 0, "0001010", filecontent, addr, True)
                        continue
                    else:
                        continue

            elif flag == '1001000' and checksum == 0:  # DAT/ACK
                self.user_setsequence(addr)
                self.user_setrequestorder(addr)
                current_client_sequence = self.client[addr]['sequenceNum']
                client_finish = self.client[addr]['finish']
                # print(client_finish)
                # print(sqecnum != self.user_getrequestorder(addr))
                # print(acknum == current_client_sequence-1)
                if sqecnum != self.user_getrequestorder(addr):
                    self.resend_packet(addr)
                    self.user_setrequestorder_neg(addr)
                    self.user_setsequence_neg(addr)
                    continue
                elif acknum == current_client_sequence-1:
                    if client_finish:
                        print("Finished")
                        self.send_packet(current_client_sequence, 0, "0000100", '', addr)
                    else:
                        self.send_packet(current_client_sequence, 0, "0001000", '', addr)
                        continue
                else:
                    self.resend_packet(addr)
                    self.user_setrequestorder_neg(addr)
                    self.user_setsequence_neg(addr)
                    continue

            elif flag == '1001010':  # DAT/ACK/CHK
                self.user_setsequence(addr)
                self.user_setrequestorder(addr)
                current_client_sequence = self.client[addr]['sequenceNum']
                client_finish = self.client[addr]['finish']
                if sqecnum != self.user_getrequestorder(addr):
                    self.resend_packet(addr)
                    self.user_setrequestorder_neg(addr)
                    self.user_setsequence_neg(addr)
                    continue
                elif acknum == current_client_sequence-1 and self.compute_checksum(massage.encode('ascii')) == checksum:
                    if client_finish:
                        self.send_packet(current_client_sequence, 0, "0000110", '', addr, True)
                    else:
                        self.send_packet(current_client_sequence, 0, "0001010", '', addr, True)
                        continue
                else:
                    self.resend_packet(addr)
                    self.user_setrequestorder_neg(addr)
                    self.user_setsequence_neg(addr)
                    continue

            elif flag == '0101000' and checksum == 0:  # DAT/NAK
                self.user_setrequestorder(addr)
                current_client_sequence = self.client[addr]['sequenceNum']
                if sqecnum != self.user_getrequestorder(addr):
                    continue
                elif acknum == current_client_sequence:
                    self.user_settime(time.time(), addr)
                    self.resend_packet(addr)
                    continue
                else:
                    continue

            elif flag == '1000100' and checksum == 0:  # FIN/ACK
                self.user_setrequestorder(addr)
                self.user_setsequence(addr)
                current_client_sequence = self.client[addr]['sequenceNum']
                if sqecnum != self.user_getrequestorder(addr):
                    continue
                elif acknum == current_client_sequence-1:
                    self.send_packet(current_client_sequence, sqecnum, "1000100", '', addr)
                    continue
                else:
                    continue

            elif flag == '1000110':  # FIN/ACK/CHK
                self.user_setsequence(addr)
                self.user_setrequestorder(addr)
                current_client_sequence = self.client[addr]['sequenceNum']
                if sqecnum != self.user_getrequestorder(addr):
                    continue
                elif acknum == current_client_sequence-1 and self.compute_checksum(massage.encode('ascii')) == checksum:
                    self.send_packet(current_client_sequence, sqecnum, "1000110", '', addr, True)
                    continue
                else:
                    continue

    @staticmethod
    def generate_packet(sqecnum, acknum, checksum, flags, reserv, payload):
        header = str(bin(sqecnum)[2:]).zfill(16) + (bin(acknum)[2:]).zfill(16) + \
                 str(bin(checksum)[2:]).zfill(16) + flags + reserv
        header = bytes([int(header[i:i + 8], 2) for i in range(0, 64, 8)])
        # Generate packet
        payload_segment = payload.encode()
        if len(payload_segment) < MAX_FILESIZE:
            payload_segment += bytes(MAX_FILESIZE - len(payload))
        packet = header + payload_segment
        return packet

    def send_packet(self, sqecnum, acknum, flag, filecontent, address, checksum=False):
        # Header information
        send_sqecnum = sqecnum
        send_acknum = acknum
        send_flags = flag
        send_reverved_vercode = "000000010"
        file = self.user_getfile(address)[MAX_FILESIZE * (sqecnum - 1):]
        filelength = len(file)
        maxfilesize = 1464

        # Generate packet
        if filelength > maxfilesize:
            send_payload = file[:MAX_FILESIZE]
            if checksum:
                send_checksum = self.compute_checksum(send_payload.encode('ascii'))
            else:
                send_checksum = 0
            send_packet = self.generate_packet(send_sqecnum, send_acknum, send_checksum, send_flags,
                                               send_reverved_vercode, send_payload)

        else:
            if checksum:
                send_checksum = self.compute_checksum(file.encode('ascii'))
            else:
                send_checksum = 0
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
