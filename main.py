def read_txt_files(file):
    with open("tcp_data/tcp_addrs_" + str(file) + ".txt","r") as r:
      return r.read().split()
   
def dots_and_numbers_to_bytestring(ip_numb):
    split_ip_to_numb = [int(num).to_bytes(1, 'big')for num in ip_numb.split(".")]
    return b''.join(split_ip_to_numb)

def read_dat_files(file):
    with open("tcp_data/tcp_data_" + str(file) + ".dat", "rb") as f:
        return f.read()

def create_ip_pseudo_header(source_addr, destination_addr, tcp_length):
    length_into_bytes = tcp_length.to_bytes(2, byteorder ='big')
    return source_addr + destination_addr + b'\x00' + b'\x06' + length_into_bytes

def get_tcp_length(data):
    return len(data)

def gen_zero_checksum(data):
    get_checksum =  int.from_bytes(data[16:18], byteorder='big')
    zero_checksum = data[:16] + b'\x00\x00' + data[18:]
    if len(zero_checksum) % 2 == 1:
        zero_checksum += b'\x00'
    return zero_checksum, get_checksum

def calculate_checksum(pseudo_header, tcp_data):
    data = pseudo_header + tcp_data
    offset = 0
    total = 0
    while offset < len(data):
        word = int.from_bytes(data[offset:offset + 2], "big")
        total += word
        total = (total & 0xffff) + (total >> 16)
        offset += 2
    return (~total) & 0xffff
    
def iterate_over_files():
    for i in range(10):
        src, dest = read_txt_files(i)
        src_ip = dots_and_numbers_to_bytestring(src)
        tcp_data = read_dat_files(i)

        length = get_tcp_length(tcp_data)
        zero_checksum, data = gen_zero_checksum(tcp_data)
        dest_ip = dots_and_numbers_to_bytestring(dest)

        pseudo_header = create_ip_pseudo_header(src_ip, dest_ip, length)
        calc_checksum = calculate_checksum(pseudo_header, zero_checksum)
        zero_checksum, data = gen_zero_checksum(tcp_data)

        if data == calc_checksum:
            print('PASS')
        else:
            print('FAIL')

iterate_over_files()