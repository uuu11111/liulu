import socket
import struct
import time
import random
import sys
import threading
import zlib  # 用于CRC校验

# 报文类型常量
TYPE_CONN_REQUEST = 0  # 建立连接请求
TYPE_CONN_CONFIRM = 1  # 连接确认
TYPE_DATA = 2  # 数据报文
TYPE_ACK = 3  # 确认报文
TYPE_FIN = 4  # 连接关闭请求
TYPE_FIN_ACK = 5  # 关闭确认

# 默认参数
DEFAULT_LOSS_RATE = 0.2  # 默认丢包率(20%)
DEFAULT_CORRUPT_RATE = 0.1  # 默认数据损坏率(10%)

HEADER_FORMAT = '!BIIIIII'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

class UDPServer:
    def __init__(self, port, loss_rate=DEFAULT_LOSS_RATE, corrupt_rate=DEFAULT_CORRUPT_RATE):
        """初始化UDP服务器"""
        self.port = port
        self.loss_rate = loss_rate
        self.corrupt_rate = corrupt_rate  # 数据损坏率
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('0.0.0.0', port))
        self.clients = {}  # 客户端信息 {(ip, port): {'next_seq': 序号, 'total_bytes': 字节计数}}
        self.running = True
        print(f"服务器启动，监听端口 {port}...")
        print(f"模拟丢包率设置为 {loss_rate * 100:.1f}%")
        print(f"模拟数据损坏率设置为 {corrupt_rate * 100:.1f}%")

    def parse_packet(self, data):
        """解析收到的数据包，验证校验和"""
        if len(data) < HEADER_SIZE:
            return None, None, None, None, None, None, None
        # 解析报文头
        header = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        type_val = header[0]
        seq = header[1]
        length = header[2]
        client_timestamp = header[3]  # 客户端时间戳（毫秒）
        start_byte = header[4]
        end_byte = header[5]
        checksum = header[6]
        # 解析数据部分，使用 'replace' 处理解码错误
        payload = data[HEADER_SIZE:].decode('utf-8', errors='replace') if length > 0 else ""

        # 验证数据包校验和（连接请求和关闭请求除外）
        if type_val not in (TYPE_CONN_REQUEST, TYPE_FIN):
            # 构造不含校验和的数据包（去掉最后4字节校验和）
            packet_without_checksum = data[:HEADER_SIZE - 4] + data[HEADER_SIZE:]
            calculated_checksum = zlib.crc32(packet_without_checksum)
            if checksum != calculated_checksum:
                return None, None, None, None, None, None, None

        return type_val, seq, length, client_timestamp, start_byte, end_byte, payload

    def create_ack(self, seq, start_byte, end_byte):
        """创建确认报文，原填充字段存放校验和"""
        # 确保参数合法
        if start_byte < 0:
            start_byte = 0
        if end_byte < start_byte:
            end_byte = start_byte
        # 服务器时间戳（毫秒）
        server_timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        # 构造前6个字段
        header_base = struct.pack('!BIIIII',  # Type, Seq, Length, Timestamp, start, end
                                  TYPE_ACK, seq, 0, server_timestamp, start_byte, end_byte)
        packet = header_base  # ACK无数据部分
        # 计算CRC32校验和
        checksum = zlib.crc32(packet)
        # 打包完整头部（含校验和）
        header = struct.pack(HEADER_FORMAT,
                             TYPE_ACK, seq, 0, server_timestamp, start_byte, end_byte, checksum)
        print(f"创建ACK: seq={seq}, bytes={start_byte}-{end_byte}")
        return header

    def create_conn_confirm(self, seq):
        """创建连接确认报文，原填充字段存放校验和"""
        server_timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        # 构造前6个字段
        header_base = struct.pack('!BIIIII', TYPE_CONN_CONFIRM, seq, 0, server_timestamp, 0, 0)
        packet = header_base
        checksum = zlib.crc32(packet)
        # 打包完整头部
        header = struct.pack(HEADER_FORMAT,
                             TYPE_CONN_CONFIRM, seq, 0, server_timestamp, 0, 0, checksum)
        print(f"创建CONN_CONFIRM: seq={seq}")
        return header

    def create_fin_ack(self, seq):
        """创建关闭连接确认报文，原填充字段存放校验和"""
        server_timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        # 构造前6个字段
        header_base = struct.pack('!BIIIII', TYPE_FIN_ACK, seq, 0, server_timestamp, 0, 0)
        packet = header_base
        checksum = zlib.crc32(packet)
        # 打包完整头部
        header = struct.pack(HEADER_FORMAT,
                             TYPE_FIN_ACK, seq, 0, server_timestamp, 0, 0, checksum)
        print(f"创建FIN_ACK: seq={seq}")
        return header

    def should_drop_packet(self):
        """决定是否丢弃数据包"""
        return random.random() < self.loss_rate

    def should_corrupt_packet(self):
        """决定是否损坏数据包"""
        return random.random() < self.corrupt_rate

    def handle_client(self, data, addr):
        """处理客户端请求，包含数据损坏"""
        original_data = data  # 保存原始数据
        seq = -1

        # 解析原始数据包的序列号
        if len(original_data) >= HEADER_SIZE:
            try:
                original_header = struct.unpack(HEADER_FORMAT, original_data[:HEADER_SIZE])
                seq = original_header[1]
            except:
                pass

        # 模拟数据损坏
        if self.should_corrupt_packet():
            print(f"[数据损坏] 模拟修改客户端 {addr} 的数据包 seq={seq}")
            # 转换为可变->修改
            data_list = bytearray(data)
            while True:
                corrupt_pos = random.randint(0, len(data_list) - 1)
                if not (HEADER_SIZE - 4 <= corrupt_pos <= HEADER_SIZE - 1):  # 避开校验和字段
                    break
            data_list[corrupt_pos] ^= 0xFF  # 翻转字节
            data = bytes(data_list)

        # 解析数据包（含校验和验证）
        result = self.parse_packet(data)
        if result[0] is None:
            print(f"[数据损坏] 客户端 {addr} 的数据包 seq={seq} 因校验错误被丢弃")
            return

        type_val, seq, length, client_timestamp, start_byte, end_byte, payload = result

        if type_val == TYPE_CONN_REQUEST:
            if addr not in self.clients:
                self.clients[addr] = {'next_seq': seq + 1, 'last_ack': 0, 'total_bytes': 0}
            confirm = self.create_conn_confirm(seq + 1)
            self.socket.sendto(confirm, addr)
            print(f"收到来自 {addr} 的连接请求 (seq={seq})，已回复确认 (seq={seq + 1})")
        elif type_val == TYPE_DATA:
            if addr not in self.clients:
                print(f"收到来自未知客户端 {addr} 的数据，已忽略")
                return
            client_info = self.clients[addr]
            expected_seq = client_info['next_seq']
            print(f"收到来自 {addr} 的数据包: seq={seq}, expected={expected_seq}, "
                  f"length={length}, bytes={start_byte}-{end_byte}")
            # 随机决定是否丢弃数据包
            if self.should_drop_packet():
                print(f"[模拟丢包] 丢弃来自 {addr} 的数据包 (seq={seq})")
                return
            if seq == expected_seq:
                # 更新字节计数
                client_info['total_bytes'] = end_byte + 1
                print(f"处理数据包 seq={seq}, 长度={length}字节 (字节范围: {start_byte}~{end_byte})")
                client_info['next_seq'] += 1
                # 创建ACK，包含字节范围信息
                ack = self.create_ack(client_info['next_seq'], start_byte, end_byte)
                self.socket.sendto(ack, addr)
                print(f"发送ACK: seq={client_info['next_seq']}, bytes={start_byte}-{end_byte}")
            else:
                # 乱序包丢弃，只重发上次ACK
                last_ack = client_info['next_seq']
                last_bytes = client_info['total_bytes']
                # 确保start_byte不小于0
                ack_start = max(0, last_bytes - 1)
                ack_end = last_bytes
                ack = self.create_ack(last_ack, ack_start, ack_end)
                self.socket.sendto(ack, addr)
                print(f"数据包乱序，期望seq={expected_seq}，收到seq={seq}，重发ACK={last_ack}, "
                      f"bytes={ack_start}-{ack_end}")
        elif type_val == TYPE_FIN:
            fin_ack = self.create_fin_ack(seq + 1)
            self.socket.sendto(fin_ack, addr)
            print(f"收到来自 {addr} 的连接关闭请求（FIN），已回复FIN-ACK")
            if addr in self.clients:
                del self.clients[addr]

    def run(self):
        """运行服务器"""
        try:
            while self.running:
                data, addr = self.socket.recvfrom(1024)
                # 创建新线程处理客户端请求
                client_thread = threading.Thread(target=self.handle_client, args=(data, addr))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\n服务器正在关闭...")
        except Exception as e:
            print(f"服务器运行出错: {e}")
        finally:
            self.socket.close()
            print("服务器已关闭")

    def stop(self):
        """停止服务器"""
        self.running = False
        self.socket.close()


def print_usage():
    """打印使用说明"""
    print("使用方法: python udpserver.py <port> [loss_rate] [corrupt_rate]")
    print("参数说明:")
    print("  port: 服务器监听端口")
    print("  loss_rate: 模拟丢包率(0.0-1.0，默认0.2)")
    print("  corrupt_rate: 模拟数据损坏率(0.0-1.0，默认0.01)")
    print("示例: python udpserver.py 8888 0.3 0.05")


def main():
    random.seed(time.time())
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        print_usage()
        sys.exit(1)
    try:
        port = int(sys.argv[1])
        if port < 1 or port > 65535:
            print("错误: 端口号必须在1-65535之间")
            sys.exit(1)
        # 解析丢包率和损坏率参数
        loss_rate = DEFAULT_LOSS_RATE
        corrupt_rate = DEFAULT_CORRUPT_RATE
        if len(sys.argv) >= 3:
            loss_rate = float(sys.argv[2])
            if loss_rate < 0.0 or loss_rate > 1.0:
                print("错误: 丢包率必须在0.0-1.0之间")
                sys.exit(1)
        if len(sys.argv) == 4:
            corrupt_rate = float(sys.argv[3])
            if corrupt_rate < 0.0 or corrupt_rate > 1.0:
                print("错误: 数据损坏率必须在0.0-1.0之间")
                sys.exit(1)
        # 创建并运行服务器
        server = UDPServer(port, loss_rate, corrupt_rate)
        server.run()
    except ValueError:
        print("错误: 端口号必须是整数，丢包率和损坏率必须是小数")
        print_usage()
        sys.exit(1)
    except Exception as e:
        print(f"发生错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()