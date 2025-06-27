import socket
import struct
import time
import random
import sys
import pandas as pd
import threading
import zlib  # 用于CRC校验

# 报文类型常量
TYPE_CONN_REQUEST = 0  # 建立连接请求
TYPE_CONN_CONFIRM = 1  # 连接确认
TYPE_DATA = 2  # 数据报文
TYPE_ACK = 3  # 确认报文
TYPE_FIN = 4  # 连接关闭请求
TYPE_FIN_ACK = 5  # 关闭确认

DEFAULT_TIMEOUT = 300  # 超时时间(毫秒)
DEFAULT_WINDOW_SIZE = 400  # 窗口大小(字节)
DEFAULT_MIN_PACKET_SIZE = 40  # 最小数据包大小(字节)
DEFAULT_MAX_PACKET_SIZE = 80  # 最大数据包大小(字节)
DEFAULT_PACKET_COUNT = 30  # 默认发送的数据包数量

HEADER_FORMAT = '!BIIIIII'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class UDPClient:
    def __init__(self, server_ip, server_port, timeout=DEFAULT_TIMEOUT):
        """初始化UDP客户端"""
        self.server_ip = server_ip
        self.server_port = server_port
        self.timeout = timeout / 1000.0  # 转换为秒
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(self.timeout)
        self.seq_num = 0  # 初始序列号
        self.window_bytes = DEFAULT_WINDOW_SIZE  # 窗口大小
        self.min_packet_size = DEFAULT_MIN_PACKET_SIZE  # 最小数据包大小
        self.max_packet_size = DEFAULT_MAX_PACKET_SIZE  # 最大数据包大小

        self.sent_packets = {}  # 已发送但未确认的数据包 {seq_num: (send_time, data, retries, start_byte, end_byte)}
        self.acked_packets = {}  # 已确认的数据包 {seq_num: rtt}

        self.rtt_values = []  # RTT值列表，用于统计
        self.total_sent = 0  # 总共发送的数据包数(包括重传)
        self.total_retries = 0  # 总共重传的次数
        self.is_connected = False  # 连接状态
        self.total_bytes_sent = 0  # 累计发送的字节数

        self.lock = threading.Lock()  # 线程锁，用于保护共享数据
        self.stop_event = threading.Event()  # 用于停止超时检测线程

        self.base = 0  # 窗口基准
        self.nextseqnum = 0  # 下一个可用序号
        self.current_window_bytes = 0  # 当前窗口已使用字节数
        self.estimated_rtt = 0.3  # 初始RTT估计（秒）
        self.dev_rtt = 0.0  # RTT偏差
        self.alpha = 0.125  # RTT平滑因子
        self.beta = 0.25  # 偏差平滑因子

        # 快重传相关变量
        self.dup_ack_count = 0  # 重复ACK计数器
        self.last_ack_seq = -1  # 上一个ACK的序列号
        self.fast_retransmit_enabled = True  # 快重传功能开关
        self.fast_retransmit_count = 0  # 快重传触发次数计数器

    def connect(self):
        """建立与服务器的逻辑连接"""
        print(f"正在连接服务器 {self.server_ip}:{self.server_port}...")
        # 构造连接请求报文（timestamp为客户端当前时间戳，毫秒，截断为4字节）
        client_timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        # 连接请求包的校验和设为0（服务器忽略校验）
        header = struct.pack(HEADER_FORMAT,
                             TYPE_CONN_REQUEST,  # Type
                             self.seq_num,  # Seq
                             0,  # Length
                             client_timestamp,  # 客户端时间戳（毫秒）
                             0,  # start_byte
                             0,  # end_byte
                             0)  # 校验和设为0
        # 发送连接请求
        self.socket.sendto(header, (self.server_ip, self.server_port))
        try:
            # 等待连接确认
            data, addr = self.socket.recvfrom(1024)
            if len(data) < HEADER_SIZE:
                print("连接建立失败：收到的确认报文格式不正确")
                return False
            # 解析报文头，获取服务器的时间戳（header[3]）
            header = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
            type_val = header[0]
            seq = header[1]
            server_timestamp_ms = header[3]  # 服务器时间戳（毫秒）
            if type_val == TYPE_CONN_CONFIRM and seq == self.seq_num + 1:
                self.seq_num = seq  # 更新序列号
                self.is_connected = True
                # 解析服务器时间
                server_time_sec = server_timestamp_ms / 1000
                server_time_str = time.strftime('%H-%M-%S', time.localtime(server_time_sec))
                print(f"连接建立成功，服务器系统时间: {server_time_str}")
                return True
            else:
                print(f"连接建立失败：收到无效的确认报文 (type={type_val}, seq={seq})")
                return False
        except socket.timeout:
            print("连接建立失败：等待确认超时")
            return False
        except Exception as e:
            print(f"连接建立失败：{e}")
            return False

    def create_packet(self, type_val, seq_num, data, start_byte, end_byte):
        """创建数据报文，原填充字段存放校验和"""
        # 客户端时间戳（毫秒），截断为4字节
        client_timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        # 构造不含校验和的头部（前6个字段）
        header_base = struct.pack('!BIIIII',  # Type, Seq, Length, Timestamp, start, end
                                  type_val, seq_num, len(data), client_timestamp, start_byte, end_byte)
        packet = header_base + data.encode('utf-8') if type_val == TYPE_DATA else header_base
        # 计算CRC32校验和（覆盖整个数据包）
        checksum = zlib.crc32(packet)
        # 重新打包头部（包含校验和，即原填充字段）
        header = struct.pack(HEADER_FORMAT,
                             type_val, seq_num, len(data), client_timestamp, start_byte, end_byte, checksum)
        return header + data.encode('utf-8') if type_val == TYPE_DATA else header

    def parse_ack(self, data):
        """解析确认报文，验证校验和并处理数据损坏"""
        if len(data) < HEADER_SIZE:
            return None, None, None, None
        header = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        type_val, seq, _, server_timestamp_ms, start_byte, end_byte, checksum = header

        # 验证ACK包的校验和（仅在数据传输阶段验证）
        if type_val == TYPE_ACK:
            packet_without_checksum = data[:HEADER_SIZE - 4] + data[HEADER_SIZE:]
            calculated_checksum = zlib.crc32(packet_without_checksum)
            if checksum != calculated_checksum:
                print(f"[数据损坏] 收到校验错误的ACK seq={seq}，已忽略")
                return None, None, None, None

        if type_val != TYPE_ACK:
            return None, None, None, None
        return seq, server_timestamp_ms, start_byte, end_byte

    def timeout_checker(self):
        """超时检测线程，添加数据损坏相关日志"""
        while not self.stop_event.is_set():
            current_time = time.perf_counter()
            with self.lock:
                # GBN: 只检查base包是否超时，超时重传base及之后所有未确认包
                if self.base in self.sent_packets:
                    send_time, data, retries, start_byte, end_byte = self.sent_packets[self.base]
                    if current_time - send_time > self.timeout:
                        print(f"检测到超时，重传窗口内数据包 [{self.base}~{self.nextseqnum - 1}] "
                              f"(可能因数据损坏或丢包)")
                        # 重置窗口计数器
                        self.current_window_bytes = 0
                        # 重传所有未确认包
                        for seq in range(self.base, self.nextseqnum):
                            if seq in self.sent_packets:
                                # 获取包信息
                                _, data, retries, start_byte, end_byte = self.sent_packets[seq]
                                # 创建并发送数据包
                                packet = self.create_packet(TYPE_DATA, seq, data, start_byte, end_byte)
                                self.socket.sendto(packet, (self.server_ip, self.server_port))
                                # 更新重传计数
                                self.sent_packets[seq] = (
                                    time.perf_counter(),
                                    data,
                                    retries + 1,
                                    start_byte,
                                    end_byte
                                )
                                self.total_sent += 1
                                self.total_retries += 1
                                # 打印重传日志（包含字节范围）
                                print(f"超时重传第 {seq} 个（第 {start_byte}~{end_byte} 字节）数据包")
                                # 更新窗口字节计数
                                self.current_window_bytes += (end_byte - start_byte + 1)
                        # 重置超时计时器
                        self.sent_packets[self.base] = (
                            time.perf_counter(),
                            self.sent_packets[self.base][1],
                            self.sent_packets[self.base][2] + 1,
                            self.sent_packets[self.base][3],
                            self.sent_packets[self.base][4]
                        )
            # 每50ms检查一次
            time.sleep(0.05)

    def send_data(self, packet_count=DEFAULT_PACKET_COUNT):
        """发送指定数量的数据包"""
        if not self.is_connected:
            print("错误：未建立连接")
            return False
        print(f"开始发送{packet_count}个数据包...")
        print(f"窗口大小: {self.window_bytes}字节")
        print(f"快重传功能: {'启用' if self.fast_retransmit_enabled else '禁用'}")
        # 启动超时检测线程
        timeout_thread = threading.Thread(target=self.timeout_checker)
        timeout_thread.daemon = True
        timeout_thread.start()
        start_time = time.perf_counter()
        try:
            while self.base < packet_count:
                with self.lock:
                    # GBN: 只要窗口未满就发新包
                    while (self.nextseqnum < packet_count and
                           self.current_window_bytes < self.window_bytes):
                        # 确定数据包大小（确保不超过窗口剩余空间）
                        max_possible_size = min(
                            self.max_packet_size,
                            self.window_bytes - self.current_window_bytes
                        )
                        # 确保数据包大小在有效范围内
                        if max_possible_size < self.min_packet_size:
                            break  # 窗口空间不足以发送最小数据包
                        data_size = random.randint(
                            self.min_packet_size,
                            max_possible_size
                        )
                        # 计算字节范围
                        start_byte = self.total_bytes_sent
                        end_byte = start_byte + data_size - 1
                        # 创建数据内容
                        data = f"数据包-{self.nextseqnum}-内容-{'X' * (data_size - 20)}"
                        # 创建数据包（timestamp为客户端时间戳）
                        packet = self.create_packet(TYPE_DATA, self.nextseqnum, data, start_byte, end_byte)
                        # 发送数据包，记录发送时间（perf_counter，秒）
                        send_time = time.perf_counter()
                        self.socket.sendto(packet, (self.server_ip, self.server_port))
                        # 存储发送信息
                        self.sent_packets[self.nextseqnum] = (send_time, data, 0, start_byte, end_byte)
                        # 打印发送日志（包含字节范围）
                        print(f"发送第 {self.nextseqnum} 个（第 {start_byte}~{end_byte} 字节）数据包")
                        # 更新计数
                        self.nextseqnum += 1
                        self.total_sent += 1
                        self.total_bytes_sent = end_byte + 1
                        self.current_window_bytes += data_size
                # 尝试接收ACK
                try:
                    data, addr = self.socket.recvfrom(1024)
                    ack_seq, server_timestamp_ms, ack_start_byte, ack_end_byte = self.parse_ack(data)
                    if ack_seq is not None:
                        with self.lock:
                            recv_time = time.perf_counter()
                            # 快重传
                            if self.fast_retransmit_enabled:
                                if ack_seq == self.last_ack_seq:
                                    self.dup_ack_count += 1
                                    print(f"收到重复ACK {ack_seq} (计数: {self.dup_ack_count})")
                                    # 当收到3个重复ACK时触发快重传
                                    if self.dup_ack_count == 3:
                                        print(f"触发快重传：收到3个重复ACK {ack_seq}")
                                        # 仅重传base包（即当前窗口的第一个包）
                                        if self.base in self.sent_packets:
                                            send_time, data, retries, start_byte, end_byte = self.sent_packets[self.base]
                                            # 创建并发送数据包
                                            packet = self.create_packet(TYPE_DATA, self.base, data, start_byte,end_byte)
                                            self.socket.sendto(packet, (self.server_ip, self.server_port))
                                            # 更新重传计数
                                            self.sent_packets[self.base] = (
                                                time.perf_counter(),
                                                data,
                                                retries + 1,
                                                start_byte,
                                                end_byte
                                            )
                                            self.total_sent += 1
                                            self.total_retries += 1
                                            # 增加快重传计数
                                            self.fast_retransmit_count += 1
                                            # 打印重传日志
                                            print(f"快重传第 {self.base} 个（第 {start_byte}~{end_byte} 字节）数据包")
                                        # 重置重复ACK计数
                                        self.dup_ack_count = 0
                                else:
                                    # 收到新的ACK，重置重复ACK计数
                                    self.dup_ack_count = 0
                                    self.last_ack_seq = ack_seq
                            # 处理ACK，计算RTT和服务器时间
                            # 更新已确认的数据包
                            for seq in list(self.sent_packets.keys()):
                                if seq < ack_seq:
                                    send_time, data, retries, start_byte, end_byte = self.sent_packets[seq]
                                    # 计算RTT（毫秒）
                                    rtt = (recv_time - send_time) * 1000
                                    # 解析服务器时间
                                    server_time_sec = server_timestamp_ms / 1000
                                    server_time_str = time.strftime('%H-%M-%S', time.localtime(server_time_sec))
                                    # 存储RTT值
                                    self.acked_packets[seq] = rtt
                                    self.rtt_values.append(rtt)
                                    # 打印日志：RTT和服务器系统时间
                                    print(f"第 {seq} 个（第 {start_byte}~{end_byte} 字节）server端已经收到，RTT 是 {rtt:.4f} ms，服务器系统时间: {server_time_str}")
                                    # 从已发送列表中移除
                                    del self.sent_packets[seq]
                                    # 更新窗口字节计数
                                    self.current_window_bytes -= (end_byte - start_byte + 1)
                                    # RTT动态调整超时
                                    if self.estimated_rtt == 0.3:
                                        self.estimated_rtt = rtt / 1000.0
                                        self.dev_rtt = (rtt / 1000.0) / 2
                                    else:
                                        rtt_s = rtt / 1000.0
                                        self.estimated_rtt = (1 - self.alpha) * self.estimated_rtt + self.alpha * rtt_s
                                        self.dev_rtt = (1 - self.beta) * self.dev_rtt + self.beta * abs(
                                            rtt_s - self.estimated_rtt)
                                    # 更新超时时间（至少100ms）
                                    self.timeout = max(0.1, (self.estimated_rtt + 4 * self.dev_rtt))
                            # 更新窗口基准
                            self.base = max(self.base, ack_seq)
                except socket.timeout:
                    pass
                except Exception as e:
                    print(f"接收ACK时出错: {e}")
            # 所有数据包发送完成
            self.stop_event.set()
            timeout_thread.join()
            # 等待所有ACK
            end_time = time.time() + 2.0  # 最多等待2秒
            while time.time() < end_time and self.sent_packets:
                try:
                    data, addr = self.socket.recvfrom(1024)
                    ack_seq, server_timestamp_ms, ack_start_byte, ack_end_byte = self.parse_ack(data)
                    if ack_seq is not None:
                        with self.lock:
                            # 更新已确认的数据包
                            for seq in list(self.sent_packets.keys()):
                                if seq < ack_seq:
                                    send_time, data, retries, start_byte, end_byte = self.sent_packets[seq]
                                    rtt = (time.perf_counter() - send_time) * 1000
                                    # 解析服务器时间
                                    server_time_sec = server_timestamp_ms / 1000
                                    server_time_str = time.strftime('%H-%M-%S', time.localtime(server_time_sec))
                                    self.acked_packets[seq] = rtt
                                    self.rtt_values.append(rtt)
                                    del self.sent_packets[seq]
                                    print(f"第 {seq} 个（第 {start_byte}~{end_byte} 字节）server端已经收到，RTT 是 {rtt:.4f} ms，服务器系统时间: {server_time_str}")
                except(socket.timeout, ConnectionError) as e:
                    print(f"网络错误: {e}")
                except struct.error as e:
                    print(f"数据解析错误: {e}")
                except Exception as e:
                    print(f"未预期的错误: {e}")
                    raise  # 考虑重新抛出真正意外的异常
            print("所有数据包发送完成")
            elapsed = time.perf_counter() - start_time
            print(f"数据传输完成，耗时：{elapsed:.4f} 秒\n")
            self.print_statistics()
            return True
        except Exception as e:
            print(f"发送数据时出错: {e}")
            self.stop_event.set()
            if timeout_thread.is_alive():
                timeout_thread.join()
            return False

    def print_statistics(self):
        """打印统计信息"""
        print("\n=== 传输统计 ===")
        # 计算丢包率
        loss_rate = (DEFAULT_PACKET_COUNT / self.total_sent) * 100 if self.total_sent > 0 else 0
        print(f"丢包率：{loss_rate:.2f}%")
        print(f"总发送包数：{self.total_sent} (包括重传)")
        print(f"重传次数：{self.total_retries}")
        print(f"成功发送包数：{len(self.acked_packets)}")
        print(f"总发送字节数：{self.total_bytes_sent}")
        # 使用独立的计数器来显示快重传次数
        print(f"快重传触发次数：{self.fast_retransmit_count}")
        # 使用pandas计算RTT统计量
        if self.rtt_values:
            rtt_series = pd.Series(self.rtt_values)
            print(f"最小RTT：{rtt_series.min():.4f} ms")
            print(f"最大RTT：{rtt_series.max():.4f} ms")
            print(f"平均RTT：{rtt_series.mean():.4f} ms")
            print(f"RTT标准差：{rtt_series.std():.4f} ms")
        else:
            print("没有收集到RTT数据")

    def close(self):
        """优雅关闭连接，发送FIN并等待FIN-ACK"""
        # 客户端时间戳（毫秒），截断为4字节
        client_timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        # 关闭请求包的校验和设为0（服务器忽略校验）
        fin_header = struct.pack(HEADER_FORMAT,
                                 TYPE_FIN,
                                 self.seq_num,
                                 0,
                                 client_timestamp,
                                 0,
                                 0,
                                 0)
        self.socket.sendto(fin_header, (self.server_ip, self.server_port))
        print("已发送连接关闭请求（FIN）...")
        # 等待FIN-ACK
        try:
            self.socket.settimeout(2.0)
            for _ in range(5):  # 最多等5次
                data, addr = self.socket.recvfrom(1024)
                if len(data) >= HEADER_SIZE:
                    header = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
                    type_val = header[0]
                    if type_val == TYPE_FIN_ACK:
                        # 解析服务器时间
                        server_timestamp_ms = header[3]
                        server_time_sec = server_timestamp_ms / 1000
                        server_time_str = time.strftime('%H-%M-%S', time.localtime(server_time_sec))
                        print(f"收到服务器FIN-ACK，连接已优雅关闭，服务器系统时间: {server_time_str}")
                        break
            else:
                print("未收到服务器FIN-ACK，强制关闭")
        except Exception as e:
            print(f"关闭连接时异常: {e}")
        self.socket.close()
        print("连接已关闭")


def print_usage():
    print("使用方法: python udpclient.py <server_ip> <server_port>")
    print("示例: python udpclient.py 127.0.0.1 8888")


def main():
    random.seed(time.time())
    if len(sys.argv) != 3:
        print_usage()
        sys.exit(1)
    try:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
        # 创建客户端实例
        client = UDPClient(server_ip, server_port)
        # 建立连接
        if client.connect():
            client.send_data()

        client.close()
    except ValueError:
        print("错误: 端口号必须是整数")
        print_usage()
        sys.exit(1)
    except Exception as e:
        print(f"发生错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()