import socket
import struct
import sys
import os
import random

class ProtocolError(Exception):
    """协议解析错误"""
    pass

class NetworkError(Exception):
    """网络连接错误"""
    pass

def print_usage():
    print("使用方法: python TCP_Client.py <serverIP> <serverPort> <Lmin> <Lmax> <inputFile> <outputFile>")
    print("参数说明:")
    print("  serverIP: 服务器IP地址")
    print("  serverPort: 服务器端口号")
    print("  Lmin: 数据块最小长度(字节)")
    print("  Lmax: 数据块最大长度(字节)")
    print("  inputFile: 输入文件路径")
    print("  outputFile: 输出文件路径")

def validate_args():
    """验证命令行参数"""
    if len(sys.argv) != 7:
        print_usage()
        sys.exit(1)

    try:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
        lmin = int(sys.argv[3])
        lmax = int(sys.argv[4])
        input_file = sys.argv[5]
        output_file = sys.argv[6]

        # 验证端口范围
        if server_port < 1 or server_port > 65535:
            raise ValueError("端口号必须在1-65535之间")

        # 验证Lmin和Lmax
        if lmin < 1 or lmax < lmin:
            raise ValueError("Lmin必须大于0，且Lmax必须大于或等于Lmin")

        # 验证输入文件
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"输入文件不存在: {input_file}")
        if os.path.getsize(input_file) == 0:
            raise ValueError("输入文件为空")

        # 验证输出目录可写
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.access(output_dir, os.W_OK):
            raise PermissionError(f"输出目录不可写: {output_dir}")

        return server_ip, server_port, lmin, lmax, input_file, output_file

    except ValueError as e:
        print("错误: 端口号、Lmin和Lmax必须是整数")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"文件错误: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"权限错误: {e}")
        sys.exit(1)


def read_file(file_path):
    """读取文件内容（ASCII编码）"""
    try:
        with open(file_path, 'r', encoding='ascii') as f:
            return f.read()
    except UnicodeDecodeError:
        raise ProtocolError("输入文件必须是ASCII编码")
    except Exception as e:
        raise NetworkError(f"读取文件失败: {e}")


def split_data(data, lmin, lmax):
    """将数据分割成随机长度的块"""
    if not data:
        return []

    chunks = []
    remaining = data
    while remaining:
        max_len = min(lmax, len(remaining))
        if max_len < lmin:
            chunk_len = max_len  # 最后一块不足lmin时特殊处理
        else:
            chunk_len = random.randint(lmin, max_len)
        chunks.append(remaining[:chunk_len])
        remaining = remaining[chunk_len:]

    return chunks


def receive_exact(sock, size):
    """确保接收指定大小的字节数据"""
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise NetworkError("连接断开")
        data += chunk
    return data


def send_initialization(sock, n_blocks):
    """发送初始化报文"""
    try:
        msg = struct.pack('!HI', 1, n_blocks)  # Type=1, N=n_blocks
        sock.sendall(msg)
        print(f"发送初始化报文: N={n_blocks}")
    except socket.error as e:
        raise NetworkError(f"发送初始化报文失败: {e}")


def receive_agree(sock):
    """接收服务器同意报文"""
    try:
        data = receive_exact(sock, 2)  # 接收Type字段
        msg_type = struct.unpack('!H', data)[0]
        if msg_type != 2:
            raise ProtocolError(f"预期同意报文(Type=2)，但收到Type={msg_type}")
        print("收到服务器同意报文")
        return True
    except (struct.error, NetworkError) as e:
        raise ProtocolError(f"接收同意报文失败: {e}")


def send_reverse_request(sock, data):
    """发送反转请求报文"""
    try:
        encoded_data = data.encode('ascii')
        msg = struct.pack(f'!HI{len(encoded_data)}s', 3, len(encoded_data), encoded_data)
        sock.sendall(msg)
    except UnicodeEncodeError:
        raise ProtocolError("数据包含非ASCII字符")
    except socket.error as e:
        raise NetworkError(f"发送反转请求失败: {e}")


def receive_reverse_answer(sock):
    """接收反转应答报文"""
    max_retries = 3
    for retry in range(max_retries):
        try:
            # 接收Type字段
            type_data = receive_exact(sock, 2)
            msg_type = struct.unpack('!H', type_data)[0]
            if msg_type != 4:
                raise ProtocolError(f"预期反转应答(Type=4)，但收到Type={msg_type}")
            # 接收Length字段
            length_data = receive_exact(sock, 4)
            length = struct.unpack('!I', length_data)[0]
            # 接收Data字段
            data = receive_exact(sock, length)
            return data.decode('ascii')
        except (struct.error, UnicodeDecodeError, NetworkError) as e:
            if retry < max_retries - 1:
                print(f"接收失败，重试第{retry + 1}/{max_retries}次: {e}")
                continue
            else:
                raise ProtocolError(f"接收反转应答失败，已重试{max_retries}次: {e}")


def write_output(file_path, content):
    """写入输出文件"""
    try:
        with open(file_path, 'w', encoding='ascii') as f:
            f.write(content)
        print(f"已保存结果到: {file_path}")
    except Exception as e:
        raise NetworkError(f"写入输出文件失败: {e}")


def main():
    # 解析并验证命令行参数
    server_ip, server_port, lmin, lmax, input_file, output_file = validate_args()

    try:
        # 读取输入文件
        data = read_file(input_file)

        # 分割数据
        chunks = split_data(data, lmin, lmax)
        n_blocks = len(chunks)

        # 创建socket并连接服务器
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect((server_ip, server_port))

            # 发送初始化报文
            send_initialization(sock, n_blocks)
            # 接收同意报文
            receive_agree(sock)

            # 处理每个数据块
            reversed_chunks = []
            for i, chunk in enumerate(chunks, 1):
                send_reverse_request(sock, chunk)
                reversed_data = receive_reverse_answer(sock)
                reversed_chunks.append(reversed_data)

                print(f"第{i}块：{reversed_data}")

            reversed_text = ''.join(reversed_chunks[::-1])
            write_output(output_file, reversed_text)
            print(f"{'='*25} 处理结果 {'='*30}")
            print(f"原文：{data}")
            print(f"反转后：{reversed_text}")
            print(f"{'=' * 65}")
            print(f"文件反转成功！\n")

    except ProtocolError as e:
        print(f"协议错误: {e}")
        sys.exit(1)
    except NetworkError as e:
        print(f"网络错误: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n操作被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"未知错误: {e}")
        sys.exit(1)
    except ConnectionResetError:
        print("服务器强制关闭连接")
        sys.exit(1)
    finally:
        if sock:
            sock.close()
            print("客户端连接已关闭")


if __name__ == "__main__":
    main()