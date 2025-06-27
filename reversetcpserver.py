import socket
import struct
import threading
import sys

class ProtocolError(Exception):
    """协议解析错误"""
    pass

class NetworkError(Exception):
    """网络连接错误"""
    pass

def print_usage():
    print("使用方法: python TCP_Server.py <port>")
    print("参数说明:")
    print("  port: 服务器监听端口号")

def validate_args():
    """验证命令行参数"""
    if len(sys.argv) != 2:
        print_usage()
        sys.exit(1)

    try:
        port = int(sys.argv[1])
        # 验证端口范围
        if port < 1 or port > 65535:
            print("错误: 端口号必须在1-65535之间")
            sys.exit(1)

        return port

    except ValueError:
        print("错误: 端口号必须是整数")
        sys.exit(1)

def reverse_text(text):
    """反转文本"""
    return text[::-1]

def receive_exact(client_socket, size):
    """确保接收指定大小的数据"""
    data = b''
    remaining = size
    try:
        while remaining > 0:
            chunk = client_socket.recv(min(remaining, 4096))
            if not chunk:
                raise NetworkError("连接中断")
            data += chunk
            remaining -= len(chunk)
        return data
    except socket.timeout:
        raise NetworkError("接收超时")
    except socket.error as e:
        raise NetworkError(f"网络错误: {e}")

def handle_client(client_socket, client_address):
    """处理客户端连接"""
    print(f"接受来自 {client_address} 的连接")

    try:
        # 接收Initialization报文
        init_data = receive_exact(client_socket, 6)  # Type(2) + N(4)
        try:
            msg_type, n = struct.unpack('!HI', init_data)
        except struct.error as e:
            raise ProtocolError(f"解析Initialization报文失败: {e}")

        if msg_type != 1:
            raise ProtocolError(f"预期接收Initialization报文(Type=1)，但收到Type={msg_type}")

        print(f"从 {client_address} 收到Initialization报文，N={n}")

        # 发送agree报文
        agree_message = struct.pack('!H', 2)
        client_socket.sendall(agree_message)
        print(f"向 {client_address} 发送agree报文")

        # 处理n个数据块
        for i in range(n):
            try:
                # 接收reverseRequest报文
                # 接收Type字段
                type_data = receive_exact(client_socket, 2)
                msg_type = struct.unpack('!H', type_data)[0]
                if msg_type != 3:
                    raise ProtocolError(f"预期接收reverseRequest报文(Type=3)，但收到Type={msg_type}")

                # 接收Length字段
                length_data = receive_exact(client_socket, 4)
                length = struct.unpack('!I', length_data)[0]
                print(f"从 {client_address} 接收第{i + 1}块数据，长度={length}字节")

                # 接收Data字段
                data = receive_exact(client_socket, length)

                # 反转文本
                try:
                    text = data.decode('ascii')
                except UnicodeDecodeError:
                    raise ProtocolError("接收到非ASCII数据")

                reversed_text = reverse_text(text)

                # 发送reverseAnswer报文
                reversed_data = reversed_text.encode('ascii')
                answer_message = struct.pack(f'!HI{len(reversed_data)}s', 4, len(reversed_data), reversed_data)
                client_socket.sendall(answer_message)
                print(f"向 {client_address} 发送第{i + 1}块反转后的数据，长度={len(reversed_data)}字节")

            except (ProtocolError, UnicodeDecodeError) as e:
                print(f"处理第{i + 1}块数据时发生协议错误: {e}")
                break
            except NetworkError as e:
                print(f"处理第{i + 1}块数据时发生网络错误: {e}")
                raise

        else:
            print(f"完成处理 {client_address} 的所有{n}块数据")

    except ProtocolError as e:
        print(f"协议错误: {e}")
    except NetworkError as e:
        print(f"网络错误: {e}")
    except Exception as e:
        print(f"未知错误: {e}")
    finally:
        client_socket.close()
        print(f"关闭与 {client_address} 的连接")

def main():
    # 解析命令行参数
    port = validate_args()

    try:
        # 创建服务器socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # 绑定地址和端口
        server_socket.bind(('0.0.0.0', port))

        # 开始监听
        server_socket.listen(5)
        print(f"服务器启动，监听端口 {port}...")

        while True:
            # 接受客户端连接
            client_socket, client_address = server_socket.accept()

            # 创建新线程处理客户端请求
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
            print(f"创建新线程处理 {client_address} 的请求")

    except KeyboardInterrupt:
        print("\n服务器正在关闭...")
    except socket.error as e:
        print(f"网络错误: {e}")
    except Exception as e:
        print(f"发生错误: {e}")
    finally:
        if 'server_socket' in locals():
            server_socket.close()
        print("服务器已关闭")

if __name__ == "__main__":
    main()