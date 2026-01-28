import socket
import time
import sys


def ping_vacuum(ip):
    # miio hello 封包
    hello_msg = bytes.fromhex(
        "21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    addr = (ip, 54321)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1.0)
        print(f"--- 開始對 {ip} 進行高頻通訊測試 (Ctrl+C 停止) ---")
        count = 0
        while True:
            try:
                start = time.time()
                s.sendto(hello_msg, addr)
                data, _ = s.recvfrom(1024)
                latency = (time.time() - start) * 1000
                print(f"[{count}] 回應成功: 延遲={latency:.2f}ms, 長度={len(data)}")
            except socket.timeout:
                print(f"[{count}] *** 通訊超時 (Timeout) ***")
            except Exception as e:
                print(f"[{count}] 發生錯誤: {e}")

            count += 1
            time.sleep(1)


if __name__ == "__main__":
    target_ip = "192.168.1.9"
    ping_vacuum(target_ip)
