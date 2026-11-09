#!/usr/bin/env python3
"""
Lightweight Zero-Dependency Modbus TCP Server Simulator.
Simulates an industrial PLC Holding Register (Address 0: Pump Cutoff Pressure).
Supports:
- Modbus Function Code 03 (Read Holding Registers)
- Modbus Function Code 06 (Write Single Register)
"""

import socket
import sys

def run_mock_plc(host="0.0.0.0", port=502):
    registers = [85] + [0] * 15  # Reg 0 is cutoff pressure (default 85 psi)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Mock PLC Server listening on {host}:{port}")
    print(f"[*] Holding Register 0 (pump_cutoff_pressure_psi) = {registers[0]} psi")
    sys.stdout.flush()

    while True:
        try:
            conn, addr = server.accept()
            data = conn.recv(1024)
            if not data or len(data) < 8:
                conn.close()
                continue

            trans_id = data[0:2]
            proto_id = data[2:4]
            unit_id = data[6]
            fc = data[7]

            if fc == 0x03:  # Read Holding Registers
                start_addr = (data[8] << 8) | data[9]
                count = (data[10] << 8) | data[11]
                byte_count = count * 2
                payload = bytearray()
                for i in range(count):
                    val = registers[start_addr + i] if (start_addr + i) < len(registers) else 0
                    payload.append((val >> 8) & 0xFF)
                    payload.append(val & 0xFF)
                
                resp_len = 3 + byte_count
                resp = bytearray(trans_id + proto_id + bytearray([(resp_len >> 8) & 0xFF, resp_len & 0xFF, unit_id, 0x03, byte_count]) + payload)
                conn.sendall(resp)

            elif fc == 0x06:  # Write Single Register
                reg_addr = (data[8] << 8) | data[9]
                reg_val = (data[10] << 8) | data[11]
                if reg_addr < len(registers):
                    old_val = registers[reg_addr]
                    registers[reg_addr] = reg_val
                    print(f"[!] 🚨 Modbus FC 06 暫存器竄改事件：Register[{reg_addr}] 由 {old_val} 變更為 {reg_val}！")
                    sys.stdout.flush()
                # Echo back the request as standard FC 06 response
                conn.sendall(data[:12])

            conn.close()
        except Exception as e:
            pass

if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 502
    run_mock_plc(port=p)
