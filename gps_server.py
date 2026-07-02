#!/usr/bin/env python3
"""
PICTOR PS10A/B/C GPS Tracker TCP Server
Protocol Version: v1.8.9
"""

import socket
import struct
import threading
import logging
import sqlite3
from typing import Optional, Tuple, Dict, List
from dataclasses import dataclass
from enum import IntEnum

# ==================== CONFIGURATION ====================
HOST = "0.0.0.0"
PORT = 5001
DB_PATH = "/mnt/agents/output/gps_tracker.db"
LOG_PATH = "/mnt/agents/output/gps_server.log"

# ==================== LOGGING SETUP ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== CRC-ITU LOOKUP TABLE ====================
CRC_TABLE = [
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
    0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
    0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
    0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
    0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
    0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
    0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
    0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
    0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
    0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
    0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
    0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
    0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
    0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
    0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
    0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
    0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
    0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
    0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
    0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
    0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
    0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
    0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
    0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
    0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
    0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
    0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
    0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78,
]

# ==================== PROTOCOL ENUMS ====================
class ProtocolType(IntEnum):
    LOGIN = 0x01
    LOCATION = 0x12
    STATUS = 0x13
    STRING_INFO = 0x15
    ALARM = 0x16
    GPS_QUERY = 0x1A
    SERVER_COMMAND = 0x80

class AlarmType(IntEnum):
    NORMAL = 0x00
    SOS = 0x01
    POWER_CUT = 0x02
    SHOCK = 0x03
    FENCE_IN = 0x04
    FENCE_OUT = 0x05
    OVER_SPEED = 0x06
    RAPID_ACCEL = 0x29
    SUDDEN_BRAKE = 0x30
    SHARP_TURN = 0x4C

class Language(IntEnum):
    CHINESE = 0x01
    ENGLISH = 0x02

# ==================== DATA CLASSES ====================
@dataclass
class GPSData:
    imei: str
    timestamp: str
    latitude: float
    longitude: float
    speed: float
    course: int
    satellites: int
    mcc: int
    mnc: int
    lac: int
    cell_id: int
    acc_on: bool
    gps_realtime: bool
    gps_positioned: bool
    east_longitude: bool
    north_latitude: bool
    voltage_level: int = 0
    gsm_signal: int = 0
    alarm_type: str = "NORMAL"
    terminal_info: int = 0
    raw_hex: str = ""

# ==================== DATABASE ====================
class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS gps_locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                imei TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                speed REAL,
                course INTEGER,
                satellites INTEGER,
                mcc INTEGER,
                mnc INTEGER,
                lac INTEGER,
                cell_id INTEGER,
                acc_on INTEGER,
                gps_realtime INTEGER,
                gps_positioned INTEGER,
                voltage_level INTEGER,
                gsm_signal INTEGER,
                alarm_type TEXT,
                raw_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                imei TEXT UNIQUE NOT NULL,
                last_seen TIMESTAMP,
                last_latitude REAL,
                last_longitude REAL,
                status TEXT DEFAULT 'offline',
                first_connected TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS raw_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                imei TEXT,
                protocol_type TEXT,
                direction TEXT,
                raw_hex TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info("Database initialized")
    
    def save_location(self, data: GPSData):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO gps_locations 
            (imei, timestamp, latitude, longitude, speed, course, satellites,
             mcc, mnc, lac, cell_id, acc_on, gps_realtime, gps_positioned,
             voltage_level, gsm_signal, alarm_type, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.imei, data.timestamp, data.latitude, data.longitude,
            data.speed, data.course, data.satellites, data.mcc, data.mnc,
            data.lac, data.cell_id, int(data.acc_on), int(data.gps_realtime),
            int(data.gps_positioned), data.voltage_level, data.gsm_signal,
            data.alarm_type, data.raw_hex
        ))
        
        cursor.execute("""
            INSERT INTO devices (imei, last_seen, last_latitude, last_longitude, status)
            VALUES (?, ?, ?, ?, 'online')
            ON CONFLICT(imei) DO UPDATE SET
                last_seen = excluded.last_seen,
                last_latitude = excluded.last_latitude,
                last_longitude = excluded.last_longitude,
                status = 'online'
        """, (data.imei, data.timestamp, data.latitude, data.longitude))
        
        conn.commit()
        conn.close()
    
    def save_raw_packet(self, imei: str, protocol_type: str, direction: str, raw_hex: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO raw_packets (imei, protocol_type, direction, raw_hex)
            VALUES (?, ?, ?, ?)
        """, (imei, protocol_type, direction, raw_hex))
        conn.commit()
        conn.close()
    
    def get_device_locations(self, imei: str, limit: int = 100):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM gps_locations WHERE imei = ? ORDER BY timestamp DESC LIMIT ?
        """, (imei, limit))
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def get_all_devices(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        return results

# ==================== CRC CALCULATOR ====================
def calculate_crc(data: bytes) -> int:
    fcs = 0xFFFF
    for byte in data:
        fcs = (fcs >> 8) ^ CRC_TABLE[(fcs ^ byte) & 0xFF]
    return ~fcs & 0xFFFF

def verify_crc(data: bytes, expected_crc: bytes) -> bool:
    if len(expected_crc) != 2:
        return False
    expected = struct.unpack(">H", expected_crc)[0]
    calculated = calculate_crc(data)
    return expected == calculated

# ==================== PACKET PARSER ====================
class PacketParser:
    @staticmethod
    def parse_login(data: bytes) -> Tuple[str, int]:
        terminal_id = data[2:10]
        imei = ''.join(f'{b:02X}' for b in terminal_id)
        serial_no = struct.unpack(">H", data[10:12])[0]
        return imei, serial_no
    
    @staticmethod
    def parse_location(data: bytes) -> Dict:
        idx = 0
        year = data[idx] + 2000
        month = data[idx + 1]
        day = data[idx + 2]
        hour = data[idx + 3]
        minute = data[idx + 4]
        second = data[idx + 5]
        timestamp = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
        idx += 6
        
        gps_info = data[idx]
        gps_length = (gps_info >> 4) & 0x0F
        satellites = gps_info & 0x0F
        idx += 1
        
        lat_raw = struct.unpack(">I", data[idx:idx+4])[0]
        latitude = lat_raw / 30000 / 60
        idx += 4
        
        lon_raw = struct.unpack(">I", data[idx:idx+4])[0]
        longitude = lon_raw / 30000 / 60
        idx += 4
        
        speed = data[idx]
        idx += 1
        
        course_status = struct.unpack(">H", data[idx:idx+2])[0]
        acc_on = bool((course_status >> 15) & 1)
        gps_realtime = bool((course_status >> 13) & 1)
        gps_positioned = bool((course_status >> 12) & 1)
        east_longitude = not bool((course_status >> 11) & 1)
        north_latitude = bool((course_status >> 10) & 1)
        course = course_status & 0x03FF
        idx += 2
        
        mcc = struct.unpack(">H", data[idx:idx+2])[0]
        idx += 2
        mnc = data[idx]
        idx += 1
        lac = struct.unpack(">H", data[idx:idx+2])[0]
        idx += 2
        cell_id = struct.unpack(">I", b"\x00" + data[idx:idx+3])[0]
        idx += 3
        
        return {
            'timestamp': timestamp,
            'latitude': latitude if north_latitude else -latitude,
            'longitude': longitude if east_longitude else -longitude,
            'speed': speed,
            'course': course,
            'satellites': satellites,
            'mcc': mcc,
            'mnc': mnc,
            'lac': lac,
            'cell_id': cell_id,
            'acc_on': acc_on,
            'gps_realtime': gps_realtime,
            'gps_positioned': gps_positioned,
            'east_longitude': east_longitude,
            'north_latitude': north_latitude,
        }
    
    @staticmethod
    def parse_alarm(data: bytes) -> Dict:
        location_data = PacketParser.parse_location(data)
        idx = 31
        
        terminal_info = data[idx]
        idx += 1
        
        voltage_level = data[idx]
        idx += 1
        
        gsm_signal = data[idx]
        idx += 1
        
        alarm_lang = struct.unpack(">H", data[idx:idx+2])[0]
        alarm_code = (alarm_lang >> 8) & 0xFF
        language = alarm_lang & 0xFF
        
        alarm_map = {
            0x00: "NORMAL", 0x01: "SOS", 0x02: "POWER_CUT",
            0x03: "SHOCK", 0x04: "FENCE_IN", 0x05: "FENCE_OUT",
            0x06: "OVER_SPEED", 0x29: "RAPID_ACCEL", 0x30: "SUDDEN_BRAKE",
            0x4C: "SHARP_TURN"
        }
        alarm_type = alarm_map.get(alarm_code, f"UNKNOWN({alarm_code:02X})")
        
        location_data.update({
            'terminal_info': terminal_info,
            'voltage_level': voltage_level,
            'gsm_signal': gsm_signal,
            'alarm_type': alarm_type,
            'language': language,
        })
        
        return location_data
    
    @staticmethod
    def parse_heartbeat(data: bytes) -> Dict:
        terminal_info = data[0]
        voltage_level = data[1]
        gsm_signal = data[2]
        alarm_lang = struct.unpack(">H", data[3:5])[0]
        
        alarm_map = {
            0x00: "NORMAL", 0x01: "SOS", 0x02: "POWER_CUT",
            0x03: "SHOCK", 0x04: "FENCE_IN", 0x05: "FENCE_OUT",
            0x06: "OVER_SPEED"
        }
        alarm_code = (alarm_lang >> 8) & 0xFF
        alarm_type = alarm_map.get(alarm_code, f"UNKNOWN({alarm_code:02X})")
        
        return {
            'terminal_info': terminal_info,
            'voltage_level': voltage_level,
            'gsm_signal': gsm_signal,
            'alarm_type': alarm_type,
            'language': alarm_lang & 0xFF,
        }

# ==================== RESPONSE BUILDER ====================
class ResponseBuilder:
    START_BIT = b"\x78\x78"
    STOP_BIT = b"\x0D\x0A"
    
    @staticmethod
    def build_response(protocol: int, serial_no: int) -> bytes:
        packet_length = 0x05
        data_for_crc = struct.pack(">BBH", packet_length, protocol, serial_no)
        crc = calculate_crc(data_for_crc)
        
        packet = (
            ResponseBuilder.START_BIT +
            data_for_crc +
            struct.pack(">H", crc) +
            ResponseBuilder.STOP_BIT
        )
        return packet
    
    @staticmethod
    def build_command_response(protocol: int, serial_no: int, 
                                server_flag: bytes, command: str) -> bytes:
        command_bytes = command.encode("ascii")
        cmd_length = len(server_flag) + len(command_bytes)
        
        info_content = struct.pack(">B", cmd_length) + server_flag + command_bytes
        packet_length = 1 + 1 + len(info_content) + 2 + 2
        
        data_for_crc = struct.pack(">BB", packet_length, protocol) + info_content
        data_for_crc += struct.pack(">H", serial_no)
        crc = calculate_crc(data_for_crc)
        
        packet = (
            ResponseBuilder.START_BIT +
            data_for_crc +
            struct.pack(">H", crc) +
            ResponseBuilder.STOP_BIT
        )
        return packet

# ==================== CLIENT HANDLER ====================
class ClientHandler(threading.Thread):
    def __init__(self, client_socket: socket.socket, address: Tuple[str, int], db: Database):
        super().__init__(daemon=True)
        self.client_socket = client_socket
        self.address = address
        self.db = db
        self.imei: Optional[str] = None
        self.serial_counter = 0
        self.running = True
        self.buffer = b""
    
    def send_response(self, protocol: int, serial_no: int):
        response = ResponseBuilder.build_response(protocol, serial_no)
        self.client_socket.sendall(response)
        if self.imei:
            self.db.save_raw_packet(self.imei, f"0x{protocol:02X}", "TX", response.hex().upper())
        logger.info(f"[{self.address}] Sent response: {response.hex().upper()}")
    
    def handle_login(self, data: bytes, serial_no: int):
        self.imei, _ = PacketParser.parse_login(data)
        logger.info(f"[{self.address}] Login from IMEI: {self.imei}")
        self.send_response(ProtocolType.LOGIN, serial_no)
    
    def handle_location(self, data: bytes, serial_no: int):
        if not self.imei:
            logger.warning(f"[{self.address}] Location before login!")
            return
        
        parsed = PacketParser.parse_location(data)
        gps_data = GPSData(
            imei=self.imei,
            timestamp=parsed['timestamp'],
            latitude=parsed['latitude'],
            longitude=parsed['longitude'],
            speed=parsed['speed'],
            course=parsed['course'],
            satellites=parsed['satellites'],
            mcc=parsed['mcc'],
            mnc=parsed['mnc'],
            lac=parsed['lac'],
            cell_id=parsed['cell_id'],
            acc_on=parsed['acc_on'],
            gps_realtime=parsed['gps_realtime'],
            gps_positioned=parsed['gps_positioned'],
            east_longitude=parsed['east_longitude'],
            north_latitude=parsed['north_latitude'],
            raw_hex=data.hex().upper()
        )
        
        self.db.save_location(gps_data)
        logger.info(f"[{self.imei}] Location: {parsed['latitude']:.6f}, {parsed['longitude']:.6f} | "
                   f"Speed: {parsed['speed']}km/h | ACC: {'ON' if parsed['acc_on'] else 'OFF'}")
    
    def handle_alarm(self, data: bytes, serial_no: int):
        if not self.imei:
            return
        
        parsed = PacketParser.parse_alarm(data)
        gps_data = GPSData(
            imei=self.imei,
            timestamp=parsed['timestamp'],
            latitude=parsed['latitude'],
            longitude=parsed['longitude'],
            speed=parsed['speed'],
            course=parsed['course'],
            satellites=parsed['satellites'],
            mcc=parsed['mcc'],
            mnc=parsed['mnc'],
            lac=parsed['lac'],
            cell_id=parsed['cell_id'],
            acc_on=parsed['acc_on'],
            gps_realtime=parsed['gps_realtime'],
            gps_positioned=parsed['gps_positioned'],
            east_longitude=parsed['east_longitude'],
            north_latitude=parsed['north_latitude'],
            voltage_level=parsed.get('voltage_level', 0),
            gsm_signal=parsed.get('gsm_signal', 0),
            alarm_type=parsed.get('alarm_type', 'NORMAL'),
            terminal_info=parsed.get('terminal_info', 0),
            raw_hex=data.hex().upper()
        )
        
        self.db.save_location(gps_data)
        self.send_response(ProtocolType.ALARM, serial_no)
        
        logger.warning(f"[{self.imei}] ALARM: {parsed.get('alarm_type', 'UNKNOWN')} | "
                      f"Location: {parsed['latitude']:.6f}, {parsed['longitude']:.6f}")
    
    def handle_heartbeat(self, data: bytes, serial_no: int):
        if not self.imei:
            return
        
        parsed = PacketParser.parse_heartbeat(data)
        logger.info(f"[{self.imei}] Heartbeat | Voltage: {parsed['voltage_level']} | "
                   f"GSM: {parsed['gsm_signal']} | Alarm: {parsed['alarm_type']}")
        self.send_response(ProtocolType.STATUS, serial_no)
    
    def handle_server_command(self, data: bytes, serial_no: int):
        idx = 0
        cmd_length = data[idx]
        idx += 1
        server_flag = data[idx:idx+4]
        idx += 4
        command_content = data[idx:idx+cmd_length-4]
        idx += cmd_length - 4
        language = struct.unpack(">H", data[idx:idx+2])[0]
        
        try:
            cmd_str = command_content.decode("ascii")
        except:
            cmd_str = command_content.hex()
        
        logger.info(f"[{self.imei}] Command Response | Flag: {server_flag.hex()} | "
                   f"Cmd: {cmd_str} | Lang: {language}")
    
    def process_packet(self, packet: bytes):
        if len(packet) < 10:
            logger.warning(f"[{self.address}] Packet too short: {len(packet)} bytes")
            return
        
        if packet[:2] != b"\x78\x78":
            logger.warning(f"[{self.address}] Invalid start bit: {packet[:2].hex()}")
            return
        
        packet_length = packet[2]
        protocol = packet[3]
        expected_len = 2 + 1 + packet_length + 2
        
        if len(packet) < expected_len:
            logger.warning(f"[{self.address}] Incomplete packet: {len(packet)} < {expected_len}")
            return
        
        info_content = packet[4:4 + packet_length - 5]
        serial_no = struct.unpack(">H", packet[4 + packet_length - 5:4 + packet_length - 3])[0]
        crc_bytes = packet[4 + packet_length - 3:4 + packet_length - 1]
        stop_bit = packet[4 + packet_length - 1:4 + packet_length + 1]
        
        crc_data = packet[2:4 + packet_length - 3]
        if not verify_crc(crc_data, crc_bytes):
            logger.warning(f"[{self.address}] CRC mismatch! Packet discarded.")
            return
        
        raw_hex = packet.hex().upper()
        if self.imei:
            self.db.save_raw_packet(self.imei, f"0x{protocol:02X}", "RX", raw_hex)
        
        logger.info(f"[{self.address}] RX Protocol: 0x{protocol:02X} | Serial: {serial_no} | "
                   f"Length: {packet_length}")
        
        if protocol == ProtocolType.LOGIN:
            self.handle_login(info_content, serial_no)
        elif protocol == ProtocolType.LOCATION:
            self.handle_location(info_content, serial_no)
        elif protocol == ProtocolType.ALARM:
            self.handle_alarm(info_content, serial_no)
        elif protocol == ProtocolType.STATUS:
            self.handle_heartbeat(info_content, serial_no)
        elif protocol == ProtocolType.STRING_INFO:
            self.handle_server_command(info_content, serial_no)
        elif protocol == ProtocolType.GPS_QUERY:
            logger.info(f"[{self.imei}] GPS Query received")
        else:
            logger.warning(f"[{self.address}] Unknown protocol: 0x{protocol:02X}")
    
    def find_packets(self) -> List[bytes]:
        packets = []
        while True:
            start_idx = self.buffer.find(b"\x78\x78")
            if start_idx == -1:
                self.buffer = b""
                break
            
            if start_idx > 0:
                self.buffer = self.buffer[start_idx:]
            
            if len(self.buffer) < 5:
                break
            
            packet_length = self.buffer[2]
            total_length = 2 + 1 + packet_length + 2
            
            if len(self.buffer) < total_length:
                break
            
            packet = self.buffer[:total_length]
            packets.append(packet)
            self.buffer = self.buffer[total_length:]
        
        return packets
    
    def run(self):
        logger.info(f"[{self.address}] Client connected")
        
        try:
            while self.running:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                
                self.buffer += data
                packets = self.find_packets()
                
                for packet in packets:
                    self.process_packet(packet)
        
        except ConnectionResetError:
            logger.info(f"[{self.address}] Connection reset")
        except Exception as e:
            logger.error(f"[{self.address}] Error: {e}")
        finally:
            self.client_socket.close()
            if self.imei:
                logger.info(f"[{self.imei}] Client disconnected")
            else:
                logger.info(f"[{self.address}] Client disconnected")

# ==================== TCP SERVER ====================
class GPSServer:
    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.db = Database(DB_PATH)
        self.server_socket = None
        self.running = False
        self.clients: List[ClientHandler] = []
    
    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        self.running = True
        
        logger.info("=" * 60)
        logger.info("PICTOR GPS Tracker Server Started")
        logger.info(f"Listening on {self.host}:{self.port}")
        logger.info(f"Database: {DB_PATH}")
        logger.info("=" * 60)
        
        try:
            while self.running:
                client_socket, address = self.server_socket.accept()
                client = ClientHandler(client_socket, address, self.db)
                client.start()
                self.clients.append(client)
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        finally:
            self.stop()
    
    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        for client in self.clients:
            client.running = False
        logger.info("Server stopped")

# ==================== MAIN ====================
if __name__ == "__main__":
    server = GPSServer()
    server.start()