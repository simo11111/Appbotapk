import socket
import select
import requests
import threading
import re
import time
import struct
import random
import urllib3
from datetime import datetime
#━━━━━━━━━━━━━━━━━━━
def Decrypted_id(id_value):
    url = f"https://besto-api-enc.vercel.app/Enc/{id_value}?Key=Besto-K7J9"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.text
        encrypted_part = data.split("EncryPted Id : ")[1].split("\n")[0].strip()
        return encrypted_part
    else:
        return f"{id_value}"

#━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_random_color():
    color = random.choice([
        "[cُ][bَ][FF0000]",
        "[cُ][bَ][00FF00]",
        "[cُ][bَ][0000FF]",
        "[cُ][bَ][FFFF00]",
        "[cُ][bَ][FFA500]",
        "[cُ][bَ][800080]",
        "[cُ][bَ][808080]",
        "[cُ][bَ][FFD700]",
        "[cُ][bَ][00FFFF]",
        "[cُ][bَ][FF1493]",
        "[cُ][bَ][8A2BE2]",
        "[cُ][bَ][A52A2A]",
        "[cُ][bَ][DC143C]",
        "[cُ][bَ][00CED1]",
        "[cُ][bَ][FF4500]",
        "[cُ][bَ][2E8B57]",
        "[cُ][bَ][ADFF2F]",
        "[cُ][bَ][4682B4]",
        "[cُ][bَ][40E0D0]",
        "[cُ][bَ][DA70D6]",
        "[cُ][bَ][F4A460]",
        "[cُ][bَ][FF6347]",
        "[cُ][bَ][7FFF00]",
        "[cُ][bَ][BA55D3]",
        "[cُ][bَ][FF69B4]",
        "[cُ][bَ][E9967A]",
    ])
    return color

def gen_squad(clisocks, packet: str):
        header = packet[0:62]
        lastpacket = packet[64:]
        squadcount = "04"
        NewSquadData = header + squadcount + lastpacket
        clisocks.send(bytes.fromhex(NewSquadData))
        
def gen_msg4(packet, content):
        content = content.encode("utf-8")
        content = content.hex()
        header = packet[0:8]
        packetLength = packet[8:10]
        packetBody = packet[10:32]
        pyloadbodyLength = packet[32:34]
        pyloadbody2 = packet[34:62]
        pyloadlength = packet[62:64]
        pyloadtext= re.findall(r"{}(.*?)28".format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+64):]
        NewTextLength = (hex((int(f"0x{pyloadlength}", 16) - int(len(pyloadtext)//2) ) + int(len(content)//2))[2:])
        if len(NewTextLength) == 1:
                NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f"0x{packetLength}", 16) - int((len(pyloadtext))//2) ) ) + int(len(content)//2) )[2:]
        NewPyloadLength = hex(((int(f"0x{pyloadbodyLength}", 16) - int(len(pyloadtext)//2)))+ int(len(content)//2) )[2:]
        NewMsgPacket = header + NewpaketLength + packetBody + NewPyloadLength + pyloadbody2 + NewTextLength + content + pyloadTile
        return str(NewMsgPacket)
        
def gen_msgv3(packet , replay):
        replay = replay.encode('utf-8')
        replay = replay.hex()
        hedar = packet[0:8]
        packetLength = packet[8:10]
        paketBody = packet[10:32]
        pyloadbodyLength = packet[32:34]
        pyloadbody2= packet[34:60]
        pyloadlength = packet[60:62]
        pyloadtext= re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+62):]
        NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
        if len(NewTextLength) == 1:
                NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
        NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)))+ int(len(replay)//2) )[2:]
        finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
        return str(finallyPacket)    
          
def Clan(replay,packet):
    replay  = replay.encode('utf-8')
    replay = replay.hex()
    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:64]
    if "googleusercontent" in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    else:
        pyloadlength = packet[64:66]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+66):]
    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
    return finallyPacket

def send_msg_friends(replay, packet):
	replay  = replay.encode('utf-8')
	replay = replay.hex()
	hd = packet[0:8]
	packetLength = packet[8:10]
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]
	pyloadbody2 = packet[34:60]
	pyloadlength = packet[60:62]
	pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
	Tipy = packet[int(int(len(pyloadtext))+62):]
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) ==1:
		NewTextLength = "0"+str(NewTextLength)
	Nepalh = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
	Nepylh = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2))  )+ int(len(replay)//2) )[2:]
	st_pack = hd + Nepalh + paketBody + Nepylh + pyloadbody2 + NewTextLength + replay + Tipy
	return st_pack

def send_msg_clan(replay, packet):
	replay  = replay.encode('utf-8')
	replay = replay.hex()
	hd = packet[0:8]
	packetLength = packet[8:10] #
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]#
	pyloadbody2 = packet[34:64]
	if "googleusercontent" in str(bytes.fromhex(packet)):
		pyloadlength = packet[64:68]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+68):]
	elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
		pyloadlength = packet[64:68]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+68):]
		print(bytes.fromhex(pyloadlength))
	else:
		pyloadlength = packet[64:66]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+66):]
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) ==1:
		NewTextLength = "0"+str(NewTextLength)
	NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
	NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
	st_pack = hd + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + Tipy
	return st_pack

def gen_msg(packet, content):
	content = content.encode("utf-8")
	content = content.hex()	
	header = packet[0:8]
	packetLength = packet[8:10]
	packetBody = packet[10:32]
	pyloadbodyLength = packet[32:34]
	pyloadbody2 = packet[34:62]
	pyloadlength = packet[62:64]	
	pyloadtext= re.findall(r"{}(.*?)28".format(pyloadlength) , packet[50:])[0]
	pyloadTile = packet[int(int(len(pyloadtext))+64):]	
	NewTextLength = (hex((int(f"0x{pyloadlength}", 16) - int(len(pyloadtext)//2) ) + int(len(content)//2))[2:])
	if len(NewTextLength) == 1:
		NewTextLength = "0"+str(NewTextLength)	
	NewpaketLength = hex(((int(f"0x{packetLength}", 16) - int((len(pyloadtext))//2) ) ) + int(len(content)//2) )[2:]
	NewPyloadLength = hex(((int(f"0x{pyloadbodyLength}", 16) - int(len(pyloadtext)//2)))+ int(len(content)//2) )[2:]
	NewMsgPacket = header + NewpaketLength + packetBody + NewPyloadLength + pyloadbody2 + NewTextLength + content + pyloadTile
	return str(NewMsgPacket)	
def gen_msgv2(packet , replay):
	replay = replay.encode('utf-8')
	replay = replay.hex()		
	hedar = packet[0:8]
	packetLength = packet[8:10] #
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]
	pyloadbody2= packet[34:60]	
	pyloadlength = packet[60:62]
	pyloadtext= re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
	pyloadTile = packet[int(int(len(pyloadtext))+62):]	
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) == 1:
		NewTextLength = "0"+str(NewTextLength)
	NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
	NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)))+ int(len(replay)//2) )[2:]	
	finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile	
	return str(finallyPacket)	
def send_msg(sock, packet, content, delay:int):
	time.sleep(delay)
	try:
		sock.send(bytes.fromhex(gen_msg(packet, content)))
		sock.send(bytes.fromhex(gen_msgv2(packet, content)))
	except Exception as e:
		print(e)
		pass
def adjust_text_length(text, target_length=22, fill_char="20"):
    if len(text) > target_length:
        return text[:target_length]
    elif len(text) < target_length:
        fill_length = target_length - len(text)
        return text + (fill_char * (fill_length // len(fill_char)))[:fill_length]
    else:
        return text
def adjust_text_length(text, target_length=22, fill_char="20"):
    if len(text) > target_length:
        return text[:target_length]
    elif len(text) < target_length:
        fill_length = target_length - len(text)
        return text + (fill_char * (fill_length // len(fill_char)))[:fill_length]
    else:
        return text
#━━━━━━━━━━━━━━━━━━━
###############DEF INFO##############
def get_status(user_id):
    try:
        r = requests.get(f'https://ff.garena.com/api/antihack/check_banned?lang=en&uid={user_id}')
        if "0" in r.text:
            return f"{get_random_color()}▶PLAYER STATUS: {get_random_color()} Account Clear!"
        else:
            return "{get_random_color()}▶PLAYER STATUS: {get_random_color()} Account Ban!"
    except Exception as e:
        return f"Error checking status: {e}"
def get_player_info(user_id):
    try:
        cookies = {
            '_ga': 'GA1.1.2123120599.1674510784',
            '_fbp': 'fb.1.1674510785537.363500115',
            '_ga_7JZFJ14B0B': 'GS1.1.1674510784.1.1.1674510789.0.0.0',
            'source': 'mb',
            'region': 'MA',
            'language': 'ar',
            '_ga_TVZ1LG7BEB': 'GS1.1.1674930050.3.1.1674930171.0.0.0',
            'datadome': '6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0',
            'session_key': 'efwfzwesi9ui8drux4pmqix4cosane0y',
        }
        headers = {
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Origin': 'https://shop2game.com',
            'Referer': 'https://shop2game.com/app/100067/idlogin',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi Note 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
            'accept': 'application/json',
            'content-type': 'application/json',
            'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'x-datadome-clientid': '20ybNpB7Icy69F~RH~hbsvm6XFZADUC-2_--r5gBq49C8uqabutQ8DV_IZp0cw2y5Erk-KbiNZa-rTk1PKC900mf3lpvEP~95Pmut_FlHnIXqxqC4znsakWbqSX3gGlg',
        }
        json_data = {
            'app_id': 100067,
            'login_id': str(user_id),
            'app_server_id': 0,
        }
        response = requests.post(
            'https://shop2game.com/api/auth/player_id_login',
            cookies=cookies,
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            player_info = response.json()
            if 'region' in player_info and 'nickname' in player_info:
                print(player_info['region'])
                print(player_info['nickname'])
                return {
                    "region": f"⏯PLAYER REGION: {player_info['region']}",
                    "nickname": f"⏭PLAYER NAME: {player_info['nickname']}"
                }
            else:
                print("error")
                return {"error": "Invalid response format"}
        else:
            print(response.status_code)
            return {"error": f"Failed to fetch player info: {response.status_code}"}

    except Exception as e:
        return {"error": f"Error fetching player info: {e}"}
##########DEF INFO REGION############
def getname(Id):    
    url = "https://shop2game.com/api/auth/player_id_login"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://shop2game.com",
        "Referer": "https://shop2game.com/app",
        "sec-ch-ua": '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "x-datadome-clientid": "10BIK2pOeN3Cw42~iX48rEAd2OmRt6MZDJQsEeK5uMirIKyTLO2bV5Ku6~7pJl_3QOmDkJoSzDcAdCAC8J5WRG_fpqrU7crOEq0~_5oqbgJIuVFWkbuUPD~lUpzSweEa",
    }
    payload = {
        "app_id": 100067,
        "login_id": f"{Id}",
        "app_server_id": 0,
    }
    response = requests.post(url, headers=headers, json=payload)
    try:
        if response.status_code == 200:
            return response.json()['nickname']
        else:
            return("ERROR")
    except:
        return("Name unknown??")
####################################
def adjust_text_length(text, target_length=22, fill_char="20"):
    if len(text) > target_length:
        return text[:target_length]
    elif len(text) < target_length:
        fill_length = target_length - len(text)
        return text + (fill_char * (fill_length // len(fill_char)))[:fill_length]
    else:
        return text
#━━━━━━━━━━━━━━━━━━━
spam_room = False
spam_inv = False
get_room_code = None
packet_start = None
recode_packet = False
#CLASS SOCKES5!
SOCKS_VERSION = 5
#CODEX_BOT_FREE_3DAY
class Proxy:
    def __init__(self):
        self.username = "bot"
        self.password = "bot"
        self.website = f"https://besto-api-enc.vercel.app/Enc/{id}?Key=Besto-K7J9"
    def fake_friend(self, client, id: str):
        if len(id) == 8:
            packet = "060000007708d4d7faba1d100620022a6b08cec2f1051a1b5b3030464630305d2b2b4d494d4f2058202b2b5b3030464630305d32024d454049b00101b801e807d801d4d8d0ad03e001b2dd8dae03ea011eefbca8efbca5efbcb2efbcafefbcb3efbca8efbca9efbcadefbca1efa3bf8002fd98a8dd03900201d00201"
            packet = re.sub(r'cec2f105', id, packet)
            client.send(bytes.fromhex(packet))
        elif len(id) == 10:            
            packet = "060000006f08d4d7faba1d100620022a6308fb9db9ae061a1c5b3030464630305d2b2be385a4434f44455820205b3030464630305d32024d454040b00113b801e71cd801d4d8d0ad03e00191db8dae03ea010a5a45522d49534b494e47f00101f801911a8002fd98a8dd03900201d0020ad80221"
            packet = re.sub(r'fb9db9ae06', id, packet)
            client.send(bytes.fromhex(packet))
        else:
            print(id)
    def Encrypt_ID(self, id):
            response = requests.get(f'https://besto-api-enc.vercel.app/Enc/{id}?Key=Besto-K7J9')
            if response.status_code == 200:
                match = re.search(r"EncryPted Id : (\S+)", response.text)
                if match:
                	Enc_Iddd = match.group(1)
                	return Enc_Iddd
    def spam_invite(self, dataS, remote):
         global invit_spam
         while invit_spam:
             try:
                 for _ in range(5):
                     remote.send(dataS)
                     time.sleep(0.03)
                 time.sleep(2.1)
             except:
                 pass
    def handle_client(self, connection):
        version, nmethods = connection.recv(2)
        methods = self.get_available_methods(nmethods, connection)
        if 2 not in set(methods):
            connection.close()
            return
        connection.sendall(bytes([SOCKS_VERSION, 2]))
        if not self.verify_credentials(connection):
            return
        version, cmd, _, address_type = connection.recv(4)
        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)
        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
            else:
                connection.close()
            addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
            port = bind_address[1]
            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')
            ])
        except Exception as e:
            reply = self.generate_failed_reply(address_type, 5)
        connection.sendall(reply)
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(connection, remote)
        connection.close()
    def squad_rom_invisible(self):
         try:
             packet_invisible = "0503000001d01fb578313150905babcef51dd24ed75fd0a24b024bd1429646114bc22e604afd35a96fbc48710b2d9cfec4378287ec829e33a78608fd2dd138d4d24a19c00fbfdc9f15c77ff86d638b34de95bd886e3075e82d3f4a3888f9b6943463022c43fb90e229f0eaf8a788f6f766d891d99eb2c37b277144923212810b3c80d1c521790154ed270f5241adc136f2a22816e0bc84fcaf79386b27559de966aa788c184d35bbbfaa03a5f08746f8db0e73b2c91ec4515d61f689a0cad30a7cbd6c325151e879dabc43d506b3240abe41bc0d6b4416c18f68ef4af2d04c381be6bf586f6b25727c0c85c03a579137e4a6c602ef6d833dabdab3eba3a5266e5a4731fbfb1720b60f124cd8fd4fa26cc7a9fb6e0a218d8809f57b204d22fa97520aeb99007c7b71c709e53ecc688c9963e0786909152fa93f06dc93085468dae34e1609f33f7dee228fb058c6efd6846b50ac54db0aebb8f5bc2f6751f9e2886dbab41cbaf5a1d8cd88e6c13a2a2a56b613a2d32179dc3f781493a5027322ac0cb1a2d3c79d49fb12ed26230e1561df43d315a27be17b5debdba757803305252b5443f3d77cd319dde9c49a72c636d93d02bdd9597168f378aa6e41d0fd545abf8bc0883f3dac11ea27166683c7111a0f329bf6b6a5"
             self.client0500.send(bytes.fromhex(packet_invisible))
         except:
             pass
    def gen_squad_6(self):
        try:
            packet_6 = f'050000032708{self.EncryptedPlayerid}100520082a9a0608dbdcd7cb251a910608{self.EncryptedPlayerid}12024d4518012005329d0508{self.EncryptedPlayerid}121ee28094cd9ecd9fcd9ee29885efbcb6efbca5efbcaeefbcafefbcade385a41a024d4520ebdd88b90628363087cbd1303832421880c38566949be061e1cea561b793e66080a89763e5bfce64480150d60158991468b7db8dae037a05ab93c5b00382011f08d1daf1eb0412054f75656973180420d487d4f0042a0808cc9d85f304100392010b0107090a0b12191a1e20229801db01a0014fc00101d001ada48aaf03e80101880203920208c205d628ae2db202aa02050801109c44aa0208080210ea3018c413aa0208080f10d836188827aa0205081710bd33aa0205082b10e432aa0205083910a070aa0205083d10c16faa02050849108439aa0205081810d836aa0205081a10d836aa0205081c10d836aa0205082010d836aa0205082210d836aa0205082110d836aa0205082310d836aa0205083110e432aa0205084110d836aa0205084d10e432aa0205081b10d836aa0205083410d836aa0205082810e432aa0205082910e432c202cd0112041a0201041a730848121301040506070203f1a802f4a802f2a802f3a8021a0b080110031886032086ac021a0b0802100418810420c59a081a0b0803100418da0620ecb4051a06080520f5ec021a0d08f1a802100318b80320def0041a0d08f2a802100318bc0520d0e90a1a0d08f3a802100318ef032092c9051a1208501201631a0b0863100e188f0420eeba0d1a1b0851120265661a09086520a6910128e7021a08086620822d289e05221f121d65ed0e890ed9049103f503ad02f90abd05e907a1068507cd08950ab109d802a6a38daf03ea020410011801f202080885cab5ee01105c8a0300920300980398e0b3af0ba20319efbca334e385a4eaa884e385a4efbcb4efbca5efbca1efbcada80368b00301c2030a081c100f180320052801e203014fea03003a011a403e50056801721e313733303239333438313635343436323834305f6c646a72387477723378880180909beaf3d18fd919a20100b001e201ea010449444331fa011e313733303239333438313635343436363239355f6f747735637831756c6d050000031e08{self.EncryptedPlayerid}1005203a2a910608{self.EncryptedPlayerid}12024d4518012005329d0508{self.EncryptedPlayerid}121ee28094cd9ecd9fcd9ee29885efbcb6efbca5efbcaeefbcafefbcade385a41a024d4520ebdd88b90628363087cbd1303832421880c38566949be061e1cea561b793e66080a89763e5bfce64480150d60158991468b7db8dae037a05ab93c5b00382011f08d1daf1eb0412054f75656973180420d487d4f0042a0808cc9d85f304100392010b0107090a0b12191a1e20229801db01a0014fc00101d001ada48aaf03e80101880203920208c205d628ae2db202aa02050801109c44aa0208080210ea3018c413aa0208080f10d836188827aa0205081710bd33aa0205082b10e432aa0205083910a070aa0205083d10c16faa02050849108439aa0205081810d836aa0205081a10d836aa0205081c10d836aa0205082010d836aa0205082210d836aa0205082110d836aa0205082310d836aa0205083110e432aa0205084110d836aa0205084d10e432aa0205081b10d836aa0205083410d836aa0205082810e432aa0205082910e432c202cd0112041a0201041a730848121301040506070203f1a802f4a802f2a802f3a8021a0b080110031886032086ac021a0b0802100418810420c59a081a0b0803100418da0620ecb4051a06080520f5ec021a0d08f1a802100318b80320def0041a0d08f2a802100318bc0520d0e90a1a0d08f3a802100318ef032092c9051a1208501201631a0b0863100e188f0420eeba0d1a1b0851120265661a09086520a6910128e7021a08086620822d289e05221f121d65ed0e890ed9049103f503ad02f90abd05e907a1068507cd08950ab109d802a6a38daf03ea020410011801f202080885cab5ee01105c8a0300920300980398e0b3af0ba20319efbca334e385a4eaa884e385a4efbcb4efbca5efbca1efbcada80368b00301c2030a081c100f180320052801e203014fea03003a011a403e50056801721e313733303239333438313635343436323834305f6c646a72387477723378880180909beaf3d18fd919a20100b001e201ea010449444331fa011e313733303239333438313635343436363239355f6f747735637831756c6d'
            self.client0500.send(bytes.fromhex(packet_6))
        except:
            pass
    def gen_squad_3(self):
         try:
             packet_3 = f"050000030908{self.EncryptedPlayerid}1005203a2afc0508{self.EncryptedPlayerid}12024d451801200232880508{self.EncryptedPlayerid}1215d8a3d8add881d985d8af4dcda23134e2bc83e29cbf1a024d452093e6c7be0628343084cbd1304218c59be061cc91e6608b9dd164c197a361c8bcce6480c38566480150b60258ed0f6096d9d0ad0368f28390ae037a05acd5cab00382012808f6daf1eb04120ed8b9d980d985d8a7d986d980d98a180720b888d4f0042a0808d19d85f30410039201090107090a0b12191a209801db01a0015aa801d9aff8b103ba010a08b985fe902310011864c00101e80101880208920208b930ea079215b810aa020a080110e43218807d2001aa02050802109035aa020a080f10e43218807d2001aa0205081710be4eaa0205081810b83caa0205081c108139aa0205082010a539aa0205082110e83caa0205082210c63baa0205082b10de3aaa0205083110f02eaa0205083910e052aa02050849109633aa0205081a10e432aa0205082310e432aa0205083d10e432aa0205084110e432aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810c03eaa0205082910e432c2022712031a01011a0f0848120b0104050607f1a802f4a8021a0508501201631a060851120265662200d802a8a38daf03ea020410011801f202080883cab5ee01101b8a03009203009803b198b0b10ba20324efbca7efbca8efbcafefbcb3efbcb4e385a4efbcb4efbca5efbca1efbcade385a4e1b6abc2030a082c1001180320012801c2030a081e100f180320092801ca030a080210eec9d3be061801ca030a080410ba83d3be061805ca030a080510ddb1cdbe061801ca030a080610eec9d3be061801ca030a080b10df9ccdbe061807e203024f52ea0300f20300800464900402aa040408011001aa040408011003aa0411080f1d87b1da3f25e8e7673e2d7683293f3a011a403e50056801721e313734313831323439373339303930373138355f6b663530687473786e638801829080dae083f9ae1aa20100b001e301ea010449444331fa011e313734313831323439373339303931303033375f6b7865696d7a7a72726c"
             self.client0500.send(bytes.fromhex(packet_3))
         except:
             pass
    def gen_squad_5(self):
         try:
             packet_5 = f"05000001ff08{self.EncryptedPlayerid}1005203a2af20308{self.EncryptedPlayerid}12024d451801200432f70208{self.EncryptedPlayerid}1209424c52585f4d6f642b1a024d4520d78aa5b40628023085cbd1303832421880c38566fa96e660c19de061d998a36180a89763aab9ce64480150c90158e80792010801090a12191a1e209801c901c00101e801018802039202029603aa0208080110e43218807daa0207080f10e4322001aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910e432aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2022812041a0201041a0508501201631a060851120265661a0f0848120b0104050607f1a802f4a8022200ea0204100118018a03009203009803b7919db30ba20319c2b27854e19687e197a95fe191ade192aae197a95945e19687e20301523a011a403e50056801721e313732303237323231313638373535353930315f736f3278687a61366e347801820103303b30880180e0aecdacceba8e19a20100b00114ea010449444332fa011e313732303237323231313638373535383330335f71356f79736b3934716d"
             self.client0500.send(bytes.fromhex(packet_5))
         except:
             pass
    def adding_1mG_16kD(self):
        try:
            packet_1m_16k_GD = "080000001608edaae28710100820022a0a08bfda5b10fe7d18c801"
            self.client0500.send(bytes.fromhex(packet_1m_16k_GD))
        except:
            pass
    def adding_gold(self):
         try:
             packet_gold = f"080000001308{self.EncryptedPlayerid}100820022a0708a6b10318fa01"
             self.client0500.send(bytes.fromhex(packet_gold))
         except:
             pass
    def adding_daimond(self):
         try:
             packet_diamond = f"080000001608edaae28710100820022a0a08e7be0110b24f18c801"
             self.client0500.send(bytes.fromhex(packet_diamond))
         except:
             pass
    def adding_youtoubrs(self):
                    try:
                        yout1 = b"\x06\x00\x00\x00{\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*o\x08\x81\x80\x83\xb6\x01\x1a)[f50057]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf\xe3\x85\xa4\xd8\xa7\xd9\x84\xd8\xa8\xd9\x87\xd8\xa7\xd8\xa6\xd9\x85[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\xdc)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\tAO'-'TEAM\xf0\x01\x01\xf8\x01\xdc\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02F";yout2 = b'\x06\x00\x00\x00|\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*p\x08\xd6\xd1\xb9(\x1a![f50057]\xef\xbc\xa8\xef\xbc\xac\xe3\x85\xa4Hassone.[f50057]2\x02ME@G\xb0\x01\x13\xb8\x01\xcf\x1e\xd8\x01\xcc\xd6\xd0\xad\x03\xe0\x01\xed\xdc\x8d\xae\x03\xea\x01\x1d\xef\xbc\xb4\xef\xbc\xa8\xef\xbc\xa5\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xac\xef\xbc\xac\xe0\xbf\x90\xc2\xb9\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout3 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xe9\xa7\xe9\x1b\x1a [ff00ff]DS\xe3\x85\xa4WAJIHANO\xe3\x85\xa4[ff00ff]2\x02ME@Q\xb0\x01\x14\xb8\x01\xca2\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x10.DICTATORS\xe3\x85\xa4\xe2\x88\x9a\xf0\x01\x01\xf8\x01\xc4\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+';yout4 = b'\x06\x00\x00\x00z\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*n\x08\xed\xd4\xa7\xa2\x02\x1a\x1f[f50057]M8N\xe3\x85\xa4y\xe3\x85\xa4Fouad[f50057]2\x02ME@O\xb0\x01\x13\xb8\x01\xa9#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xdb\xdb\x8d\xae\x03\xea\x01\x0cGREAT\xe2\x80\xbfWALL\xf0\x01\x01\xf8\x01b\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\r\xd8\x023\xe0\x02\xc1\xb7\xf8\xb1\x03';yout5 = b"\x06\x00\x00\x00\x84\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*x\x08\xb6\xc0\xf1\xcc\x01\x1a'[f50057]\xd9\x85\xd9\x84\xd9\x83\xd8\xa9*\xd9\x84\xd9\x85\xd8\xb9\xd9\x88\xd9\x82\xd9\x8a\xd9\x86[f50057]2\x02ME@G\xb0\x01\x05\xb8\x01\x82\x0b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x15\xe9\xbf\x84\xef\xbc\xac\xef\xbc\xaf\xef\xbc\xb2\xef\xbc\xa4\xef\xbc\xb3\xe9\xbf\x84\xf0\x01\x01\xf8\x01>\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x05\xd8\x02\x0e";yout6 = b'\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xeb\x98\x88\x8e\x01\x1a"[f50057]OP\xe3\x85\xa4BNL\xe3\x85\xa4\xe2\x9a\xa1\xe3\x85\xa4*[f50057]2\x02ME@R\xb0\x01\x10\xb8\x01\xce\x16\xd8\x01\x84\xf0\xd2\xad\x03\xe0\x01\xa8\xdb\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x8f\xe1\xb4\xa0\xe1\xb4\x87\xca\x80\xe3\x85\xa4\xe1\xb4\x98\xe1\xb4\x8f\xe1\xb4\xa1\xe1\xb4\x87\xca\x80\xe2\x9a\xa1\xf0\x01\x01\xf8\x01A\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01\xe0\x02\xf3\x94\xf6\xb1\x03';yout7 = b"\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xb0\xa4\xdb\x80\x01\x1a'[f50057]\xd9\x85\xd9\x83\xd8\xa7\xd9\x81\xd8\xad\xd8\xa9.\xe2\x84\x93\xca\x99\xe3\x80\xb5..[f50057]2\x02ME@T\xb0\x01\x13\xb8\x01\xfc$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x1d\xef\xbc\xad\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa1\xe3\x85\xa4\xe2\x8e\xb0\xe2\x84\x93\xca\x99\xe2\x8e\xb1\xf0\x01\x01\xf8\x01\xdb\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0f\xd8\x02>";yout8 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xfd\x8a\xde\xb4\x02\x1a\x1f[f50057]ITZ\xe4\xb8\xb6MOHA\xe3\x85\xa42M[f50057]2\x02ME@C\xb0\x01\n\xb8\x01\xdf\x0f\xd8\x01\xac\xd8\xd0\xad\x03\xe0\x01\xf2\xdc\x8d\xae\x03\xea\x01\x15\xe3\x80\x9dITZ\xe3\x80\x9e\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf8\x01\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x026';yout9 = b'\x06\x00\x00\x00w\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*k\x08\xc6\x99\xddp\x1a\x1b[f50057]HEROSHIIMA1[f50057]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xb2\xef\xbc\xaf\xef\xbc\xb3\xef\xbc\xa8\xef\xbc\xa9\xef\xbc\xad\xef\xbc\xa1\xef\xa3\xbf\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout10 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[f50057]SH\xe3\x85\xa4SHIMA|M[f50057]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03';yout11 = b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[f50057]2JZ\xe3\x85\xa4POWER[f50057]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03';yout12 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[f50057]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[f50057]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03';yout13 = b'\x06\x00\x00\x00`\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*T\x08\xd2\xbc\xae\x07\x1a%[f50057]SYBLUS\xe3\x85\xa4\xe4\xba\x97\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4[f50057]2\x02ME@E\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout14 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[f50057]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[f50057]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03';yout15 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\x90\xf6\x87\x15\x1a"[f50057]V4\xe3\x85\xa4RIO\xe3\x85\xa46%\xe3\x85\xa4zt[f50057]2\x02ME@M\xb0\x01\x13\xb8\x01\x95&\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x0e\xe1\xb4\xa0\xe1\xb4\x80\xe1\xb4\x8d\xe1\xb4\x8f\xd1\x95\xf0\x01\x01\xf8\x01\xe2\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02^\xe0\x02\x85\xff\xf5\xb1\x03';yout16 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[f50057]SA777RAWI\xe3\x85\xa4\xe3\x85\xa4[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 ';yout17 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[f50057]SVG.NINJA\xe2\xbc\xbd[f50057]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?';yout18 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[f50057]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03";yout19 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[f50057]FARAMAWY_1M.[f50057]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout20 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[f50057]SH\xe3\x85\xa4SHIMA|M[f50057]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03';yout21 = b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[f50057]2JZ\xe3\x85\xa4POWER[f50057]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03';yout22 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[f50057]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[f50057]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03';yout23 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[f50057]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[f50057]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03';yout24 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[f50057]SA777RAWI\xe3\x85\xa4\xe3\x85\xa4[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 ';yout25 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[f50057]SVG.NINJA\xe2\xbc\xbd[f50057]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?';yout26 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[f50057]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03";yout27 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[f50057]FARAMAWY_1M.[f50057]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout28 = b"\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xaa\xdd\xf1'\x1a\x1d[f50057]BM\xe3\x85\xa4ABDOU_YT[f50057]2\x02ME@G\xb0\x01\x13\xb8\x01\xd4$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1d\xe2\x80\xa2\xc9\xae\xe1\xb4\x87\xca\x9f\xca\x9f\xe1\xb4\x80\xca\x8d\xe1\xb4\x80\xd2\x93\xc9\xaa\xe1\xb4\x80\xc2\xb0\xf0\x01\x01\xf8\x01\x8e\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x07\xd8\x02\x16";yout29 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9a\xd6\xdcL\x1a-[f50057]\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa4\xef\xbc\xa9[f50057]2\x02ME@H\xb0\x01\x01\xb8\x01\xe8\x07\xea\x01\x15\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xc9\xb4\xef\xbd\x93\xe1\xb4\x9b\xe1\xb4\x87\xca\x80\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout30 = b'\x06\x00\x00\x00v\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*j\x08\xb6\x92\xa9\xc8\x01\x1a [f50057]\xef\xbc\xaa\xef\xbc\xad\xef\xbc\xb2\xe3\x85\xa4200K[f50057]2\x02ME@R\xb0\x01\x13\xb8\x01\xc3(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\n3KASH-TEAM\xf8\x012\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x06\xd8\x02\x13\xe0\x02\x89\xa0\xf8\xb1\x03';yout31 = b"\x06\x00\x00\x00\x92\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x85\x01\x08\xa2\xd3\xf4\x81\x07\x1a'[f50057]\xd8\xb3\xd9\x80\xd9\x86\xd9\x80\xd8\xaf\xd8\xb1\xd9\x8a\xd9\x84\xd8\xa71M\xe3\x85\xa4[f50057]2\x02ME@K\xb0\x01\x13\xb8\x01\xc1 \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xad\xef\xbc\xa6\xef\xbc\x95\xef\xbc\xb2\xef\xbc\xa8\xe3\x85\xa4\xe1\xb4\xa0\xc9\xaa\xe1\xb4\x98\xf0\x01\x01\xf8\x01\x8c\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x024\xe0\x02\x87\xff\xf5\xb1\x03";yout32 = b'\x06\x00\x00\x00|\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*p\x08\xe0\xe1\xdeu\x1a\x1a[f50057]P1\xe3\x85\xa4Fahad[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\xd0&\xd8\x01\xea\xd6\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1a\xe3\x85\xa4\xef\xbc\xb0\xef\xbc\xa8\xef\xbc\xaf\xef\xbc\xa5\xef\xbc\xae\xef\xbc\xa9\xef\xbc\xb8\xc2\xb9\xf0\x01\x01\xf8\x01\x9e\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0b\xd8\x02*';yout33 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xc5\xcf\x94\x8b\x02\x1a\x18[f50057]@EL9YSAR[f50057]2\x02ME@P\xb0\x01\x13\xb8\x01\x86+\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\x89\xae\x8f\xae\x03\xea\x01\x1d-\xc9\xaa\xe1\xb4\x8d\xe1\xb4\x8d\xe1\xb4\x8f\xca\x80\xe1\xb4\x9b\xe1\xb4\x80\xca\x9fs\xe2\xac\x86\xef\xb8\x8f\xf8\x01j\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xe2\x02\xe0\x02\x9f\xf1\xf7\xb1\x03';yout34 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xa9\x81\xe6^\x1a\x1e[f50057]STRONG\xe3\x85\xa4CRONA[f50057]2\x02ME@J\xb0\x01\x13\xb8\x01\xd8$\xd8\x01\xd8\xd6\xd0\xad\x03\xe0\x01\x92\xdb\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xbc\x01';yout35 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xeb\x8d\x97\xec\x01\x1a&[f50057]\xd8\xb9\xd9\x80\xd9\x85\xd9\x80\xd8\xaf\xd9\x86\xd9\x8a\xd9\x80\xd8\xaa\xd9\x80\xd9\x88[f50057]2\x02ME@F\xb0\x01\x13\xb8\x01\xd3\x1a\xd8\x01\xaf\xd7\xd0\xad\x03\xe0\x01\xf4\xdc\x8d\xae\x03\xea\x01\rOSIRIS\xe3\x85\xa4MASR\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02\\\xe0\x02\xf4\x94\xf6\xb1\x03';yout36 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xb4\xff\xa3\xef\x01\x1a\x1c[f50057]ZAIN_YT_500K[f50057]2\x02ME@K\xb0\x01\x13\xb8\x01\xa3#\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\xbb\xdb\x8d\xae\x03\xea\x01\x1b\xe1\xb6\xbb\xe1\xb5\x83\xe1\xb6\xa4\xe1\xb6\xb0\xe3\x85\xa4\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\\\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0b\xd8\x02(';yout37 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\x86\xa7\x9e\xa7\x0b\x1a([f50057]\xe2\x80\x94\xcd\x9e\xcd\x9f\xcd\x9e\xe2\x98\x85\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8[f50057]2\x02ME@d\xb0\x01\x13\xb8\x01\xe3\x1c\xe0\x01\xf2\x83\x90\xae\x03\xea\x01!\xe3\x85\xa4\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf8\x01u\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Y\xe0\x02\xc1\xb7\xf8\xb1\x03';yout38 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xc3\xcf\xe5H\x1a([f50057]\xe3\x85\xa4BEE\xe2\x9c\xbfSTO\xe3\x85\xa4\xe1\xb5\x80\xe1\xb4\xb5\xe1\xb4\xb7[f50057]2\x02ME@Q\xb0\x01\x14\xb8\x01\xffP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x15TIK\xe2\x9c\xbfTOK\xe1\xb5\x80\xe1\xb4\xb1\xe1\xb4\xac\xe1\xb4\xb9\xf0\x01\x01\xf8\x01\xc8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02q';yout39 = b'\x06\x00\x00\x00\x94\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x87\x01\x08\x97\xd5\x9a.\x1a%[f50057]\xd8\xb9\xd9\x86\xd9\x83\xd9\x88\xd8\xb4\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe3\x85\xa4[f50057]2\x02ME@P\xb0\x01\x13\xb8\x01\xe8(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe1\xb4\x9c\xea\x9c\xb1\xca\x9c\xe3\x85\xa4\xe1\xb4\x9b\xe1\xb4\x87\xe1\xb4\x80\xe1\xb4\x8d\xf0\x01\x01\xf8\x01\xb6\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02"\xe0\x02\xf2\x94\xf6\xb1\x03';yout40 = b'\x06\x00\x00\x00\x8a\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*~\x08\xf7\xdf\xda\\\x1a/[f50057]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\xa8\xef\xbc\xaf\xef\xbc\xad\xef\xbc\xb3\xef\xbc\xa9_\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93[f50057]2\x02ME@P\xb0\x01\x13\xb8\x01\xb9*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\x8e\x0e\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02S\xe0\x02\xc3\xb7\xf8\xb1\x03';yout41 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xb5\xdd\xec\x8e\x01\x1a%[f50057]\xd8\xa7\xd9\x88\xd9\x81\xe3\x80\x80\xd9\x85\xd9\x86\xd9\x83\xe3\x85\xa4\xe2\x9c\x93[f50057]2\x02ME@K\xb0\x01\x13\xb8\x01\xdd#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x18\xef\xbc\xaf\xef\xbc\xa6\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf0\x01\x01\xf8\x01\xe8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Q';yout42 = b'\x06\x00\x00\x00\x8b\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x7f\x08\x81\xf4\xba\xf8\x01\x1a%[f50057]\xef\xbc\xa7\xef\xbc\xa2\xe3\x85\xa4\xef\xbc\xae\xef\xbc\xaf\xef\xbc\x91\xe3\x81\x95[f50057]2\x02ME@N\xb0\x01\x0c\xb8\x01\xbd\x11\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xa7\xef\xbc\xb2\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xb4__\xef\xbc\xa2\xef\xbc\xaf\xef\xbc\xb9\xf8\x018\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02-\xe0\x02\x85\xff\xf5\xb1\x03';yout43 = b'\x06\x00\x00\x00o\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*c\x08\xfb\x9d\xb9\xae\x06\x1a\x1c[f50057]BT\xe3\x85\xa4BadroTV[f50057]2\x02ME@@\xb0\x01\x13\xb8\x01\xe7\x1c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x91\xdb\x8d\xae\x03\xea\x01\nBadro_TV_F\xf0\x01\x01\xf8\x01\x91\x1a\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02!';yout44 = b"\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xc4\xe5\xe1>\x1a'[f50057]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf~\xd8\xa7\xd9\x84\xd8\xba\xd9\x86\xd8\xa7\xd8\xa6\xd9\x85[f50057]2\x02ME@J\xb0\x01\x14\xb8\x01\xceP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x03Z7F\xf0\x01\x01\xf8\x01\xd0\x19\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\x9c\x01";yout45 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xfd\xa4\xa6i\x1a$[f50057]\xd8\xb2\xd9\x8a\xd9\x80\xd8\xb1\xc9\xb4\xcc\xb67\xcc\xb6\xca\x80\xe3\x85\xa4[f50057]2\x02ME@M\xb0\x01\x13\xb8\x01\xe1(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x19\xc2\xb7\xe3\x85\xa4\xe3\x85\xa4N\xe3\x85\xa47\xe3\x85\xa4R\xe3\x85\xa4\xe3\x85\xa4\xc2\xb7\xf0\x01\x01\xf8\x01\x8f\t\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02k';yout46 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xcc\xb9\xcc\xd4\x06\x1a"[f50057]\xd8\xa8\xd9\x88\xd8\xad\xd8\xa7\xd9\x83\xd9\x80\xd9\x80\xd9\x80\xd9\x85[f50057]2\x02ME@9\xb0\x01\x07\xb8\x01\xca\x0c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x11*\xef\xbc\x97\xef\xbc\xaf\xef\xbc\xab\xef\xbc\xa1\xef\xbc\xad*\xf0\x01\x01\xf8\x01\xad\x05\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout47 = b'\x06\x00\x00\x00e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*Y\x08\xe8\xbd\xc9b\x1a [f50057]\xe3\x80\x8cvip\xe3\x80\x8dDR999FF[f50057]2\x02ME@Q\xb0\x01\x10\xb8\x01\x94\x16\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xf0\x01\x01\xf8\x01\xa0\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+';yout48 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\x86\xb7\x84\xf1\x01\x1a&[f50057]\xd8\xa2\xd9\x86\xd9\x8a\xd9\x80\xd9\x80\xd9\x84\xd8\xa7\xce\x92\xe2\x92\x91\xe3\x85\xa4[f50057]2\x02ME@Q\xb0\x01\x13\xb8\x01\x82)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x13\xce\x92\xe2\x92\x91\xe3\x85\xa4MAFIA\xe3\x85\xa4\xef\xa3\xbf\xf0\x01\x01\xf8\x01\x95\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02W';yout49 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [f50057]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[f50057]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{';yout50 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [f50057]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[f50057]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{'
                        yout_list = [yout1,yout2,yout3,yout4,yout5,yout6,yout7,yout8,yout9,yout10,yout11,yout12,yout13,yout14,yout15,yout16,yout17,yout18,yout19,yout20,yout21,yout22,yout23,yout24,yout25,yout26,yout27,yout28,yout29,yout30,yout31,yout32,yout33,yout34,yout35,yout36,yout37,yout38,yout39,yout40,yout41,yout42,yout43,yout44,yout45,yout46,yout47,yout48,yout49,yout50]
                        for y in yout_list:
                        		try:
                        		  		self.client0500.send(y)
                        		  		time.sleep(1)
                        		except:
                        		    pass
                    except:
                        pass
    def YearsOld7(self):
        years_old_7 = f"12000000F308{self.EncryptedPlayerid}101220022AE60108{self.EncryptedPlayerid}10{self.EncryptedPlayerid}2883BBBCC40642247B225469746C654944223A3930343039303032372C2274797065223A225469746C65227D4A520A13E29DBC2ECFBB2EE29DBCE385A4524544464F5810EDB58FAE0318B1B1D2AD0320C10228C3B7F8B10338024214E3808E4164E3808FC39FC581C398C48CCCA3C6986A00720C08{self.EncryptedPlayerid}10011A0210155202656E6A520A4C68747470733A2F2F67726170682E66616365626F6F6B2E636F6D2F76392E302F3131393337333137393632373538352F706963747572653F77696474683D313630266865696768743D313630100118017200"
        self.client1200.send(bytes.fromhex(years_old_7))
    def YearsOld6(self):
        years_old_6 = f"12000000F308{self.EncryptedPlayerid}101220022AE60108{self.EncryptedPlayerid}10{self.EncryptedPlayerid}2883BBBCC40642247B225469746C654944223A3930343039303032362C2274797065223A225469746C65227D4A520A13E29DBC2ECFBB2EE29DBCE385A4524544464F5810EDB58FAE0318B1B1D2AD0320C10228C3B7F8B10338024214E3808E4164E3808FC39FC581C398C48CCCA3C6986A00720C08{self.EncryptedPlayerid}10011A0210155202656E6A520A4C68747470733A2F2F67726170682E66616365626F6F6B2E636F6D2F76392E302F3131393337333137393632373538352F706963747572653F77696474683D313630266865696768743D313630100118017200"
        self.client1200.send(bytes.fromhex(years_old_6))
    def YearsOld5(self):
        years_old_5 = f"12000000f308{self.EncryptedPlayerid}101220022ae60108{self.EncryptedPlayerid}10{self.EncryptedPlayerid}2883bbbcc40642247b225469746c654944223a3930343039303032352c2274797065223a225469746c65227d4a520a13e29dbc2ecfbb2ee29dbce385a4524544464f5810edb58fae0318b1b1d2ad0320c10228c3b7f8b10338024214e3808e4164e3808fc39fc581c398c48ccca3c6986a00720c08{self.EncryptedPlayerid}10011a0210155202656e6a520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3131393337333137393632373538352f706963747572653f77696474683d313630266865696768743d313630100118017200"
        self.client1200.send(bytes.fromhex(years_old_5))
    
    HELP_TEXT = """
[C][B][1E90FF]━━━━━━━━━━━━━━━━━━
[FFFFFF][B]               MIMO X BOT V2
[C][B][1E90FF]━━━━━━━━━━━━━━━━━━

[FFB300][B]           ROOM COMMAND:
[00CED1]/RMSPM        [FFFFFF]- سبام دعوات الروم
[00CED1]@RMSPM        [FFFFFF]- إغلاق سبام الدعوات
[00CED1]/RSPY         [FFFFFF]- التجسس في الغرفة
[00CED1]/RMCD         [FFFFFF]- عرض كلمة مرور الغرفة

[32CD32][B]           SQUAD COMMAND:
[00FF00]/6s           [FFFFFF]- تحويل الفريق إلى 6 لاعبين
[00FF00]/5s           [FFFFFF]- تحويل الفريق إلى 5 لاعبين
[00FF00]/3s           [FFFFFF]- تحويل الفريق إلى 3 لاعبين

[DC143C][B]           SPECIAL COMMAND:
[FF69B4]/spm          [FFFFFF]- سبام رسائل آمن
[FF69B4]/add          [FFFFFF]- إضافة لاعب بواسطة ID
[FFFF00]/yt           [FFFFFF]- إضافة 50 منشئ محتوى
[FF69B4]/proxy        [FFFFFF]- جميع الملابس في الخزنة

[FFB300][B]           INVITE COMMAND:
[00CED1]/invON        [FFFFFF]- تفعيل سبام الدعوات
[00CED1]@invOFF       [FFFFFF]- إيقاف سبام الدعوات
[00CED1]/SPYSQ        [FFFFFF]- تجسس في الفريق
[00CED1]/start        [FFFFFF]- دخول إجباري

[FFD700][B]           FAKE COMMAND:
[FFFF00]/GOLD         [FFFFFF]- إضافة 1.5M ذهب و16K ماس وهمي

[8A2BE2][B]           TITLE COMMAND:
[FFFFFF]/7old         [FFFFFF]- إضافة شعار 7 سنوات
[FFFFFF]/6old         [FFFFFF]- إضافة شعار 6 سنوات
[FFFFFF]/5old         [FFFFFF]- إضافة شعار 5 سنوات

[C][B][1E90FF]━━━━━━━━━━━━━━━━━━
"""
    
    def Msg_Help_En(self):
        try:
            message_en = f"1200000F2F08{self.EncryptedPlayerid}101220022AA21E08{self.EncryptedPlayerid}10{self.EncryptedPlayerid}225b435d5b425d5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a5b4646464646465d5b425d2020202020202020202020202020204d494d4f205820424f542056320a5b435d5b425d5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a0a5b4646423330305d5b425d2020202020202020202020524f4f4d20434f4d4d414e44533a0a5b3030434544315d2f524d53504d20202020202020205b4646464646465d2d20526f6f6d20696e76697465207370616d0a5b3030434544315d40524d53504d20202020202020205b4646464646465d2d2053746f7020696e76697465207370616d0a5b3030434544315d2f525350592020202020202020205b4646464646465d2d20537079206f6e20726f6f6d0a5b3030434544315d2f524d43442020202020202020205b4646464646465d2d2053686f7720726f6f6d2070617373776f72640a0a5b3332434433325d5b425d2020202020202020202020535155414420434f4d4d414e44533a0a5b3030464630305d2f367320202020202020202020205b4646464646465d2d2053657420737175616420746f203620706c61796572730a5b3030464630305d2f357320202020202020202020205b4646464646465d2d2053657420737175616420746f203520706c61796572730a5b3030464630305d2f337320202020202020202020205b4646464646465d2d2053657420737175616420746f203320706c61796572730a0a5b4443313433435d5b425d20202020202020202020205350454349414c20434f4d4d414e44533a0a5b4646363942345d2f73706d202020202020202020205b4646464646465d2d2053616665206d657373616765207370616d0a5b4646363942345d2f616464202020202020202020205b4646464646465d2d2041646420706c617965722062792049440a5b4646464630305d2f797420202020202020202020205b4646464646465d2d2041646420353020636f6e74656e742063726561746f72730a5b4646363942345d2f70726f787920202020202020205b4646464646465d2d20556e6c6f636b20616c6c207661756c74206f7574666974730a0a5b4646423330305d5b425d2020202020202020202020494e5649544520434f4d4d414e44533a0a5b3030434544315d2f696e764f4e20202020202020205b4646464646465d2d20456e61626c6520696e76697465207370616d0a5b3030434544315d40696e764f4646202020202020205b4646464646465d2d2044697361626c6520696e76697465207370616d0a5b3030434544315d2f535059535120202020202020205b4646464646465d2d205371756164207370790a5b3030434544315d2f737461727420202020202020205b4646464646465d2d20466f726365206a6f696e0a0a5b4646443730305d5b425d202020202020202020202046414b4520434f4d4d414e44533a0a5b4646464630305d2f474f4c442020202020202020205b4646464646465d2d2041646420312e354d2066616b6520676f6c6420262031364b206469616d6f6e64730a0a5b3841324245325d5b425d20202020202020202020205449544c4520434f4d4d414e44533a0a5b4646464646465d2f376f6c642020202020202020205b4646464646465d2d2041646420372059656172732062616467650a5b4646464646465d2f366f6c642020202020202020205b4646464646465d2d2041646420362059656172732062616467650a5b4646464646465d2f356f6c642020202020202020205b4646464646465d2d2041646420352059656172732062616467650a0a5b435d5b425d5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481"
            self.client1200.send(bytes.fromhex(message_en))
            message_ar = f""
            self.client1200.send(bytes.fromhex(message_ar))
        except:
            pass
    def handle_id(self, iddd):
        if '***' in iddd:
            iddd = iddd.replace('***', '106')
        iddd = str(iddd).split('(\\x')[0]
        add_id_packet = self.Encrypt_ID(iddd)
        finale_packet = Danse_Players(add_id_packet)
        self.client0500.send(bytes.fromhex(finale_packet))
#━━━━━━━━━━━━━━━━━━━
    def exchange_loop(self, client, remote):
        global fake_friend, spam_room, spam_inv, get_room_code, packet_start, recode_packet, bot_true, bot_codes
        while True:
            r, w, e = select.select([client, remote], [], [])
            #CLIENT
            if client in r:
                try:
                    dataC = client.recv(9999)
                    #MANDATORY ENTRY
                    if recode_packet and "0515" in dataC.hex()[:4] and len(dataC.hex()) == 140:
                        packet_start = dataC.hex()
                        recode_packet = False
                except:
                    break
                #spam_room
                if spam_room and '0e15' in dataC.hex()[0:4]:
                    try:
                        while True:
                            for _ in range(10000):
                                for __ in range(1000):
                                    remote.send(dataC)
                                    time.sleep(0.2)
                            time.sleep(0.01)
                        time.sleep(5)
                    except:
                        pass
                #spam_invition
                if spam_inv and '0515' in dataC.hex()[0:4]:
                    try:
                        while True:
                            for _ in range(10000):
                                for __ in range(100):
                                    remote.send(dataC)
                                    time.sleep(0.005)
                            time.sleep(0.03)
                        time.sleep(5)
                    except:
                        pass
                #ports
                if "39699" in str(client):
                    self.client0500 = client
                if "39699" in str(remote):
                    self.remote0500 = remote
                try:
                    if remote.send(dataC) <= 0:
                        break 
                except:
                    break 
            #SERVER
            if remote in r:
                try:
                    dataS = remote.recv(9999)
                except:
                    break
                self.EncryptedPlayerid = dataS.hex()[12:22]
                self.client1200 = client
                if '0e00' in dataS.hex()[0:4]:
                    try:
                        while True:
                            for i in range(10):
                                pattern = fr"x0{str(i)}(\d+)Z"
                                match = re.search(pattern, str(dataS))
                                if match:
                                    number = match.group(1)
                                    get_room_code = number
                    except:
                        pass
                if "0500" in dataS.hex()[0:4]:
                    self.client0500 = client
                #COMMANDS
                if  b"/help" in dataS:
                   threading.Thread(target=self.Msg_Help_En).start()
                #ROOM FEATURES!
                if   b"/RMSPM" in dataS:
                    try:
                        spam_room = True
                    except:
                        pass
                if   b"@RMSPM" in dataS:
                    try:
                        spam_room = False
                    except:
                        pass
                if   b"/RMCD" in dataS:
                    try:              
                        threading.Thread(target=send_msg, args=(self.client1200, dataS.hex(), f"[b][i][c][7cfc00] - Code Room : {get_room_code}\n By : MIMO X", 0.001)).start()
                    except:
                        pass
                if   b"/RSPY" in dataS:
                    try:
                        threading.Thread(target=self.squad_rom_invisible).start()
                        threading.Thread(target=send_msg, args=(self.client1200, dataS.hex(), "[b][i][c][7cfc00] - Spy On", 0.2)).start()
                    except:
                        pass
                #SQUAD FEATURES!
                if   b"/invON" in dataS:
                    try:
                        spam_inv = True
                        self.client1200.send(bytes.fromhex(f"120000014708{self.EncryptedPlayerid}101220022aba0208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}2292010a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a0a220a5b3030464630305d5b635d5b625d496e76697465207370616d206163746976617465642e0a0a220a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"))
                    except:
                        pass
                if   b"@invOFF" in dataS:
                    try:
                        spam_inv = False
                        self.client1200.send(bytes.fromhex(f"120000014908{self.EncryptedPlayerid}101220022abc0208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}2294010a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a0a220a5b3030464630305d5b635d5b625d496e76697465207370616d2064656163746976617465642e0a0a220a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"))
                    except:
                        pass
                if   b"/SPYSQ" in dataS:
                    try:
                        threading.Thread(target=self.squad_rom_invisible).start()
                        threading.Thread(target=send_msg, args=(self.client1200, dataS.hex(), "[b][i][c][7cfc00] - Spy On", 0.2)).start()
                    except:
                        pass
                if   b"/3s" in dataS:
                    try:
                        threading.Thread(target=self.gen_squad_3).start()
                        self.client1200.send(bytes.fromhex(f"120000017508{self.EncryptedPlayerid}101220022ae80208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22c0010a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a0a220a5b3030464630305d5b635d5b625d54686520737175616420686173206265656e20636f6e76657274656420746f203320706c61796572732e2053656e6420616e20696e7669746520746f20476c6f62616c2e0a0a220a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"))
                    except:
                        pass
                if   b"/5s" in dataS:
                    try:
                        threading.Thread(target=self.gen_squad_5).start()
                        self.client1200.send(bytes.fromhex(f"120000017508{self.EncryptedPlayerid}101220022ae80208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22c0010a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a0a220a5b3030464630305d5b635d5b625d54686520737175616420686173206265656e20636f6e76657274656420746f203520706c61796572732e2053656e6420616e20696e7669746520746f20476c6f62616c2e0a0a220a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"))
                    except:
                        pass
                if   b"/6s" in dataS:
                    try:
                        threading.Thread(target=self.gen_squad_6).start()
                        self.client1200.send(bytes.fromhex(f"120000017508{self.EncryptedPlayerid}101220022ae80208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22c0010a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a0a220a5b3030464630305d5b635d5b625d54686520737175616420686173206265656e20636f6e76657274656420746f203620706c61796572732e2053656e6420616e20696e7669746520746f20476c6f62616c2e0a0a220a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"))
                    except:
                        pass
                #ADDING FEATURES!
                if   b"/YT" in dataS:
                    try:
                        threading.Thread(target=self.adding_youtoubrs).start()
                        self.client1200.send(bytes.fromhex(f"120000014208{self.EncryptedPlayerid}101220022ab50208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}228d010a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a0a220a5b3030464630305d5b635d5b625d2d20444f4e45204144442035312059542e0a0a220a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"))
                    except:
                        pass
                if   b"/GOLD" in dataS:
                    try:
                        threading.Thread(target=self.adding_1mG_16kD).start()
                        self.client1200.send(bytes.fromhex(f"120000015608{self.EncryptedPlayerid}101220022ac90208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22a1010a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a0a220a5b3030464630305d5b635d5b625d2d20444f4e452041444420312e354d20474f4c4420414e442031364b204449414d4f4e442e0a0a220a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"))
                    except:
                        pass
                if   b"/GD" in dataS:
                    try:
                        threading.Thread(target=self.adding_gold).start()
                        self.client1200.send(bytes.fromhex(f"120000014508{self.EncryptedPlayerid}101220022ab80208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}2290010a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a0a220a5b3030464630305d5b635d5b625d2d20444f4e45204144442035304b20474f4c442e0a0a220a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"))
                    except:
                        pass
                if b"/proxy1" in dataS:
                    try:
                        items_ids = [ 'b598e660', 'b698e660', 'b798e660', 'b898e660', 'b998e660', 'ba98e660', 'bb98e660', 'bc98e660', 'bd98e660', 'be98e660', 'bf98e660', 'c098e660', 'c198e660', 'c298e660', 'c398e660', 'c498e660', 'c598e660', 'c698e660', 'c798e660', 'c898e660', 'c998e660', 'ca98e660', 'cb98e660', 'cc98e660', 'cd98e660', 'ce98e660', 'cf98e660', 'd098e660', 'd198e660', 'd298e660', 'd398e660', 'd498e660', 'd598e660', 'd698e660', 'd798e660', 'd898e660', 'd998e660', 'da98e660', 'db98e660', 'dc98e660', 'dd98e660', 'de98e660', 'df98e660', 'e098e660', 'e198e660', 'e298e660', 'e398e660', 'e498e660', 'e598e660', 'e698e660', 'e798e660', 'e89ae660', 'e99ae660', 'ea9ae660', 'eb9ae660', 'ec9ae660', 'ed9ae660', 'ee9ae660', 'ef9ae660', 'f09ae660', 'f19ae660', 'f29ae660', 'f39ae660', 'f49ae660', 'f59ae660', 'f69ae660', 'f79ae660', 'f89ae660', 'f99ae660', 'fa9ae660', 'fb9ae660', 'fc9ae660', 'fd9ae660', 'fe9ae660', 'ff9ae660', '809be660', '819be660', '829be660', '839be660', '849be660', '859be660', '869be660', '879be660', '889be660', '899be660', '8a9be660', '8b9be660', '8c9be660', '8d9be660', '8e9be660', '8f9be660', '909be660', '919be660', '929be660', '939be660', '949be660', '959be660', '969be660', '979be660', '989be660', '999be660', '9a9be660', '9b9be660', '9c9be660', '9d9be660', '9e9be660', '9f9be660', 'a09be660', 'a19be660', 'a29be660', 'a39be660', 'a49be660', 'a59be660', 'a69be660', 'a79be660', 'a89be660', 'a99be660', 'aa9be660', 'ab9be660', 'ac9be660', 'ad9be660', 'ae9be660', 'af9be660', 'b09be660', 'b19be660', 'b29be660', 'b39be660', 'b49be660', 'b59be660', 'b69be660', 'b79be660', 'b89be660', 'b99be660', 'ba9be660', 'bb9be660', 'bc9be660', 'bd9be660', 'be9be660', 'bf9be660', 'c09be660', 'c19be660', 'c29be660', 'c39be660', 'c49be660', 'c59be660', 'c69be660', 'c79be660', 'c89be660', 'c99be660', 'ca9be660', 'cb9be660', 'cc9be660', 'cd9be660', 'ce9be660', 'cf9be660', 'd09be660', 'd19be660', 'd29be660', 'd39be660']
                        for ids in items_ids:
                            self.client0500.send(bytes.fromhex(f"080000005a08cdede39a31100820062a4e0a1808f680e960100120ffffffffffffffffff012801380140020a1808b185a661100120ffffffffffffffffff012801380140020a1808{ids}100120ffffffffffffffffff01280138014002080000002708cdede39a31100820032a1b0a0708f680e96010010a0708b185a66110010a0708{ids}1001"))
                    except:
                        pass
                #UnLock All Shoes
                if b"/proxy2" in dataS:
                    try:
                        items_ids = [
    "c19ae061", "c29ae061", "c39ae061", "c49ae061", "c59ae061", "c69ae061", "c79ae061", "c89ae061", "c99ae061", "ca9ae061", "cb9ae061", "cc9ae061", "cd9ae061", "ce9ae061", "cf9ae061",
    "d09ae061", "d19ae061", "d29ae061", "d39ae061", "d49ae061", "d59ae061", "d69ae061", "d79ae061", "d89ae061", "d99ae061", "da9ae061", "db9ae061", "dc9ae061", "dd9ae061", "de9ae061", "df9ae061",
    "e09ae061", "e19ae061", "e29ae061", "e39ae061", "e49ae061", "e59ae061", "e69ae061", "e79ae061", "e89ae061", "e99ae061", "ea9ae061", "eb9ae061", "ec9ae061", "ed9ae061", "ee9ae061", "ef9ae061",
    "f09ae061", "f19ae061", "f29ae061", "f39ae061", "f49ae061", "f59ae061", "f69ae061", "f79ae061", "f89ae061", "f99ae061", "fa9ae061", "fb9ae061", "fc9ae061", "fd9ae061", "fe9ae061", "ff9ae061",
    "809be061", "819be061", "829be061", "839be061", "849be061", "859be061", "869be061", "879be061", "e89de061", "e99de061", "ea9de061", "eb9de061", "ec9de061", "ed9de061", "ee9de061", "ef9de061",
    "f09de061", "f19de061", "f29de061", "f39de061", "f49de061", "f59de061", "f69de061", "f79de061", "f89de061", "f99de061", "fa9de061", "fb9de061", "fc9de061", "fd9de061", "fe9de061", "ff9de061",
    "809ee061", "819ee061", "829ee061", "839ee061", "849ee061", "859ee061", "869ee061", "879ee061", "889ee061", "899ee061", "8a9ee061", "8b9ee061", "8c9ee061", "8d9ee061", "8e9ee061", "8f9ee061",
    "909ee061", "919ee061", "929ee061", "939ee061", "949ee061", "959ee061", "969ee061", "979ee061", "989ee061", "999ee061", "9a9ee061", "9b9ee061", "9c9ee061", "9d9ee061", "9e9ee061", "9f9ee061",
    "a09ee061", "a19ee061", "a29ee061", "a39ee061", "a49ee061", "a59ee061", "a69ee061", "a79ee061", "a89ee061", "a99ee061", "aa9ee061", "ab9ee061", "ac9ee061", "ad9ee061", "ae9ee061", "af9ee061",
    "b09ee061", "b19ee061", "b29ee061", "b39ee061", "b49ee061", "b59ee061", "b69ee061", "b79ee061", "b89ee061", "b99ee061", "ba9ee061", "bb9ee061", "bc9ee061", "bd9ee061", "be9ee061", "bf9ee061",
    "c09ee061", "c19ee061", "c29ee061", "c39ee061", "c49ee061", "c59ee061", "c69ee061", "c79ee061", "c89ee061", "c99ee061", "ca9ee061", "cb9ee061", "cc9ee061", "cd9ee061", "ce9ee061", "cf9ee061",
    "d09ee061", "d19ee061", "d29ee061", "d39ee061", "d49ee061", "d59ee061", "d69ee061", "d79ee061", "d89ee061", "d99ee061", "da9ee061", "db9ee061", "dc9ee061", "dd9ee061", "de9ee061", "df9ee061",
    "e09ee061", "e19ee061", "e29ee061", "e39ee061", "e49ee061", "e59ee061", "e69ee061", "e79ee061", "e89ee061", "e99ee061", "ea9ee061", "eb9ee061", "ec9ee061", "ed9ee061", "ee9ee061", "ef9ee061",
    "f09ee061", "f19ee061", "f29ee061", "f39ee061", "f49ee061", "f59ee061", "f69ee061", "f79ee061", "f89ee061", "f99ee061", "fa9ee061", "fb9ee061", "fc9ee061", "fd9ee061", "fe9ee061", "ff9ee061",
    "809fe061", "819fe061", "829fe061", "839fe061", "849fe061", "859fe061", "869fe061", "879fe061", "889fe061", "899fe061", "8a9fe061", "8b9fe061", "8c9fe061", "8d9fe061", "8e9fe061", "8f9fe061",
    "909fe061", "919fe061", "929fe061", "939fe061", "949fe061", "959fe061", "969fe061", "979fe061", "989fe061", "999fe061", "9a9fe061", "9b9fe061", "9c9fe061", "9d9fe061", "9e9fe061", "9f9fe061",
    "a09fe061", "a1a0e061", "a2a0e061", "a3a0e061", "bca1e061", "bda1e061", "bea1e061", "bfa1e061",
    "c0a1e061", "c1a1e061", "c2a1e061", "c3a1e061", "c4a1e061", "c5a1e061", "c6a1e061", "c7a1e061", "c8a1e061", "c9a1e061", "caa1e061", "cba1e061", "cca1e061", "cda1e061", "cea1e061", "cfa1e061",
    "d0a1e061", "d1a1e061", "d2a1e061", "d3a1e061", "d4a1e061", "d5a1e061", "d6a1e061", "d7a1e061", "d8a1e061", "d9a1e061", "daa1e061", "dba1e061", "dca1e061", "dda1e061", "dea1e061", "dfa1e061",
    "e0a1e061", "e1a1e061", "e2a1e061", "e3a1e061", "e4a1e061", "e5a1e061", "e6a1e061", "e7a1e061", "e8a1e061", "e9a1e061", "eaa1e061", "eba1e061", "eca1e061", "eda1e061", "eea1e061", "efa1e061",
    "f0a1e061", "f1a1e061", "f2a1e061", "f3a1e061", "f4a1e061", "f5a1e061", "f6a1e061", "f7a1e061", "f8a1e061", "f9a1e061", "faa1e061", "fba1e061", "fca1e061", "fda1e061", "fea1e061", "ffa1e061"
]
                        for ids in items_ids:
                            self.client0500.send(bytes.fromhex(f"080000005a08cdede39a31100820062a4e0a1808f680e960100120ffffffffffffffffff012801380140020a1808b185a661100120ffffffffffffffffff012801380140020a1808{ids}100120ffffffffffffffffff01280138014002080000002708cdede39a31100820032a1b0a0708f680e96010010a0708b185a66110010a0708{ids}1001"))
                    except:
                        pass
                if b"/proxy3" in dataS:
                    try:
                        items_ids = ['d49be660', 'd59be660', 'd69be660', 'd79be660', 'd89be660', 'd99be660', 'da9be660', 'db9be660', 'dc9be660', 'dd9be660', 'de9be660', 'df9be660', 'e09be660', 'e19be660', 'e29be660', 'e39be660', 'e49be660', 'e59be660', 'e69be660', 'e79be660', 'e89be660', 'e99be660', 'ea9be660', 'eb9be660', 'ec9be660', 'ed9be660', 'ee9be660', 'ef9be660', 'f09be660', 'f19be660', 'f29be660', 'f39be660', 'f49be660', 'f59be660', 'f69be660', 'f79be660', 'f89be660', 'f99be660', 'fa9be660', 'fb9be660', 'fc9be660', 'fd9be660', 'fe9be660', 'ff9be660', '809ce660', '819ce660', '829ce660', '839ce660', '849ce660', '859ce660', '869ce660', '879ce660', '889ce660', '899ce660', '8a9ce660', '8b9ce660', '8c9ce660', '8d9ce660', '8e9ce660', '8f9ce660', 'c191e660', 'c291e660', 'c391e660', 'c491e660', 'c591e660', 'c691e660', 'c791e660', 'c891e660', 'c991e660', 'ca91e660', 'cb91e660', 'cc91e660', 'cd91e660', 'ce91e660', 'cf91e660', 'd091e660', 'd191e660', 'd291e660', 'd391e660', 'd491e660', 'd591e660', 'd691e660', 'd791e660', 'd891e660', 'd991e660', 'da91e660', 'db91e660', 'dc91e660', 'dd91e660', 'de91e660', 'df91e660', 'e091e660', 'e191e660', 'e291e660', 'e391e660', 'e491e660', 'e591e660', 'e691e660', 'e791e660', 'e891e660', 'e991e660', 'ea91e660', 'eb91e660', 'ec91e660', 'ed91e660', 'ee91e660', 'ef91e660', 'f091e660', 'f191e660', 'f291e660', 'f391e660', 'f491e660', 'f591e660', 'f691e660', 'f791e660', 'f891e660', 'f991e660', 'fa91e660', 'fb91e660', 'fc91e660', 'fd91e660', 'fe91e660', 'ff91e660', '8092e660', '8192e660', '8292e660', '8392e660', '8492e660', '8592e660', '8692e660', '8792e660', '8892e660', '8992e660', '8a92e660', '8b92e660', '8c92e660', '8d92e660', '8e92e660', '8f92e660', '9092e660', '9192e660', '9292e660', '9392e660', '9492e660', '9592e660', '9692e660', '9792e660', '9892e660', '9992e660', '9a92e660', '9b92e660', '9c92e660', '9d92e660', '9e92e660', '9f92e660', 'a092e660', 'a192e660', 'a292e660', 'a392e660', 'a492e660', 'a592e660', 'a692e660', 'a792e660', 'a892e660', 'a992e660', 'aa92e660', 'ab92e660', 'ac92e660', 'ad92e660', 'ae92e660', 'af92e660', 'b092e660', 'b192e660', 'b292e660', 'b392e660', 'b492e660', 'b592e660', 'b692e660', 'b792e660', 'b892e660', 'b992e660', 'ba92e660', 'bb92e660', 'bc92e660', 'bd92e660', 'be92e660', 'bf92e660', 'c092e660', 'c192e660', 'c292e660', 'c392e660', 'c492e660', 'c592e660', 'c692e660', 'c792e660', 'c892e660', 'c992e660', 'ca92e660', 'cb92e660', 'cc92e660', 'cd92e660', 'ce92e660', 'cf92e660', 'd092e660', 'd192e660', 'd292e660', 'd392e660', 'd492e660', 'd592e660', 'd692e660', 'd792e660', 'd892e660', 'd992e660', 'da92e660', 'db92e660', 'dc92e660', 'dd92e660', 'de92e660', 'df92e660', 'e092e660', 'e192e660', 'e292e660', 'e392e660', 'e492e660', 'e592e660', 'e692e660', 'e792e660', 'e892e660', 'e992e660', 'ea92e660', 'eb92e660', 'ec92e660', 'ed92e660', 'ee92e660', 'ef92e660', 'f092e660', 'f192e660', 'f292e660', 'f392e660', 'f492e660', 'f592e660', 'f692e660', 'f792e660', 'f892e660', 'f992e660', 'fa92e660', 'fb92e660', 'fc92e660', 'fd92e660', 'fe92e660', 'ff92e660', '8093e660', '8193e660', '8293e660', '8393e660', '8493e660', '8593e660', '8693e660', '8793e660', '8893e660', '8993e660', '8a93e660', '8b93e660', '8c93e660', '8d93e660', '8e93e660', '8f93e660', '9093e660', '9193e660', '9293e660', '9393e660', '9493e660', '9593e660', '9693e660', '9793e660', '9893e660', '9993e660', '9a93e660', '9b93e660',  'c494e660', 'c594e660', 'c694e660', 'c794e660', 'c894e660', 'c994e660', 'ca94e660', 'cb94e660', 'cc94e660', 'cd94e660', 'ce94e660', 'cf94e660', 'd094e660', 'd194e660', 'd294e660', 'd394e660', 'd494e660', 'd594e660', 'd694e660', 'd794e660', 'd894e660', 'd994e660', 'da94e660', 'db94e660', 'dc94e660', 'dd94e660', 'de94e660', 'df94e660', 'e094e660', 'e194e660', 'e294e660', 'e394e660', 'e494e660', 'e594e660', 'e694e660', 'e794e660', 'e894e660', 'e994e660', 'ea94e660', 'eb94e660', 'ec94e660', 'ed94e660', 'ee94e660', 'ef94e660', 'f094e660', 'f194e660', 'f294e660', 'f394e660', 'f494e660', 'f594e660', 'f694e660', 'f794e660', 'f894e660', 'f994e660', 'fa94e660', 'fb94e660', 'fc94e660', 'fd94e660', 'fe94e660', 'ff94e660', '8095e660', '8195e660', '8295e660', '8395e660', '8495e660', '8595e660', '8695e660', '8795e660', '8895e660', '8995e660', '8a95e660', '8b95e660', '8c95e660', '8d95e660', '8e95e660', '8f95e660', '9095e660', '9195e660', '9295e660', '9395e660', '9495e660', '9595e660', '9695e660', '9795e660', '9895e660', '9995e660', '9a95e660', '9b95e660', '9c95e660', '9d95e660', '9e95e660', '9f95e660', 'a095e660', 'a195e660', 'a295e660', 'a395e660',"ddd9e860","b0a3e860","ac90e960","a094e660","9f94e660","9e94e660","9d94e660","9c94e660"]
                        for ids in items_ids:
                            self.client0500.send(bytes.fromhex(f"080000005a08cdede39a31100820062a4e0a1808f680e960100120ffffffffffffffffff012801380140020a1808b185a661100120ffffffffffffffffff012801380140020a1808{ids}100120ffffffffffffffffff01280138014002080000002708cdede39a31100820032a1b0a0708f680e96010010a0708b185a66110010a0708{ids}1001"))
                    except:
                        pass
                if   b"/proxy4" in dataS:
                    try:
                        items_ids = ['c1b5ce64', 'c2b5ce64', 'c3b5ce64', 'c4b5ce64', 'c5b5ce64', 'c6b5ce64', 'c7b5ce64', 'c8b5ce64', 'c9b5ce64', 'cab5ce64', 'cbb5ce64', 'ccb5ce64', 'cdb5ce64', 'ceb5ce64', 'cfb5ce64', 'd0b5ce64', 'd1b5ce64', 'd2b5ce64', 'd3b5ce64', 'd4b5ce64', 'd5b5ce64', 'd6b5ce64', 'd7b5ce64', 'd8b5ce64', 'd9b5ce64', 'dab5ce64', 'dbb5ce64', 'dcb5ce64', 'ddb5ce64', 'deb5ce64', 'dfb5ce64', 'e0b5ce64', 'e1b5ce64', 'e2b5ce64', 'e3b5ce64', 'e4b5ce64', 'e5b5ce64', 'e6b5ce64', 'e7b5ce64', 'e8b5ce64', 'e9b5ce64', 'eab5ce64', 'ebb5ce64', 'ecb5ce64', 'edb5ce64', 'eeb5ce64', 'efb5ce64', 'f0b5ce64', 'f1b5ce64', 'f2b5ce64', 'f3b5ce64', 'f4b5ce64', 'f5b5ce64', 'f6b5ce64', 'f7b5ce64', 'f8b5ce64', 'f9b5ce64', 'fab5ce64', 'fbb5ce64', 'fcb5ce64', 'fdb5ce64', 'feb5ce64', 'ffb5ce64', '80b6ce64', '81b6ce64', '82b6ce64', '83b6ce64', '84b6ce64', '85b6ce64', '86b6ce64', '87b6ce64', '88b6ce64', '89b6ce64', '8ab6ce64', '8bb6ce64', '8cb6ce64', '8db6ce64', '8eb6ce64', '8fb6ce64', '90b6ce64', '91b6ce64', '92b6ce64', '93b6ce64', '94b6ce64', '95b6ce64', '96b6ce64', '97b6ce64', '98b6ce64', '99b6ce64', '9ab6ce64', '9bb6ce64', '9cb6ce64', '9db6ce64', '9eb6ce64', '9fb6ce64', 'a0b6ce64', 'a1b6ce64', 'a2b6ce64', 'a3b6ce64', 'a4b6ce64', 'a5b6ce64', 'a6b6ce64', 'a7b6ce64', 'a8b6ce64', 'a9b6ce64', 'aab6ce64', 'abb6ce64', 'acb6ce64', 'adb6ce64', 'aeb6ce64', 'afb6ce64', 'b0b6ce64', 'b1b6ce64', 'b2b6ce64', 'b3b6ce64', 'b4b6ce64', 'b5b6ce64', 'b6b6ce64', 'b7b6ce64', 'b8b6ce64', 'b9b6ce64', 'bab6ce64', 'bbb6ce64', 'bcb6ce64', 'bdb6ce64', 'beb6ce64', 'bfb6ce64', 'c0b6ce64', 'c1b6ce64', 'c2b6ce64', 'c3b6ce64', 'c4b6ce64', 'c5b6ce64', 'c6b6ce64', 'c7b6ce64', 'c8b6ce64', 'c9b6ce64', 'cab6ce64', 'cbb6ce64', 'ccb6ce64', 'cdb6ce64', 'ceb6ce64', 'cfb6ce64', 'd0b6ce64', 'd1b6ce64', 'd2b6ce64', 'd3b6ce64', 'd4b6ce64', 'd5b6ce64', 'd6b6ce64', 'd7b6ce64', 'd8b6ce64', 'd9b6ce64', 'dab6ce64', 'dbb6ce64', 'dcb6ce64', 'ddb6ce64', 'deb6ce64', 'dfb6ce64', 'e0b6ce64', 'e1b6ce64', 'e2b6ce64', 'e3b6ce64', 'e4b6ce64', 'e5b6ce64', 'e6b6ce64', 'e7b6ce64', 'e8b6ce64', 'e9b6ce64', 'eab6ce64', 'ebb6ce64', 'ecb6ce64', 'edb6ce64', 'eeb6ce64', 'efb6ce64', 'f0b6ce64', 'f1b6ce64', 'f2b6ce64', 'f3b6ce64', 'f4b6ce64', 'f5b6ce64', 'f6b6ce64', 'f7b6ce64', 'f8b6ce64', 'f9b6ce64', 'fab6ce64', 'fbb6ce64', 'fcb6ce64', 'fdb6ce64', 'feb6ce64', 'ffb6ce64', '80b7ce64', '81b7ce64', '82b7ce64', '83b7ce64', '84b7ce64', '85b7ce64', '86b7ce64', '87b7ce64', '88b7ce64', '89b7ce64', '8ab7ce64', '8bb7ce64', '8cb7ce64', '8db7ce64', '8eb7ce64', '8fb7ce64', '90b7ce64', '91b7ce64', '92b7ce64', '93b7ce64', '94b7ce64', '95b7ce64', '96b7ce64', '97b7ce64', '98b7ce64', '99b7ce64', '9ab7ce64', '9bb7ce64', '9cb7ce64', '9db7ce64', '9eb7ce64', '9fb7ce64', 'a0b7ce64', 'a1b7ce64', 'a2b7ce64', 'a3b7ce64', 'a4b7ce64', 'a5b7ce64', 'a6b7ce64', 'a7b7ce64', 'a8b7ce64', 'a9b7ce64', 'aab7ce64', 'abb7ce64', 'acb7ce64', 'adb7ce64', 'aeb7ce64', 'afb7ce64', 'b0b7ce64', 'b1b7ce64', 'b2b7ce64', 'b3b7ce64', 'b4b7ce64', 'b5b7ce64', 'b6b7ce64', 'b7b7ce64', 'b8b7ce64', 'b9b7ce64', 'bab7ce64', 'bbb7ce64', 'bcb7ce64', 'bdb7ce64', 'beb7ce64', 'bfb7ce64', 'c0b7ce64', 'c1b7ce64', 'c2b7ce64', 'c3b7ce64', 'c4b7ce64', 'c5b7ce64', 'c6b7ce64', 'c7b7ce64', 'c8b7ce64', 'c9b7ce64', 'cab7ce64', 'cbb7ce64', 'ccb7ce64', 'cdb7ce64', 'ceb7ce64', 'cfb7ce64', 'd0b7ce64', 'd1b7ce64', 'd2b7ce64', 'd3b7ce64', 'd4b7ce64', 'd5b7ce64', 'd6b7ce64', 'd7b7ce64', 'd8b7ce64', 'd9b7ce64', 'dab7ce64', 'dbb7ce64', 'dcb7ce64', 'ddb7ce64', 'deb7ce64', 'dfb7ce64', 'e0b7ce64', 'e1b7ce64', 'e2b7ce64', 'e3b7ce64', 'e4b7ce64', 'e5b7ce64', 'e6b7ce64', 'e7b7ce64', 'e8b7ce64', 'e9b7ce64', 'eab7ce64', 'ebb7ce64', 'ecb7ce64', 'edb7ce64', 'eeb7ce64', 'efb7ce64', 'f0b7ce64', 'f1b7ce64', 'f2b7ce64', 'f3b7ce64', 'f4b7ce64', 'f5b7ce64', 'f6b7ce64', 'f7b7ce64', 'f8b7ce64', 'f9b7ce64', 'fab7ce64', 'fbb7ce64', 'fcb7ce64', 'fdb7ce64', 'feb7ce64', 'ffb7ce64', '80b8ce64', '81b8ce64', '82b8ce64', '83b8ce64', '84b8ce64', '85b8ce64', '86b8ce64', '87b8ce64', '88b8ce64', '89b8ce64', '8ab8ce64', '8bb8ce64', '8cb8ce64', '8db8ce64', '8eb8ce64', '8fb8ce64', '90b8ce64', '91b8ce64', '92b8ce64', '93b8ce64', '94b8ce64', '95b8ce64', '96b8ce64', '97b8ce64', '98b8ce64', '99b8ce64', '9ab8ce64', '9bb8ce64', '9cb8ce64', '9db8ce64', '9eb8ce64', '9fb8ce64', 'a0b8ce64', 'a1b8ce64', 'a2b8ce64', 'a3b8ce64', 'a4b8ce64', 'a5b8ce64', 'a6b8ce64', 'a7b8ce64', 'a8b8ce64', 'a9b8ce64', 'aab8ce64', 'abb8ce64', 'acb8ce64', 'adb8ce64', 'aeb8ce64', 'afb8ce64', 'b0b8ce64', 'b1b8ce64', 'b2b8ce64', 'b3b8ce64', 'b4b8ce64', 'b5b8ce64', 'b6b8ce64', 'b7b8ce64', 'b8b8ce64', 'b9b8ce64', 'bab8ce64', 'bbb8ce64', 'bcb8ce64', 'bdb8ce64', 'beb8ce64', 'bfb8ce64', 'c0b8ce64', 'c1b8ce64', 'c2b8ce64', 'c3b8ce64', 'c4b8ce64', 'c5b8ce64', 'c6b8ce64', 'c7b8ce64', 'c8b8ce64', 'c9b8ce64', 'cab8ce64', 'cbb8ce64', 'ccb8ce64', 'cdb8ce64', 'ceb8ce64', 'cfb8ce64', 'd0b8ce64', 'd1b8ce64', 'd2b8ce64', 'd3b8ce64', 'd4b8ce64', 'd5b8ce64', 'd6b8ce64', 'd7b8ce64', 'd8b8ce64', 'd9b8ce64', 'dab8ce64', 'dbb8ce64', 'dcb8ce64', 'ddb8ce64', 'deb8ce64', 'dfb8ce64', 'e0b8ce64', 'e1b8ce64', 'e2b8ce64', 'e3b8ce64', 'e4b8ce64', 'e5b8ce64', 'e6b8ce64', 'e7b8ce64', 'e8b8ce64', 'e9b8ce64', 'eab8ce64', 'ebb8ce64', 'ecb8ce64', 'edb8ce64', 'eeb8ce64', 'efb8ce64', 'f0b8ce64', 'f1b8ce64', 'f2b8ce64', 'f3b8ce64', 'f4b8ce64', 'f5b8ce64', 'f6b8ce64', 'f7b8ce64', 'f8b8ce64', 'f9b8ce64', 'fab8ce64', 'fbb8ce64', 'fcb8ce64', 'fdb8ce64', 'feb8ce64', 'ffb8ce64', '80b9ce64', '81b9ce64', '82b9ce64', '83b9ce64', '84b9ce64', '85b9ce64', '86b9ce64', '87b9ce64', '88b9ce64', '89b9ce64', '8ab9ce64', '8bb9ce64', '8cb9ce64', '8db9ce64', '8eb9ce64', '8fb9ce64', '90b9ce64', '91b9ce64', '92b9ce64', '93b9ce64', '94b9ce64', '95b9ce64', '96b9ce64', '97b9ce64', '98b9ce64', '99b9ce64', '9ab9ce64', '9bb9ce64', '9cb9ce64', '9db9ce64', '9eb9ce64', '9fb9ce64', 'a0b9ce64', 'a1b9ce64', 'a2b9ce64', 'a3b9ce64', 'a4b9ce64', 'a5b9ce64', 'a6b9ce64', 'a7b9ce64', 'a8b9ce64', 'a9b9ce64', 'aab9ce64', 'abb9ce64', 'acb9ce64', 'adb9ce64', 'aeb9ce64', 'afb9ce64', 'b0b9ce64', 'b1b9ce64', 'b2b9ce64', 'b3b9ce64', 'b4b9ce64', 'b5b9ce64', 'b6b9ce64', 'b7b9ce64', 'b8b9ce64', 'b9b9ce64', 'bab9ce64', 'bbb9ce64', 'bcb9ce64', 'bdb9ce64', 'beb9ce64', 'bfb9ce64', 'c0b9ce64', 'c1b9ce64', 'c2b9ce64', 'c3b9ce64', 'c4b9ce64', 'c5b9ce64', 'c6b9ce64', 'c7b9ce64', 'c8b9ce64', 'c9b9ce64', 'cab9ce64', 'cbb9ce64', 'ccb9ce64', 'cdb9ce64', 'ceb9ce64', 'cfb9ce64', 'd0b9ce64', 'd1b9ce64', 'd2b9ce64', 'd3b9ce64', 'd4b9ce64', 'd5b9ce64', 'd6b9ce64', 'd7b9ce64', 'd8b9ce64', 'd9b9ce64', 'dab9ce64', 'dbb9ce64', 'dcb9ce64', 'ddb9ce64', 'deb9ce64', 'dfb9ce64', 'e0b9ce64', 'e1b9ce64', 'e2b9ce64', 'e3b9ce64', 'e4b9ce64', 'e5b9ce64', 'e6b9ce64', 'e7b9ce64', 'e8b9ce64', 'e9b9ce64', 'eab9ce64', 'ebb9ce64', 'ecb9ce64', 'edb9ce64', 'eeb9ce64', 'efb9ce64', 'f0b9ce64', 'f1b9ce64', 'f2b9ce64', 'f3b9ce64', 'f4b9ce64', 'f5b9ce64', 'f6b9ce64', 'f7b9ce64', 'f8b9ce64', 'f9b9ce64', 'fab9ce64', 'fbb9ce64', 'fcb9ce64', 'fdb9ce64', 'feb9ce64', 'ffb9ce64', '80bace64', '81bace64', '82bace64', '83bace64', '84bace64', '85bace64', '86bace64', '87bace64', '88bace64', '89bace64', '8abace64', '8bbace64', '8cbace64', '8dbace64', '8ebace64', '8fbace64', '90bace64', '91bace64', '92bace64', '93bace64', '94bace64', '95bace64', '96bace64', '97bace64', '98bace64', '99bace64', '9abace64', '9bbace64', '9cbace64', '9dbace64', '9ebace64', '9fbace64', 'a0bace64', 'a1bace64', 'a2bace64', 'a3bace64', 'a4bace64', 'a5bace64', 'a6bace64', 'a7bace64', 'a8bace64', 'a9bace64', 'aabace64', 'abbace64', 'acbace64', 'adbace64', 'aebace64', 'afbace64', 'b0bace64', 'b1bace64', 'b2bace64', 'b3bace64', 'b4bace64', 'b5bace64', 'b6bace64', 'b7bace64', 'b8bace64', 'b9bace64', 'babace64', 'bbbace64', 'bcbace64', 'bdbace64']
                        for ids in items_ids:
                            self.client0500.send(bytes.fromhex(f"080000005a08cdede39a31100820062a4e0a1808f680e960100120ffffffffffffffffff012801380140020a1808b185a661100120ffffffffffffffffff012801380140020a1808{ids}100120ffffffffffffffffff01280138014002080000002708cdede39a31100820032a1b0a0708f680e96010010a0708b185a66110010a0708{ids}1001"))
                    except:
                        pass
                if   b"/proxy5" in dataS:
                    try:
                        items_ids = [ 'bebace64', 'bfbace64', 'c0bace64', 'c1bace64', 'c2bace64', 'c3bace64', 'c4bace64', 'c5bace64', 'c6bace64', 'c7bace64', 'c8bace64', 'c9bace64', 'cabace64', 'cbbace64', 'ccbace64', 'cdbace64', 'cebace64', 'cfbace64', 'd0bace64', 'd1bace64', 'd2bace64', 'd3bace64', 'd4bace64', 'd5bace64', 'd6bace64', 'd7bace64', 'd8bace64', 'd9bace64', 'dabace64', 'dbbace64', 'dcbace64', 'ddbace64', 'debace64', 'dfbace64', 'e0bace64', 'e1bace64', 'e2bace64', 'e3bace64', 'e4bace64', 'e5bace64', 'e6bace64', 'e7bace64', 'e8bace64', 'e9bace64', 'eabace64', 'ebbace64', 'ecbace64', 'edbace64', 'eebace64', 'efbace64', 'f0bace64', 'f1bace64', 'f2bace64', 'f3bace64', 'f4bace64', 'f5bace64', 'f6bace64', 'f7bace64', 'f8bace64', 'f9bace64', 'fabace64', 'fbbace64', 'fcbace64', 'fdbace64', 'febace64', 'ffbace64', '80bbce64', '81bbce64', '82bbce64', '83bbce64', '84bbce64', '85bbce64', '86bbce64', '87bbce64', '88bbce64', '89bbce64', '8abbce64', '8bbbce64', '8cbbce64', '8dbbce64', '8ebbce64', '8fbbce64', '90bbce64', '91bbce64', '92bbce64', '93bbce64', '94bbce64', '95bbce64', '96bbce64', '97bbce64', '98bbce64', '99bbce64', '9abbce64', '9bbbce64', '9cbbce64', '9dbbce64', '9ebbce64', '9fbbce64', 'a0bbce64', 'a1bbce64', 'a2bbce64', 'a3bbce64', 'a4bbce64', 'a5bbce64', 'a6bbce64', 'a7bbce64', 'a8bbce64', 'a9bbce64', 'aabbce64', 'abbbce64', 'acbbce64', 'adbbce64', 'aebbce64', 'afbbce64', 'b0bbce64', 'b1bbce64', 'b2bbce64', 'b3bbce64', 'b4bbce64', 'b5bbce64', 'b6bbce64', 'b7bbce64', 'b8bbce64', 'b9bbce64', 'babbce64', 'bbbbce64', 'bcbbce64', 'bdbbce64', 'bebbce64', 'bfbbce64', 'c0bbce64', 'c1bbce64', 'c2bbce64', 'c3bbce64', 'c4bbce64', 'c5bbce64', 'c6bbce64', 'c7bbce64', 'c8bbce64', 'c9bbce64', 'cabbce64', 'cbbbce64', 'ccbbce64', 'cdbbce64', 'cebbce64', 'cfbbce64', 'd0bbce64', 'd1bbce64', 'd2bbce64', 'd3bbce64', 'd4bbce64', 'd5bbce64', 'd6bbce64', 'd7bbce64', 'd8bbce64', 'd9bbce64', 'dabbce64', 'dbbbce64', 'dcbbce64', 'ddbbce64', 'debbce64', 'dfbbce64', 'e0bbce64', 'e1bbce64', 'e2bbce64', 'e3bbce64', 'e4bbce64', 'e5bbce64', 'e6bbce64', 'e7bbce64', 'e8bbce64', 'e9bbce64', 'eabbce64', 'ebbbce64', 'ecbbce64', 'edbbce64', 'eebbce64', 'efbbce64', 'f0bbce64', 'f1bbce64', 'f2bbce64', 'f3bbce64', 'f4bbce64', 'f5bbce64', 'f6bbce64', 'f7bbce64', 'f8bbce64', 'f9bbce64', 'fabbce64', 'fbbbce64', 'fcbbce64', 'fdbbce64', 'febbce64', 'ffbbce64', '80bcce64', '81bcce64', '82bcce64', '83bcce64', '84bcce64', '85bcce64', '86bcce64', '87bcce64', '88bcce64', '89bcce64', '8abcce64', '8bbcce64', '8cbcce64', '8dbcce64', '8ebcce64', '8fbcce64', '90bcce64', '91bcce64', '92bcce64', '93bcce64', '94bcce64', '95bcce64', '96bcce64', '97bcce64', '98bcce64', '99bcce64', '9abcce64', '9bbcce64', '9cbcce64', '9dbcce64', '9ebcce64', '9fbcce64', 'a0bcce64', 'a1bcce64', 'a2bcce64', 'a3bcce64', 'a4bcce64', 'a5bcce64', 'a6bcce64', 'a7bcce64', 'a8bcce64', 'a9bcce64', 'aabcce64', 'abbcce64', 'acbcce64', 'adbcce64', 'aebcce64', 'afbcce64', 'b0bcce64', 'b1bcce64', 'b2bcce64', 'b3bcce64', 'b4bcce64', 'b5bcce64', 'b6bcce64', 'b7bcce64', 'b8bcce64', 'b9bcce64', 'babcce64', 'bbbcce64', 'bcbcce64', 'bdbcce64', 'bebcce64', 'bfbcce64', 'c0bcce64', 'c1bcce64', 'c2bcce64', 'c3bcce64', 'c4bcce64', 'c5bcce64', 'c6bcce64', 'c7bcce64', 'c8bcce64', 'c9bcce64', 'cabcce64', 'cbbcce64', 'ccbcce64', 'cdbcce64', 'cebcce64', 'cfbcce64', 'd0bcce64', 'd1bcce64', 'd2bcce64', 'd3bcce64', 'd4bcce64', 'd5bcce64', 'd6bcce64', 'd7bcce64', 'd8bcce64', 'd9bcce64', 'dabcce64', 'dbbcce64', 'dcbcce64', 'ddbcce64', 'debcce64', 'dfbcce64', 'e0bcce64', 'e1bcce64', 'e2bcce64', 'e3bcce64', 'e4bcce64', 'e5bcce64', 'e6bcce64', 'e7bcce64', 'e8bcce64', 'e9bcce64', 'eabcce64', 'ebbcce64', 'ecbcce64', 'edbcce64', 'eebcce64', 'efbcce64', 'f0bcce64', 'f1bcce64', 'f2bcce64', 'f3bcce64', 'f4bcce64', 'f5bcce64', 'f6bcce64', 'f7bcce64', 'f8bcce64', 'f9bcce64', 'fabcce64', 'fbbcce64', 'fcbcce64', 'fdbcce64', 'febcce64', 'ffbcce64', '80bdce64', '81bdce64', '82bdce64', '83bdce64', '84bdce64', '85bdce64', '86bdce64', '87bdce64', '88bdce64', '89bdce64', '8abdce64', '8bbdce64', '8cbdce64', '8dbdce64', '8ebdce64', '8fbdce64', '90bdce64', '91bdce64', '92bdce64', '93bdce64', '94bdce64', '95bdce64', '96bdce64', '97bdce64', '98bdce64', '99bdce64', '9abdce64', '9bbdce64', '9cbdce64', '9dbdce64', '9ebdce64', '9fbdce64', 'a0bdce64', 'a1bdce64', 'a2bdce64', 'a3bdce64', 'a4bdce64', 'a5bdce64', 'a6bdce64', 'a7bdce64', 'a8bdce64', 'a9bdce64', 'aabdce64', 'abbdce64', 'acbdce64', 'adbdce64', 'aebdce64', 'afbdce64', 'b0bdce64', 'b1bdce64', 'b2bdce64', 'b3bdce64', 'b4bdce64', 'b5bdce64', 'b6bdce64', 'b7bdce64', 'b8bdce64', 'b9bdce64', 'babdce64', 'bbbdce64', 'bcbdce64', 'bdbdce64', 'bebdce64', 'bfbdce64', 'c0bdce64', 'c1bdce64', 'c2bdce64', 'c3bdce64', 'c4bdce64', 'c5bdce64', 'c6bdce64', 'c7bdce64', 'c8bdce64', 'c9bdce64', 'cabdce64', 'cbbdce64', 'ccbdce64', 'cdbdce64', 'cebdce64', 'cfbdce64', 'd0bdce64', 'd1bdce64', 'd2bdce64', 'd3bdce64', 'd4bdce64', 'd5bdce64', 'd6bdce64', 'd7bdce64', 'd8bdce64', 'd9bdce64', 'dabdce64', 'dbbdce64', 'dcbdce64', 'ddbdce64', 'debdce64', 'dfbdce64', 'e0bdce64', 'e1bdce64', 'e2bdce64', 'e3bdce64', 'e4bdce64', 'e5bdce64', 'e6bdce64', 'e7bdce64', 'e8bdce64', 'e9bdce64', 'eabdce64', 'ebbdce64', 'ecbdce64', 'edbdce64', 'eebdce64', 'efbdce64', 'f0bdce64', 'f1bdce64', 'f2bdce64', 'f3bdce64', 'f4bdce64', 'f5bdce64', 'f6bdce64', 'f7bdce64', 'f8bdce64', 'f9bdce64', 'fabdce64', 'fbbdce64', 'fcbdce64', 'fdbdce64', 'febdce64', 'ffbdce64', '80bece64', '81bece64', '82bece64', '83bece64', '84bece64', '85bece64', '86bece64', '87bece64', '88bece64', '89bece64', '8abece64', '8bbece64', '8cbece64', '8dbece64', '8ebece64', '8fbece64', '90bece64', '91bece64', '92bece64', '93bece64', '94bece64', '95bece64', '96bece64', '97bece64', '98bece64', '99bece64', '9abece64', '9bbece64', '9cbece64', '9dbece64', '9ebece64', '9fbece64', 'a0bece64', 'a1bece64', 'a2bece64', 'a3bece64', 'a4bece64', 'a5bece64', 'a6bece64', 'a7bece64', 'a8bece64', 'a9bece64', 'aabece64', 'abbece64', 'acbece64', 'adbece64', 'aebece64']
                        for ids in items_ids:
                            self.client0500.send(bytes.fromhex(f"080000005a08cdede39a31100820062a4e0a1808f680e960100120ffffffffffffffffff012801380140020a1808b185a661100120ffffffffffffffffff012801380140020a1808{ids}100120ffffffffffffffffff01280138014002080000002708cdede39a31100820032a1b0a0708f680e96010010a0708b185a66110010a0708{ids}1001"))

                    except:
                        pass
                if   b"/proxy6" in dataS:
                    try:
                        items_ids = ['8196a361', '8296a361', '8396a361', '8496a361', '8596a361', '8696a361', '8796a361', '8896a361', '8996a361', '8a96a361', '8b96a361', '8c96a361', '8d96a361', '8e96a361', '8f96a361', '9096a361', '9196a361', '9296a361', '9396a361', '9496a361', '9596a361', '9696a361', '9796a361', '9896a361', '9996a361', '9a96a361', '9b96a361', '9c96a361', '9d96a361', '9e96a361', '9f96a361', 'a096a361', 'a196a361', 'a296a361', 'a396a361', 'a496a361', 'a596a361', 'a696a361', 'a796a361', 'a896a361', 'a996a361', 'aa96a361', 'ab96a361', 'ac96a361', 'ad96a361', 'ae96a361', 'af96a361', 'b096a361', 'b196a361', 'b296a361', 'b396a361', 'b496a361', 'b596a361', 'b696a361', 'b796a361', 'b896a361', 'b996a361', 'ba96a361', 'bb96a361', 'bc96a361', 'bd96a361', 'be96a361', 'bf96a361', 'c096a361', 'c196a361', 'c296a361', 'c396a361', 'c496a361', 'c596a361', 'c696a361', 'c796a361', 'c896a361', 'c996a361', 'ca96a361', 'cb96a361', 'cc96a361', 'cd96a361', 'ce96a361', 'cf96a361', 'd096a361', 'd196a361', 'd296a361', 'd396a361', 'd496a361', 'd596a361', 'd696a361', 'd796a361', 'd896a361', 'd996a361', 'da96a361', 'db96a361', 'dc96a361', 'dd96a361', 'de96a361', 'df96a361', 'e096a361', 'e196a361', 'e296a361', 'e396a361', 'e496a361', 'e596a361', 'e696a361', 'e796a361', 'e896a361', 'e996a361', 'ea96a361', 'eb96a361', 'ec96a361', 'ed96a361', 'ee96a361', 'ef96a361', 'f096a361', 'f196a361', 'f296a361', 'f396a361', 'f496a361', 'f596a361', 'f696a361', 'f796a361', 'f896a361', 'f996a361', 'fa96a361', 'fb96a361', 'fc96a361', 'fd96a361', 'fe96a361', 'ff96a361', '8097a361', '8197a361', '8297a361', '8397a361', '8497a361', '8597a361', '8697a361', '8797a361', '8897a361', '8997a361', '8a97a361', '8b97a361', '8c97a361', '8d97a361', '8e97a361', '8f97a361', '9097a361', '9197a361', '9297a361', '9397a361', '9497a361', '9597a361', '9697a361', '9797a361', '9897a361', '9997a361', '9a97a361', '9b97a361', '9c97a361', '9d97a361', '9e97a361', '9f97a361', 'a097a361', 'a197a361', 'a297a361', 'a397a361', 'a497a361', 'a597a361', 'a697a361', 'a797a361', 'a897a361', 'a997a361', 'aa97a361', 'ab97a361', 'ac97a361', 'ad97a361', 'ae97a361', 'af97a361', 'b097a361', 'b197a361', 'b297a361', 'b397a361', 'b497a361', 'b597a361', 'b697a361', 'b797a361', 'b897a361', 'b997a361', 'ba97a361', 'bb97a361', 'bc97a361', 'bd97a361', 'be97a361', 'bf97a361', 'c097a361', 'c197a361', 'c297a361', 'c397a361', 'c497a361', 'c597a361', 'c697a361', 'c797a361', 'c897a361', 'c997a361', 'ca97a361', 'cb97a361', 'cc97a361', 'cd97a361', 'ce97a361', 'cf97a361', 'd097a361', 'd197a361', 'd297a361', 'd397a361', 'd497a361', 'd597a361', 'd697a361', 'd797a361', 'd897a361', 'd997a361', 'da97a361', 'db97a361', 'dc97a361', 'dd97a361', 'de97a361', 'df97a361', 'e097a361', 'e197a361', 'e297a361', 'e397a361', 'e497a361', 'e597a361', 'e697a361', 'e797a361', 'e897a361', 'e997a361', 'ea97a361', 'eb97a361', 'ec97a361', 'ed97a361', 'ee97a361', 'ef97a361', 'f097a361', 'f197a361', 'f297a361', 'f397a361', 'f497a361', 'f597a361', 'f697a361', 'f797a361', 'f897a361', 'f997a361', 'fa97a361', 'fb97a361', 'fc97a361', 'fd97a361', 'fe97a361', 'ff97a361', '8098a361', '8198a361', '8298a361', '8398a361', '8498a361', '8598a361', '8698a361', '8798a361', '8898a361', '8998a361', '8a98a361', '8b98a361', '8c98a361', '8d98a361', '8e98a361', '8f98a361', '9098a361', '9198a361', '9298a361', '9398a361', '9498a361', '9598a361', '9698a361', '9798a361', '9898a361', '9998a361', '9a98a361', '9b98a361', '9c98a361', '9d98a361', '9e98a361', '9f98a361', 'a098a361', 'a198a361', 'a298a361', 'a398a361', 'a498a361', 'a598a361', 'a698a361', 'a798a361', 'a898a361', 'a998a361', 'aa98a361', 'ab98a361', 'ac98a361', 'ad98a361', 'ae98a361', 'af98a361', 'b098a361', 'b198a361', 'b298a361', 'b398a361', 'b498a361', 'b598a361', 'b698a361', 'b798a361', 'b898a361', 'b998a361', 'ba98a361', 'bb98a361', 'bc98a361', 'bd98a361', 'be98a361', 'bf98a361', 'c098a361', 'c198a361', 'c298a361', 'c398a361', 'c498a361', 'c598a361', 'c698a361', 'c798a361', 'c898a361', 'c998a361', 'ca98a361', 'cb98a361', 'cc98a361', 'cd98a361', 'ce98a361', 'cf98a361', 'd098a361', 'd198a361', 'd298a361', 'd398a361', 'd498a361', 'd598a361', 'd698a361', 'd798a361', 'd898a361', 'd998a361', 'da98a361', 'db98a361', 'dc98a361', 'dd98a361', 'de98a361', 'df98a361', 'e098a361', 'e198a361', 'e298a361', 'e398a361', 'e498a361', 'e598a361', 'e698a361', 'e798a361', 'e898a361', 'e998a361', 'ea98a361', 'eb98a361', 'ec98a361', 'ed98a361', 'ee98a361', 'ef98a361', 'f098a361', 'f198a361', 'f298a361', 'f398a361', 'f498a361', 'f598a361', 'f698a361', 'f798a361', 'f898a361', 'f998a361', 'fa98a361', 'fb98a361', 'fc98a361', 'fd98a361', 'fe98a361', 'ff98a361', '8099a361', '8199a361', '8299a361', '8399a361', '8499a361', '8599a361', '8699a361', '8799a361', '8899a361', '8999a361', '8a99a361', '8b99a361', '8c99a361', '8d99a361', '8e99a361', '8f99a361', '9099a361', '9199a361', '9299a361', '9399a361', '9499a361', '9599a361', '9699a361', '9799a361', '9899a361', '9999a361', '9a99a361', '9b99a361', '9c99a361', '9d99a361', '9e99a361', '9f99a361', 'a099a361', 'a199a361', 'a299a361', 'a399a361', 'a499a361', 'a599a361', 'a699a361', 'a799a361', 'a899a361', 'a999a361', 'aa99a361', 'ab99a361', 'ac99a361', 'ad99a361', 'ae99a361', 'af99a361', 'b099a361', 'b199a361', 'b299a361', 'b399a361', 'b499a361', 'b599a361', 'b699a361', 'b799a361', 'b899a361', 'b999a361', 'ba99a361', 'bb99a361', 'bc99a361', 'bd99a361', 'be99a361', 'bf99a361', 'c099a361', 'c199a361', 'c299a361', 'c399a361', 'c499a361', 'c599a361', 'c699a361', 'c799a361', 'c899a361', 'c999a361', 'ca99a361', 'cb99a361', 'cc99a361', 'cd99a361', 'ce99a361', 'cf99a361', 'd099a361', 'd199a361', 'd299a361', 'd399a361', 'd499a361', 'd599a361', 'd699a361', 'd799a361', 'd899a361', 'd999a361', 'da99a361', 'db99a361', 'dc99a361', 'dd99a361', 'de99a361', 'df99a361', 'e099a361', 'e199a361', 'e299a361', 'e399a361', 'e499a361', 'e599a361', 'e699a361', 'e799a361', 'e899a361', 'e999a361', 'ea99a361', 'eb99a361', 'ec99a361', 'ed99a361', 'ee99a361', 'ef99a361', 'f099a361', 'f199a361', 'f299a361', 'f399a361', 'f499a361', 'f599a361', 'f699a361', 'f799a361', 'f899a361', 'f999a361', 'fa99a361', 'fb99a361', 'fc99a361', 'fd99a361', 'fe99a361', 'ff99a361', '809aa361', '819aa361', '829aa361', '839aa361', '849aa361', '859aa361', '869aa361', '879aa361', '889aa361', '899aa361', '8a9aa361', '8b9aa361', '8c9aa361', '8d9aa361', '8e9aa361', '8f9aa361', '909aa361', '919aa361', '929aa361', '939aa361', '949aa361', '959aa361', '969aa361', '979aa361', '989aa361', '999aa361', '9a9aa361', '9b9aa361', '9c9aa361', '9d9aa361', '9e9aa361', '9f9aa361', 'a09aa361', 'a19aa361', 'a29aa361', 'a39aa361', 'a49aa361', 'a59aa361', 'a69aa361', 'a79aa361', 'a89aa361', 'a99aa361', 'aa9aa361', 'ab9aa361', 'ac9aa361', 'ad9aa361', 'ae9aa361', 'af9aa361', 'b09aa361', 'b19aa361', 'b29aa361', 'b39aa361', 'b49aa361', 'b59aa361', 'b69aa361', 'b79aa361', 'b89aa361', 'b99aa361', 'ba9aa361', 'bb9aa361', 'bc9aa361', 'bd9aa361', 'be9aa361', 'bf9aa361', 'c09aa361', 'c19aa361', 'c29aa361', 'c39aa361', 'c49aa361', 'c59aa361', 'c69aa361', 'c79aa361', 'c89aa361', 'c99aa361', 'ca9aa361', 'cb9aa361', 'cc9aa361', 'cd9aa361', 'ce9aa361', 'cf9aa361', 'd09aa361', 'd19aa361', 'd29aa361', 'd39aa361', 'd49aa361', 'd59aa361', 'd69aa361', 'd79aa361', 'd89aa361', 'd99aa361', 'da9aa361', 'db9aa361', 'dc9aa361', 'dd9aa361', 'de9aa361', 'df9aa361', 'e09aa361', 'e19aa361', 'e29aa361', 'e39aa361', 'e49aa361', 'e59aa361', 'e69aa361', 'e79aa361', 'e89aa361', 'e99aa361', 'ea9aa361', 'eb9aa361', 'ec9aa361', 'ed9aa361', 'ee9aa361', 'ef9aa361', 'f09aa361', 'f19aa361', 'f29aa361', 'f39aa361', 'f49aa361', 'f59aa361', 'f69aa361', 'f79aa361', 'f89aa361', 'f99aa361', 'fa9aa361', 'fb9aa361', 'fc9aa361', 'fd9aa361', 'fe9aa361', 'ff9aa361', '809ba361', '819ba361', '829ba361', '839ba361', '849ba361', '859ba361', '869ba361', '879ba361', '889ba361', '899ba361', '8a9ba361', '8b9ba361', '8c9ba361', '8d9ba361', '8e9ba361', '8f9ba361', '909ba361', '919ba361', '929ba361', '939ba361', '949ba361', '959ba361', '969ba361', '979ba361', '989ba361', '999ba361', '9a9ba361', '9b9ba361', '9c9ba361', '9d9ba361', '9e9ba361', '9f9ba361', 'a09ba361', 'a19ba361', 'a29ba361', 'a39ba361', 'a49ba361', 'a59ba361', 'a69ba361', 'a79ba361', 'a89ba361', 'a99ba361', 'aa9ba361', 'ab9ba361', 'ac9ba361', 'ad9ba361', 'ae9ba361', 'af9ba361', 'b09ba361', 'b19ba361', 'b29ba361', 'b39ba361', 'b49ba361', 'b59ba361', 'b69ba361', 'b79ba361', 'b89ba361', 'b99ba361', 'ba9ba361', 'bb9ba361', 'bc9ba361', 'bd9ba361', 'be9ba361', 'bf9ba361', 'c09ba361', 'c19ba361', 'c29ba361', 'c39ba361', 'c49ba361', 'c59ba361', 'c69ba361', 'c79ba361', 'c89ba361', 'c99ba361', 'ca9ba361', 'cb9ba361', 'cc9ba361', 'cd9ba361', 'ce9ba361', 'cf9ba361', 'd09ba361', 'd19ba361', 'd29ba361', 'd39ba361', 'd49ba361', 'd59ba361', 'd69ba361', 'd79ba361', 'd89ba361', 'd99ba361', 'da9ba361', 'db9ba361', 'dc9ba361', 'dd9ba361', 'de9ba361', 'df9ba361', 'e09ba361', 'e19ba361', 'e29ba361', 'e39ba361', 'e49ba361', 'e59ba361', 'e69ba361', 'e79ba361', 'e89ba361', 'e99ba361', 'ea9ba361', 'eb9ba361', 'ec9ba361', 'ed9ba361', 'ee9ba361', 'ef9ba361', 'f09ba361', 'f19ba361', 'f29ba361', 'f39ba361', 'f49ba361', 'f59ba361', 'f69ba361', 'f79ba361', 'f89ba361', 'f99ba361', 'fa9ba361', 'fb9ba361', 'fc9ba361', 'fd9ba361', 'fe9ba361', 'ff9ba361', '809ca361', '819ca361', '829ca361', '839ca361', '849ca361', '859ca361', '869ca361', '879ca361', '889ca361', '899ca361', '8a9ca361', '8b9ca361', '8c9ca361', '8d9ca361', '8e9ca361', '8f9ca361', '909ca361', '919ca361', '929ca361', '939ca361', '949ca361', '959ca361', '969ca361', '979ca361', '989ca361', '999ca361', '9a9ca361', '9b9ca361', '9c9ca361', '9d9ca361', '9e9ca361', '9f9ca361', 'a09ca361', 'a19ca361']
                        for ids in items_ids:
                            self.client0500.send(bytes.fromhex(f"080000005a08cdede39a31100820062a4e0a1808f680e960100120ffffffffffffffffff012801380140020a1808b185a661100120ffffffffffffffffff012801380140020a1808{ids}100120ffffffffffffffffff01280138014002080000002708cdede39a31100820032a1b0a0708f680e96010010a0708b185a66110010a0708{ids}1001"))
                    except:
                        pass
                if   b"/proxy7" in dataS:
                    try:
                        items_ids = ['81c38566', '82c38566', '83c38566', '84c38566', '85c38566', '86c38566', '87c38566', '88c38566', '89c38566', '8ac38566', '8bc38566', '8cc38566', '8dc38566', '8ec38566', '8fc38566', '90c38566', '91c38566', '92c38566', '93c38566', '94c38566', '95c38566', '96c38566', '97c38566', '98c38566', '99c38566', '9ac38566', '9bc38566', '9cc38566', '9dc38566', '9ec38566', '9fc38566', 'a0c38566', 'a1c38566', 'a2c38566', 'a3c38566', 'a4c38566', 'a5c38566', 'a6c38566', 'a7c38566', 'a8c38566', 'a9c38566', 'aac38566', 'abc38566', 'acc38566', 'adc38566', 'aec38566', 'afc38566', 'b0c38566', 'b1c38566', 'b2c38566', 'b3c38566', 'b4c38566', 'b5c38566', 'b6c38566', 'b7c38566', 'b8c38566', 'b9c38566', 'bac38566', 'bbc38566', 'bcc38566', 'bdc38566', 'bec38566', 'bfc38566', 'c0c38566', 'c1c38566', 'c2c38566', 'c3c38566', 'c4c38566', 'c5c38566', 'c6c38566', 'c7c38566', 'c8c38566', 'c9c38566', 'cac38566', 'cbc38566', 'ccc38566', 'cdc38566', 'cec38566', 'cfc38566', 'd0c38566', 'd1c38566', 'd2c38566', 'd3c38566', 'd4c38566', 'd5c38566', 'd6c38566', 'd7c38566', 'd8c38566', 'd9c38566', 'dac38566', 'dbc38566', 'dcc38566', 'ddc38566', 'dec38566', 'dfc38566', 'e0c38566', 'e1c38566', 'e2c38566', 'e3c38566', 'a0dc8766', 'a1dc8766', 'a2dc8766', 'a3dc8766', 'a4dc8766', 'a5dc8766', 'a6dc8766', 'a7dc8766', 'a8dc8766', 'a9dc8766']
                        for ids in items_ids:
                            self.client0500.send(bytes.fromhex(f"080000005a08cdede39a31100820062a4e0a1808f680e960100120ffffffffffffffffff012801380140020a1808b185a661100120ffffffffffffffffff012801380140020a1808{ids}100120ffffffffffffffffff01280138014002080000002708cdede39a31100820032a1b0a0708f680e96010010a0708b185a66110010a0708{ids}1001"))
                    except:
                        pass
                if b"/evo" in dataS:
                    wep_idss = ['9181bfb003', '9281bfb003', '9381bfb003', '9481bfb003', '9581bfb003', '9681bfb003', '9781bfb003', '9881bfb003', '9981bfb003', '9a81bfb003', '9b81bfb003', '9c81bfb003', '9d81bfb003', '9e81bfb003', '9f81bfb003', 'a081bfb003', 'a181bfb003', 'a281bfb003', 'a381bfb003', 'a481bfb003', 'a581bfb003', 'a681bfb003', 'a781bfb003', 'a881bfb003', 'c1f1beb003', 'c2f1beb003', 'c3f1beb003', 'c4f1beb003', 'c5f1beb003', 'c6f1beb003', 'c7f1beb003', 'c8f1beb003', 'c9f1beb003', 'caf1beb003', 'cbf1beb003', 'ccf1beb003', 'cdf1beb003', 'cef1beb003', 'cff1beb003', 'd0f1beb003', 'd1f1beb003', 'd2f1beb003', 'd3f1beb003', 'd4f1beb003', 'd5f1beb003', 'd6f1beb003', 'd7f1beb003', 'd8f1beb003', 'd9f1beb003', 'daf1beb003', 'dbf1beb003', 'dcf1beb003', 'ddf1beb003', 'def1beb003', 'dff1beb003', 'e0f1beb003', 'e1f1beb003', 'e2f1beb003', 'e3f1beb003', 'e4f1beb003', 'e5f1beb003', 'e6f1beb003', 'e7f1beb003', 'e8f1beb003', 'e9f1beb003', 'eaf1beb003', 'ebf1beb003', 'ecf1beb003', 'edf1beb003', 'eef1beb003', 'eff1beb003', 'f0f1beb003', 'f1f1beb003', 'f2f1beb003', 'f3f1beb003', 'f4f1beb003', 'f5f1beb003', 'f6f1beb003', 'f7f1beb003', 'f8f1beb003', 'f9f1beb003', 'faf1beb003', 'fbf1beb003', 'fcf1beb003', 'fdf1beb003', 'fef1beb003', 'fff1beb003', '80f2beb003', '81f2beb003', '82f2beb003', '83f2beb003', '84f2beb003', '85f2beb003', '86f2beb003', '87f2beb003', '88f2beb003', '89f2beb003', '8af2beb003', '8bf2beb003', '8cf2beb003', '8df2beb003', '8ef2beb003', '8ff2beb003', '90f2beb003', '91f2beb003', '92f2beb003', '93f2beb003', '94f2beb003', '95f2beb003', '96f2beb003', '97f2beb003', '98f2beb003', '99f2beb003', '9af2beb003', '9bf2beb003', '9cf2beb003', '9dfdbeb003', '9efdbeb003', '9ffdbeb003', 'a0fdbeb003', 'a1fdbeb003', 'a2fdbeb003', 'a3fdbeb003', 'a4fdbeb003', 'a5fdbeb003', 'a6fdbeb003', 'a7fdbeb003', 'a8fdbeb003', 'a9fdbeb003', 'aafdbeb003', 'abfdbeb003', 'acfdbeb003', 'adfdbeb003', 'aefdbeb003', 'affdbeb003', 'b0fdbeb003', 'b1fdbeb003', 'b2fdbeb003', 'b3fdbeb003', 'b4fdbeb003', 'b9fcbeb003', 'bafcbeb003', 'bbfcbeb003', 'bcfcbeb003', 'bdfcbeb003', 'befcbeb003', 'bffcbeb003', 'c0fcbeb003', 'c1fcbeb003', 'c2fcbeb003', 'c3fcbeb003', 'c4fcbeb003', 'c5fcbeb003', 'c6fcbeb003', 'c7fcbeb003', 'c8fcbeb003', 'c9fcbeb003', 'cafcbeb003', 'cbfcbeb003', 'ccfcbeb003', 'cdfcbeb003', 'cefcbeb003', 'cffcbeb003', 'd0fcbeb003', 'd1fcbeb003', 'd2fcbeb003', 'd3fcbeb003', 'd4fcbeb003', 'd5fcbeb003', 'd6fcbeb003', 'd7fcbeb003', 'd8fcbeb003', 'd9fcbeb003', 'dafcbeb003', 'dbfcbeb003', 'dcfcbeb003', 'ddfcbeb003', 'defcbeb003', 'dffcbeb003', 'e0fcbeb003', 'e1fcbeb003', 'e2fcbeb003', 'e3fcbeb003', 'd5fbbeb003', 'd6fbbeb003', 'd7fbbeb003', 'd8fbbeb003', 'd9fbbeb003', 'dafbbeb003', 'dbfbbeb003', 'dcfbbeb003', 'ddfbbeb003', 'defbbeb003', 'dffbbeb003', 'e0fbbeb003', 'e1fbbeb003', 'e2fbbeb003', 'e3fbbeb003', 'e4fbbeb003', 'e5fbbeb003', 'e6fbbeb003', 'e7fbbeb003', '81febeb003', '82febeb003', '83febeb003', '84febeb003', '85febeb003', '86febeb003', '87febeb003', '88febeb003', '89febeb003', '8afebeb003', '8bfebeb003', '8cfebeb003', '8dfebeb003', '8efebeb003', '8ffebeb003', '90febeb003', '91febeb003', '92febeb003', '93febeb003', '94febeb003', '95febeb003', '96febeb003', '97febeb003', '98febeb003', '99febeb003', '9afebeb003', '9bfebeb003', '9cfebeb003', '9dfebeb003', 'e5febeb003', 'e6febeb003', 'e7febeb003', 'e8febeb003', 'e9febeb003', 'eafebeb003', 'ebfebeb003', 'ecfebeb003', 'edfebeb003', 'eefebeb003', 'effebeb003', 'f0febeb003', 'f1febeb003', 'f2febeb003', 'f3febeb003', 'f4febeb003', 'f5febeb003', 'f6febeb003', 'f7febeb003', 'f8febeb003', 'f9febeb003', 'fafebeb003', 'fbfebeb003', 'fcfebeb003', 'c9ffbeb003', 'caffbeb003', 'cbffbeb003', 'ccffbeb003', 'cdffbeb003', 'ceffbeb003', 'cfffbeb003', 'd0ffbeb003', 'd1ffbeb003', 'd2ffbeb003', 'd3ffbeb003', 'd4ffbeb003', 'd5ffbeb003', 'd6ffbeb003', 'd7ffbeb003', 'd8ffbeb003', 'd9ffbeb003', 'daffbeb003', 'dbffbeb003', 'dcffbeb003', 'ddffbeb003', 'deffbeb003', 'dfffbeb003', 'bb84bfb003', 'bc84bfb003', 'bd84bfb003', 'be84bfb003', 'bf84bfb003', 'c084bfb003', 'c184bfb003', 'c284bfb003', 'c384bfb003', 'c484bfb003', 'bd83bfb003', 'be83bfb003', 'bf83bfb003', 'c083bfb003', 'c183bfb003', 'c283bfb003', 'c383bfb003', 'c483bfb003', 'c583bfb003', 'c683bfb003', 'c783bfb003', 'c883bfb003', 'c983bfb003', 'ca83bfb003', 'cb83bfb003', 'cc83bfb003', 'cd83bfb003', 'ce83bfb003', 'cf83bfb003', 'd083bfb003', 'd183bfb003', 'd283bfb003', 'd383bfb003', 'd982bfb003', 'da82bfb003', 'db82bfb003', 'dc82bfb003', 'dd82bfb003', 'de82bfb003', 'df82bfb003', 'e082bfb003', 'e182bfb003', 'e282bfb003', 'e382bfb003', 'e482bfb003', 'e582bfb003', 'e682bfb003', 'e782bfb003', 'e882bfb003', 'e982bfb003', 'ea82bfb003', 'eb82bfb003', 'ec82bfb003', 'ed82bfb003', 'ee82bfb003', 'ef82bfb003', 'f082bfb003', 'f182bfb003', 'f282bfb003', 'f382bfb003', 'f482bfb003', 'f582bfb003', 'f682bfb003', 'f782bfb003', 'f581bfb003', 'f681bfb003', 'f781bfb003', 'f881bfb003', 'f981bfb003', 'fa81bfb003', 'fb81bfb003', 'fc81bfb003', 'fd81bfb003', 'fe81bfb003', 'ff81bfb003', '8082bfb003', '8182bfb003', '8282bfb003', '8382bfb003', '8482bfb003', '8582bfb003', '8682bfb003', '8782bfb003', '8882bfb003', '8982bfb003', '8a82bfb003', 'bbd1cab003', '9fd2cab003', '83d3cab003', 'e7d3cab003','e9decab003', '85decab003', '95e1cab003', 'dfdecab003', 'fbddcab003', '97ddcab003', 'afd5cab003']
                    try:
                            for wep_ids in wep_idss:
                                self.client0500.send(bytes.fromhex(f"080000003308e7e8e8ba30100820062a270a2508{wep_ids}100118a5f1bec50620ffffffffffffffffff0128013080e90f380240097003"))
                                time.sleep(0.02)

                    except:
                        pass
                if b"/other" in dataS:
                    others_idss = ['81fbc6d202', '82fbc6d202', '83fbc6d202', '84fbc6d202', '85fbc6d202', '86fbc6d202', '87fbc6d202', '88fbc6d202', '89fbc6d202', '8afbc6d202', '8bfbc6d202', '8cfbc6d202', '8dfbc6d202', '8efbc6d202', '8ffbc6d202', '90fbc6d202', '91fbc6d202', '92fbc6d202', '93fbc6d202', '94fbc6d202', '95fbc6d202', '96fbc6d202', '97fbc6d202', '98fbc6d202', '99fbc6d202', '9afbc6d202', '9bfbc6d202', '9cfbc6d202', '9dfbc6d202', '9efbc6d202', '9ffbc6d202', 'a0fbc6d202', 'a1fbc6d202', 'a2fbc6d202', 'a3fbc6d202', 'a4fbc6d202', 'a5fbc6d202', 'a6fbc6d202', 'a7fbc6d202', 'a8fbc6d202', 'a9fbc6d202', 'aafbc6d202', 'abfbc6d202', 'acfbc6d202', 'adfbc6d202', 'aefbc6d202', 'affbc6d202', 'b0fbc6d202', 'b1fbc6d202', 'b2fbc6d202', 'b3fbc6d202', 'b4fbc6d202', 'b5fbc6d202', 'b6fbc6d202', 'b7fbc6d202', 'b8fbc6d202', 'b9fbc6d202', 'bafbc6d202', 'bbfbc6d202', 'bcfbc6d202', 'bdfbc6d202', 'befbc6d202', 'bffbc6d202', 'c0fbc6d202', 'c1fbc6d202', 'c2fbc6d202', 'c3fbc6d202', 'c4fbc6d202', 'c5fbc6d202', 'c6fbc6d202', 'c7fbc6d202', 'c8fbc6d202', 'c9fbc6d202', 'cafbc6d202', 'cbfbc6d202', 'ccfbc6d202', 'cdfbc6d202', 'cefbc6d202', 'cffbc6d202', 'd0fbc6d202', 'd1fbc6d202', 'd2fbc6d202', 'd3fbc6d202', 'd4fbc6d202', 'd5fbc6d202', 'd6fbc6d202', 'd7fbc6d202', 'd8fbc6d202', 'd9fbc6d202', 'dafbc6d202', 'dbfbc6d202', 'dcfbc6d202', 'ddfbc6d202', 'defbc6d202', 'dffbc6d202', 'e0fbc6d202', 'e1fbc6d202', 'e2fbc6d202', 'e3fbc6d202', 'e4fbc6d202', 'e5fbc6d202', 'e6fbc6d202', 'e7fbc6d202', 'e8fbc6d202', 'e9fbc6d202', 'eafbc6d202', 'ebfbc6d202', 'ecfbc6d202', 'edfbc6d202', 'eefbc6d202', 'effbc6d202', 'f0fbc6d202', 'f1fbc6d202', 'f2fbc6d202', 'f3fbc6d202', 'f4fbc6d202', 'f5fbc6d202', 'f6fbc6d202', 'f7fbc6d202', 'f8fbc6d202', 'f9fbc6d202', 'fafbc6d202', 'fbfbc6d202', 'fcfbc6d202', 'fdfbc6d202', 'fefbc6d202', 'fffbc6d202', '80fcc6d202', '81fcc6d202', '82fcc6d202', '83fcc6d202', '84fcc6d202', '85fcc6d202', '86fcc6d202', '87fcc6d202', '88fcc6d202', '89fcc6d202', '8afcc6d202', '8bfcc6d202', '8cfcc6d202', '8dfcc6d202', '8efcc6d202', '8ffcc6d202', '90fcc6d202', '91fcc6d202', '92fcc6d202','99edc8d202', '9aedc8d202', '9bedc8d202', '9cedc8d202', '9dedc8d202', '9eedc8d202', '9fedc8d202', 'a0edc8d202', 'a1edc8d202', 'a2edc8d202', 'a3edc8d202', 'a4edc8d202', 'a5edc8d202', 'a6edc8d202', 'a7edc8d202', 'a8edc8d202', 'a9edc8d202', 'aaedc8d202', 'abedc8d202', 'acedc8d202', 'adedc8d202', 'aeedc8d202', 'afedc8d202', 'b0edc8d202', 'b1edc8d202', 'b2edc8d202', 'b3edc8d202', 'b4edc8d202', 'b5edc8d202', 'b6edc8d202', 'b7edc8d202', 'b8edc8d202', 'b9edc8d202', 'baedc8d202', 'bbedc8d202', 'bcedc8d202', 'bdedc8d202', 'beedc8d202', 'bfedc8d202', 'c0edc8d202', 'c1edc8d202', 'c2edc8d202', 'c3edc8d202', 'c4edc8d202', 'c5edc8d202', 'c6edc8d202', 'c7edc8d202', 'c8edc8d202', 'c9edc8d202', 'caedc8d202', 'cbedc8d202', 'ccedc8d202', 'cdedc8d202', 'ceedc8d202', 'cfedc8d202', 'd0edc8d202', 'd1edc8d202', 'd2edc8d202', 'd3edc8d202', 'd4edc8d202', 'd5edc8d202', 'd6edc8d202', 'd7edc8d202', 'd8edc8d202', 'd9edc8d202', 'daedc8d202', 'dbedc8d202', 'dcedc8d202', 'ddedc8d202', 'd184c9d202', 'd284c9d202', 'd384c9d202', 'd484c9d202', 'd584c9d202', 'd684c9d202', 'd784c9d202', 'd884c9d202', 'd984c9d202', 'da84c9d202', 'db84c9d202', 'dc84c9d202', 'dd84c9d202', 'de84c9d202', 'df84c9d202', 'e084c9d202', 'e184c9d202', 'e284c9d202', 'e384c9d202', 'e484c9d202', 'e584c9d202', 'e684c9d202', 'e784c9d202', 'e884c9d202', 'e984c9d202', 'ea84c9d202', 'eb84c9d202', 'ec84c9d202', 'ed84c9d202', 'ee84c9d202', 'ef84c9d202', 'f084c9d202', 'f184c9d202', 'f284c9d202', 'f384c9d202', 'f484c9d202', 'f584c9d202', 'f684c9d202', 'f784c9d202', 'f884c9d202', 'f984c9d202', 'fa84c9d202', 'fb84c9d202', 'fc84c9d202', 'fd84c9d202', 'fe84c9d202', 'ff84c9d202', '8085c9d202', '8185c9d202', '8285c9d202', '8385c9d202', '8485c9d202', '8585c9d202', '8685c9d202', '8785c9d202', '8885c9d202', '8985c9d202', '8a85c9d202', '8b85c9d202', '8c85c9d202', '8d85c9d202', '8e85c9d202', '8f85c9d202', '9085c9d202', '9185c9d202', '9285c9d202', '9385c9d202', '9485c9d202', '9585c9d202', 'b98cc9d202', 'ba8cc9d202', 'bb8cc9d202', 'bc8cc9d202', 'bd8cc9d202', 'be8cc9d202', 'bf8cc9d202', 'c08cc9d202', 'c18cc9d202', 'c28cc9d202', 'c38cc9d202', 'c48cc9d202', 'c58cc9d202', 'c68cc9d202', 'c78cc9d202', 'c88cc9d202', 'c98cc9d202', 'ca8cc9d202', 'cb8cc9d202', 'cc8cc9d202', 'cd8cc9d202', 'ce8cc9d202', 'cf8cc9d202', 'd08cc9d202', 'd18cc9d202', 'd28cc9d202', 'd38cc9d202', 'd48cc9d202', 'd58cc9d202', 'd68cc9d202', 'd78cc9d202', 'd88cc9d202', 'd98cc9d202', 'da8cc9d202', 'db8cc9d202', 'dc8cc9d202', 'dd8cc9d202', 'de8cc9d202', 'df8cc9d202', 'e08cc9d202', 'e18cc9d202', 'e28cc9d202', 'e38cc9d202', 'e48cc9d202', 'e58cc9d202', 'e68cc9d202', 'e78cc9d202', 'e88cc9d202', 'e98cc9d202', 'ea8cc9d202', 'eb8cc9d202', 'ec8cc9d202', 'ed8cc9d202', 'ee8cc9d202', 'ef8cc9d202', 'f08cc9d202', 'f18cc9d202', 'f28cc9d202', 'f38cc9d202', 'f48cc9d202', 'f58cc9d202', 'f68cc9d202', 'f78cc9d202', 'f88cc9d202', 'f98cc9d202', 'fa8cc9d202', 'fb8cc9d202', 'fc8cc9d202', 'fd8cc9d202', 'a194c9d202', 'a294c9d202', 'a394c9d202', 'a494c9d202', 'a594c9d202', 'a694c9d202', 'a794c9d202', 'a894c9d202', 'a994c9d202', 'aa94c9d202', 'ab94c9d202', 'ac94c9d202', 'ad94c9d202', 'ae94c9d202', 'af94c9d202', 'b094c9d202', 'b194c9d202', 'b294c9d202', 'b394c9d202', 'b494c9d202', 'b594c9d202', 'b694c9d202', 'b794c9d202', 'b894c9d202', 'b994c9d202', 'ba94c9d202', 'bb94c9d202', 'bc94c9d202', 'bd94c9d202', 'be94c9d202', 'bf94c9d202', 'c094c9d202', 'c194c9d202', 'c294c9d202', 'c394c9d202', 'c494c9d202', 'c594c9d202', 'c694c9d202', 'c794c9d202', 'c894c9d202', 'c994c9d202', 'ca94c9d202', 'cb94c9d202', 'cc94c9d202', 'cd94c9d202', 'ce94c9d202', 'cf94c9d202', 'd094c9d202', 'd194c9d202', 'd294c9d202', 'd394c9d202', 'd494c9d202', 'd594c9d202', 'd694c9d202', 'd794c9d202', 'd894c9d202', 'd994c9d202', 'da94c9d202', 'db94c9d202', 'dc94c9d202', 'dd94c9d202', 'de94c9d202', 'df94c9d202', 'e094c9d202', 'e194c9d202', 'e294c9d202', 'e394c9d202', 'e494c9d202', 'e594c9d202', '899cc9d202', '8a9cc9d202', '8b9cc9d202', '8c9cc9d202', '8d9cc9d202', '8e9cc9d202', '8f9cc9d202', '909cc9d202', '919cc9d202', '929cc9d202', '939cc9d202', '949cc9d202', '959cc9d202', '969cc9d202', '979cc9d202', '989cc9d202', '999cc9d202', '9a9cc9d202', '9b9cc9d202', '9c9cc9d202', '9d9cc9d202', '9e9cc9d202', '9f9cc9d202', 'a09cc9d202', 'a19cc9d202', 'a29cc9d202', 'a39cc9d202', 'a49cc9d202', 'a59cc9d202', 'a69cc9d202', 'a79cc9d202', 'a89cc9d202', 'a99cc9d202', 'aa9cc9d202', 'ab9cc9d202', 'ac9cc9d202', 'ad9cc9d202', 'ae9cc9d202', 'af9cc9d202', 'b09cc9d202', 'b19cc9d202', 'b29cc9d202', 'b39cc9d202', 'b49cc9d202', 'b59cc9d202', 'b69cc9d202', 'b79cc9d202', 'b89cc9d202', 'b99cc9d202', 'ba9cc9d202', 'bb9cc9d202', 'bc9cc9d202', 'bd9cc9d202', 'be9cc9d202', 'bf9cc9d202', 'c09cc9d202', 'c19cc9d202', 'c29cc9d202', 'c39cc9d202', 'c49cc9d202', 'c59cc9d202', 'c69cc9d202', 'c79cc9d202', 'c89cc9d202', 'c99cc9d202', 'ca9cc9d202', 'cb9cc9d202', 'cc9cc9d202', 'cd9cc9d202', 'f1a3c9d202', 'f2a3c9d202', 'f3a3c9d202', 'f4a3c9d202', 'f5a3c9d202', 'f6a3c9d202', 'f7a3c9d202', 'f8a3c9d202', 'f9a3c9d202', 'faa3c9d202', 'fba3c9d202', 'fca3c9d202', 'fda3c9d202', 'fea3c9d202', 'ffa3c9d202', '80a4c9d202', '81a4c9d202', '82a4c9d202', '83a4c9d202', '84a4c9d202', '85a4c9d202', '86a4c9d202', '87a4c9d202', '88a4c9d202', '89a4c9d202', '8aa4c9d202', '8ba4c9d202', '8ca4c9d202', '8da4c9d202', '8ea4c9d202', '8fa4c9d202']
                    for others_ids in others_idss:
                        self.client0500.send(bytes.fromhex(f"080000001608c0c5cefb18100820032a0a0a0808{others_ids}1001080000003f08c0c5cefb18100820062a330a1908{others_ids}100120ffffffffffffffffff012801380140090a160883cf928403109f2b20ffffffffffffffffff013801"))

                if b"/dance1" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}109afbb8b1032a0c08{self.EncryptedPlayerid}189afbb8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance2" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}1091fbb8b1032a0c08{self.EncryptedPlayerid}1891fbb8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance3" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10c6fab8b1032a0c08{self.EncryptedPlayerid}18c6fab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance4" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10ccfab8b1032a0c08{self.EncryptedPlayerid}18ccfab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance5" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10cefab8b1032a0c08{self.EncryptedPlayerid}18cefab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance6" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10cbfab8b1032a0c08{self.EncryptedPlayerid}18cbfab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance7" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10d4fab8b1032a0c08{self.EncryptedPlayerid}18d4fab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance8" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10f0fab8b1032a0c08{self.EncryptedPlayerid}18f0fab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance9" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10fffab8b1032a0c08{self.EncryptedPlayerid}18fffab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance10" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10f4fab8b1032a0c08{self.EncryptedPlayerid}18f4fab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance11" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10d0fab8b1032a0c08{self.EncryptedPlayerid}18d0fab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance12" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10d5fab8b1032a0c08{self.EncryptedPlayerid}18d5fab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance13" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10d9fab8b1032a0c08{self.EncryptedPlayerid}18d9fab8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance14" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}1095fbb8b1032a0c08{self.EncryptedPlayerid}1895fbb8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance15" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}108bfbb8b1032a0c08{self.EncryptedPlayerid}188bfbb8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance16" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}10e193bbb1032a0c08{self.EncryptedPlayerid}18e193bbb10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance17" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}109afbb8b1032a0c08{self.EncryptedPlayerid}189afbb8b10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/dance18" in dataS:
                    try:
                        self.client0500.send(bytes.fromhex(f"050000002c08{self.EncryptedPlayerid}100520162a2008{self.EncryptedPlayerid}109184bbb1032a0c08{self.EncryptedPlayerid}189184bbb10330b7d7bc8206"))
                        self.client1200.send(bytes.fromhex(f"12000001ee08{self.EncryptedPlayerid}101220022ae10308a9c4a5c93010{self.EncryptedPlayerid}22b7020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720656d6f746520756e6c6f636b65642120200a5b3332434433325d5b435d5b425d4578707265737320796f757273656c6620696e207374796c652e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a920d8acd8afd98ad8afd8a92e20200a5b4646413530305d5b435d5b425dd8b9d8a8d991d8b120d8b9d98620d986d981d8b3d98320d8a8d8a3d986d8a7d982d8a92e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110c0db8dae03188cd7d0ad0320ca0228d1dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a706710011801720012000001f208{self.EncryptedPlayerid}101220022ae50308a9c4a5c93010{self.EncryptedPlayerid}22bb020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e657720736b696e20756e6c6f636b65642120200a5b3332434433325d5b435d5b425d437573746f6d697a6520796f757220636861726163746572206e6f772e20200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d8a7d984d8add8b5d988d98420d8b9d984d98920d8b3d983d98ad98620d8acd8afd98ad8af2e20200a5b4646413530305d5b435d5b425dd982d98520d8a8d8aad8aed8b5d98ad8b520d8b4d8aed8b5d98ad8aad98320d8a7d984d8a2d9862e0a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110cbdb8dae03188cd7d0ad0320ca0228d3dc8dae0338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200120000020408{self.EncryptedPlayerid}101220022af70308a9c4a5c93010{self.EncryptedPlayerid}22cd020a5b3145393046465d5b435d5b425de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b3030464637465d5b435d5b425d4e6577207469746c65207374796c6520756e6c6f636b65642e20200a5b3332434433325d5b435d5b425d53686f7720796f757220737175616420696e207374796c652120200a5b3145393046465de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e2948120200a5b4646374635305d5b435d5b425dd8aad98520d981d8aad8ad20d8b3d8aad8a7d98ad98420d8acd8afd98ad8af20d984d984d988d8bad8a7d8aa2e20200a5b4646413530305d5b435d5b425dd8a3d8b8d987d8b120d8a7d984d8b3d983d988d8a7d8af20d8a7d984d8aed8a7d8b520d8a8d98320d8a8d8a3d986d8a7d982d8a9210a2888fb9cc5064a420a104352415a59e385a4424f54e385a4563110b2dd8dae03188cd7d0ad0320ca0228a0f1f7b10338025001589b016a020802720e08b9d886f82f10081a041015080a5202656e6a490a4368747470733a2f2f63646e692e706f726e706963732e636f6d2f313238302f372f3830302f39383736303036392f39383736303036395f3032345f333235652e6a7067100118017200"))
                    except:
                        pass
                if b"/visible" in dataS:
                    look_idss = ['9980edb303', 'e1e8ecb303', '8391eab303', '8291eab303', '91d9ecb303', '9980edb303', '8188edb303', '9a80edb303', 'd9c1ecb303', 'f1b9ecb303', 'd197edb303']
                    try:
                            for look_ids in look_idss:
                                self.client0500.send(bytes.fromhex(f"080000001608c0c5cefb18100820032a0a0a0808{look_ids}1001080000003f08c0c5cefb18100820062a330a1908{look_ids}100120ffffffffffffffffff012801380140090a160883cf928403109f2b20ffffffffffffffffff013801"))
                    except:
                        pass
                if b"/emotes" in dataS:
                    i = re.split("/emotes", str(dataS))[1]
                    id = str(i).split("(\\x")[0].strip()
                    self.client0500.send(bytes.fromhex(emotes(self.EncryptedPlayerid, id)))
#━━━━━━━━━━━━━━DONE━━━━━━━━━━━━━━━━
              
                
                if   b"/DIAM" in dataS:
                    try:
                        threading.Thread(target=self.adding_daimond).start()
                        self.client1200.send(bytes.fromhex(f"120000014808{self.EncryptedPlayerid}101220022abb0208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}2293010a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a0a220a5b3030464630305d5b635d5b625d2d20444f4e45204144442031304b204449414d4f4e442e0a0a220a5b6666376635305d5b635d5b625de29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e29481e294810a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"))
                    except:
                        pass
                
                if b"/record" in dataS:
                    recode_packet = True
                if b"/start" in dataS:
                    self.remote0500.send(bytes.fromhex(packet_start))
                if '1200' in dataS.hex()[0:4] and b'/add' in dataS:    
                        try:
                            i = re.split('/add', str(dataS))[1]
                            print(i)                        
                            if '***' in i:
                            	i = i.replace('***', '106')            	
                            iddd = str(i).split('(\\x')[0]   	            
                            id = self.Encrypt_ID(iddd)
                            self.fake_friend(self.client0500, id)
                            self.client1200.send(bytes.fromhex(f"12000000f708{self.EncryptedPlayerid}101220022aea0108{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22430a5b625d5b695d5b635d5b3763666330305d202d20446f6e652041444420504c4159455220210a202d20456e6a6f790a202d204279203a20434f444558205445414d0a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"))
                        except:
                            pass
                #CHAT FEATURES!
                if   b'/spm' in dataS:
                    	spam_chat = dataC
                    	try:
                    	           for i in range(1):
                    	               for _ in range(5):
                    	                   remote.send(spam_chat)
                    	                   time.sleep(0.04)
                    	                   time.sleep(0.2)
                    	           threading.Thread(target=send_msg, args=(self.client1200, dataS.hex(), "[B][C][FF0000] - Spam message Done ", 0.3)).start()
                    	except:
                    	    pass
                if b"/region+" in dataS:
                             parts = dataS.split(b"/region+")
                             user_id = parts[1].split(b"\x28")[0].decode("utf-8")
                             b = get_player_info(user_id)
                             reg = b["region"]
                             nick = b["nickname"]
                             threading.Thread(target=send_msg, args=(client, dataS.hex(), reg, 0.2)).start()
                             threading.Thread(target=send_msg, args=(client, dataS.hex(), nick, 0.2)).start()
                if b"/LAG" in dataS:
                    for i in range (99999999999999):
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][FBB117]- ∫  BOT-X V6 START FUCKING YOUR ACCOUNT!!\n\n/FUCK YOUUㅤㅤ", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][FBB117]- ∫ FUCK FUCK FUCK\n\n/FUCK YOUU\n\nFUCK FUCK", 1.0)).start()
                                time.sleep(0.01)
                #STYLLLLLLLLLE
                
                if b"/7old" in dataS:
                    threading.Thread(target=self.YearsOld7).start()
                if b"/6old" in dataS:
                    threading.Thread(target=self.YearsOld6).start()
                if b"/5old" in dataS:
                    threading.Thread(target=self.YearsOld5).start()
                if b"@FOX-RR" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d52(.*?)28', dataS.hex())[0])).decode('utf-8', errors='ignore')
                        ress = f"[C][B][FF0000]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()              
                if b"@FOX-GG" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d47(.*?)28', dataS.hex())[0])).decode('utf-8')
                        ress = f"[C][B😎][00FF00]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()                   
                if b"@FOX-YY" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d59(.*?)28', dataS.hex())[0])).decode('utf-8')
                        ress = f"[C][B😎][FFFF00]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-VV" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d56(.*?)28', dataS.hex())[0])).decode('utf-8')
                        ress = f"[C][B😎][2ECC71]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-BB" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d42(.*?)28', dataS.hex())[0])).decode('utf-8') 
                        ress = f"[C][B😎][0000FF]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start() 
                if b"@FOX-OO" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4f(.*?)28', dataS.hex())[0])).decode('utf-8')
                        ress = f"[C][B😎][FFA500]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-PP" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4f(.*?)28', dataS.hex())[0])).decode('utf-8')
                        ress = f"[C][B😎][FF1493]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-GY" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4f(.*?)28', dataS.hex())[0])).decode('utf-8')
                        ress = f"[C][B😎][808080]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-DV" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4f(.*?)28', dataS.hex())[0])).decode('utf-8')
                        ress = f"[C][B😎][8A2BE2]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-BR" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4f(.*?)28', dataS.hex())[0])).decode('utf-8')
                        ress = f"[C][B😎][A52A2A]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()

                if client.send(dataS) <= 0:
                    pass
#━━━━━━━━━━━━━━━━━━━
    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ]) 
    def verify_credentials(self, connection):
        version = connection.recv(1)[0]
        username_len = connection.recv(1)[0]
        username = connection.recv(username_len).decode('utf-8')
        password_len = connection.recv(1)[0]
        password = connection.recv(password_len).decode('utf-8')
        if username == self.username and password == self.password:
            response = bytes([version, 0])
            connection.sendall(response)
            return True
        else:
            response = bytes([version, 0])
            connection.sendall(response)
            return True  
    def get_available_methods(self, nmethods, connection):
        methods = []
        for _ in range(nmethods):
            methods.append(connection.recv(1)[0])
        return methods
    def run(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, port))
        s.listen()
        print(f"* Socks5 proxy server is running on {ip}:{port}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()
import threading
from concurrent.futures import ThreadPoolExecutor
def start_bot():
    try:
            proxy = Proxy()
            t = threading.Thread(target=proxy.run, args=("127.0.0.1", 3000))
            t.start()
            threads.append(t)
            for t in threads:
                t.join()
    except:
        pass
if __name__ == "__main__":
    start_bot()
