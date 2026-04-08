from flask import Flask, request, abort
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import MessageEvent, TextMessage, TextSendMessage, ImageMessage, FileMessage
import scanner_api 
import re
import os
from dotenv import load_dotenv

# สร้างแอปพลิเคชัน Flask เพื่อทำหน้าที่เป็น Web Server รับข้อมูลจาก LINE
app = Flask(__name__)

# ตั้งค่าพื้นฐานและโหลดกุญแจความลับ
load_dotenv()

# ==========================================
# 1. ตั้งค่ากุญแจความลับ (LINE กับ VT)
# ==========================================
LINE_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN")
LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET")
VT_API_KEY = os.getenv("VT_API_KEY")

line_bot_api = LineBotApi(LINE_ACCESS_TOKEN)
handler = WebhookHandler(LINE_CHANNEL_SECRET)

# ==========================================
# 2. วิเคราะห์และสร้างข้อความรายงาน
# ==========================================
def get_threat_advice(threat_text):
    """วิเคราะห์ผลสแกน เพื่อให้คำแนะนำแบบเป็นกลาง (VirusTotal Style)"""
    text = str(threat_text).lower()
    
    # 1. กรณีพบการแจ้งเตือนตั้งแต่ 1 เอนจินขึ้นไป (จับจาก ⚠️)
    if "⚠️" in text:
        return {
            "exp": "Detection Alert: มีเอนจินสแกนไวรัสบางค่ายมองว่าน่าสงสัย", 
            "rec": "Action: หากจำนวนเอนจินที่พบน้อย อาจเป็น False Positive แต่หากพบจำนวนมาก ควรลบทิ้งทันที"
        }
    
    # กรณี 0 เอนจิน (✅) ให้ปล่อยผ่าน ไม่ต้องอธิบายเพิ่ม
    return None

def generate_report_message(title, result, detail_name, detail_value, report_url=None, engine="VirusTotal"):
    """จัดรูปแบบข้อความตอบกลับสไตล์ LINE คล้าย Embed"""
    advice = get_threat_advice(result)
    
    reply = f"[{title}]\n\n"
    reply += f"{detail_name}: {detail_value}\n"
    reply += f"{'-'*30}\n"
    reply += f"ผลการสแกน:\n{result}\n"

    if report_url:
        reply += f"{'-'*30}\n"
        reply += f"🌐 คลิกเพื่อดูรายละเอียด:\n{report_url}\n"
    
    if advice:
        reply += f"{'-'*30}\n"
        reply += f"คำอธิบาย:\n{advice['exp']}\n\n"
        reply += f"คำแนะนำ:\n{advice['rec']}"
        
    return reply

# ==========================================
# 3. ประตูรับข้อมูล (Webhook Endpoint)
# ==========================================
@app.route("/webhook", methods=['POST'])
def callback():
    signature = request.headers['X-Line-Signature']
    body = request.get_data(as_text=True)
    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)
    return 'OK'

# ==========================================
# 4. ประมวลผลข้อความแชท (Text Detection)
# ==========================================
@handler.add(MessageEvent, message=TextMessage)
def handle_text_message(event):
    text = event.message.text
    
    # ดึง URL และ Hash จากข้อความ
    urls = re.findall(r'((?:https?://)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*))', text)
    
    if urls:
        # ดึงแค่ลิงก์แรกที่เจอมาสแกน (เพราะ LINE ตอบได้ครั้งเดียว)
        urls_to_scan = urls[:5]
        
        reply_messages = []
        
        for u in urls_to_scan:
            # ถ้าผู้ใช้พิมพ์มาไม่มี http ให้แอบเติมให้มันก่อนส่งไป API
            scan_url = u
            if not scan_url.startswith(('http://', 'https://')):
                scan_url = 'http://' + scan_url
                
            # ใช้ scan_url ที่เติม http แล้วส่งไปให้ API
            result = scanner_api.check_virustotal_url(scan_url, VT_API_KEY)

            # สร้างลิงก์ Report และส่งเข้าไปในฟังก์ชัน
            vt_report_url = scanner_api.get_vt_url_report_url(scan_url)
            
            # ตอนตอบกลับ คืนค่า u แบบออริจินัลให้ผู้ใช้เห็นว่าเราสแกนข้อความที่เขาพิมพ์มาจริงๆ
            reply_msg = generate_report_message("Link Scanning Results", result, "URL", u, report_url=vt_report_url)

            reply_messages.append(TextSendMessage(text=reply_msg))
            
        line_bot_api.reply_message(event.reply_token, reply_messages)

# ==========================================
# 5. ประมวลผลไฟล์และรูปภาพ (File/Image Detection)
# ==========================================
@handler.add(MessageEvent, message=(ImageMessage, FileMessage))
def handle_file_message(event):
    message_id = event.message.id
    if isinstance(event.message, FileMessage):
        file_name = event.message.file_name
    else:
        file_name = "Image_File.jpg"

    try:
        message_content = line_bot_api.get_message_content(message_id)
        # นำข้อมูลจาก LINE เป็นก้อนๆ มารวมกันไว้ที่ RAM ไม่แตะ Harddisk
        file_bytes = b"".join([chunk for chunk in message_content.iter_content()])

        # แล้วเอาข้อมูลที่เก็บไว้ใน RAM มาคำนวณ hash
        # เรียกใช้ calculate_hash
        file_hash = scanner_api.calculate_hash(file_bytes)
        
        # เรียกใช้ check_virustotal_file
        result = scanner_api.check_virustotal_file(file_hash, VT_API_KEY)

        # สร้างลิงก์ Report และส่งเข้าไปในฟังก์ชัน
        vt_report_url = scanner_api.get_vt_file_report_url(file_hash)
        
        reply_msg = generate_report_message("File Scan Report", result, "File name", file_name, report_url=vt_report_url)
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_msg))

    except Exception as e:
        line_bot_api.reply_message(
            event.reply_token,
            TextSendMessage(text=f"⚠️ เกิดข้อผิดพลาดในการอ่านไฟล์: {str(e)}")
        )

# ==========================================
# 6. รันเซิร์ฟเวอร์
# ==========================================
if __name__ == "__main__":
    app.run(port=8080, debug=True)
