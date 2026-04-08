import discord
import re
import scanner_api
import os
from dotenv import load_dotenv

# ตั้งค่าพื้นฐานและโหลดกุญแจความลับ
load_dotenv()

# Discord Token และ VirusTotal API Key
TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

# ==========================================
# 1. วิเคราะห์และสร้างข้อความรายงาน
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

# ==========================================
# 2. ตั้งค่าบอท Discord
# ==========================================
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# ==========================================
# 3. เหตุการณ์ (Events)
# ==========================================
@client.event
async def on_ready():
    print(f'✅ {client.user} Status: Ready!')

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    # --- ฟังก์ชันผู้ช่วย: สร้างการ์ด UI (Embed) ---
    def create_embed(title, result, detail_name, detail_value, extra_fields=None, report_url=None):
        if "✅" in result:
            color = discord.Color.green()
        elif "❌" in result or "⚠️" in result:
            color = discord.Color.red()
        else:
            color = discord.Color.orange()

        embed = discord.Embed(title=title, color=color)
        embed.add_field(name="Verification Results", value=result, inline=False)
        embed.add_field(name=detail_name, value=detail_value, inline=False)

        if extra_fields:
            for name, value in extra_fields.items():
                embed.add_field(name=name, value=value, inline=False)
        
        if report_url:
            embed.add_field(name="🌐 Full Report (VirusTotal)", value=f"[คลิกเพื่อดูรายละเอียด]({report_url})", inline=False)

        advice = get_threat_advice(result)
        if advice:
            embed.add_field(name="Threat Explanation", value=advice["exp"], inline=False)
            embed.add_field(name="Recommendation", value=advice["rec"], inline=False)

        # อัปเดตข้อความ Footer ล่างสุด
        embed.set_footer(text="VirusTotal Scanner")
        return embed

    ## Auto-Scanning ##
    # 1. ดักจับไฟล์แนบอัตโนมัติ (ข้ามถ้ากำลังใช้คำสั่ง !verify)
    if message.attachments and not message.content.startswith('!verify'):
        for attachment in message.attachments:
            status_msg = await message.reply(f'🔍 กำลังสแกนไฟล์: `{attachment.filename}` ...')
            file_bytes = await attachment.read()
            
            file_hash = scanner_api.calculate_hash(file_bytes)
            result = scanner_api.check_virustotal_file(file_hash, VT_API_KEY)

            # สร้างลิงก์ Report และส่งเข้าไปในฟังก์ชัน
            vt_report_url = scanner_api.get_vt_file_report_url(file_hash)

            embed = create_embed(
                "File Scan Report", result, "File name", attachment.filename,
                extra_fields={"SHA-256 Hash": f"`{file_hash}`"}, report_url=vt_report_url
            )
            await status_msg.edit(content="", embed=embed)

    # 2. ดักจับลิงก์อัตโนมัติ (ใช้ Regex ดึง URL ออกมาจากข้อความ)
    url_pattern = r'((?:https?://)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*))'
    urls = re.findall(url_pattern, message.content)

    if urls:
        for url in urls:
            scan_url = url
            if not scan_url.startswith(('http://', 'https://')):
                scan_url = 'http://' + scan_url

            status_msg = await message.reply(f'🔍 กำลังสแกนลิงก์: `{url}` ...')
            result = scanner_api.check_virustotal_url(scan_url, VT_API_KEY)

            # สร้างลิงก์ Report และส่งเข้าไปในฟังก์ชัน
            vt_report_url = scanner_api.get_vt_url_report_url(scan_url)

            embed = create_embed("URL Scan Report", result, "URL", url, report_url=vt_report_url)
            await status_msg.edit(content="", embed=embed)
    
    ## Manual Commands ##
    # ทดสอบสถานะบอท
    if message.content == 'Hello':
        await message.reply('Hi! Bot ready to scan!')

    # ตรวจสอบความสมบูรณ์ของไฟล์ (!verify ...)
    if message.content.startswith('!verify ') and message.attachments:
        original_hash = message.content.split(' ')[1]
        attachment = message.attachments[0]
        status_msg = await message.reply(f'Checking file hash...: {attachment.filename} ...')
        
        file_bytes = await attachment.read()
                
        # เรียกใช้ verify_hash
        match, file_hash = scanner_api.verify_hash(file_bytes, original_hash)

        if match:
            result = "✅ แฮชตรงกัน! ไฟล์ไม่ได้ถูกเปลี่ยนแปลง"
        else:
            result = "❌ แฮชไม่ตรงกัน! ไฟล์ถูกเปลี่ยนแปลงหรืออาจเสียหาย"

        embed = create_embed(
            "Source Hash Integrity Report",
            result,
            "File name", attachment.filename,
            extra_fields={
                "Original Hash": f"`{original_hash}`",
                "File Hash": f"`{file_hash}`"
            }
        )
        await status_msg.edit(content="", embed=embed)

# ==========================================
# 4. สั่งรันบอท
# ==========================================
client.run(TOKEN)
