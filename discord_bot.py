import discord
import scanner_api
import zipfile
import io
import os
from dotenv import load_dotenv

# ==========================================
# 1. ตั้งค่าพื้นฐานและโหลดกุญแจความลับ
# ==========================================
load_dotenv()

# Discord Token และ VirusTotal API Key
TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

# ==========================================
# 2. ระบบวิเคราะห์และสร้างข้อความรายงาน
# ==========================================
def get_threat_advice(threat_text):
    """วิเคราะห์คำศัพท์จากผลสแกน เพื่อแยกประเภทภัยคุกคาม"""
    text = str(threat_text).lower()
    
    if "phishing" in text or "malicious" in text:
        return {"exp": "**Phishing / Malicious:** หน้าเว็บปลอมหรือไฟล์หลอกขโมยข้อมูล", "rec": "**Action:** ห้ามคลิกหรือเปิด ให้ลบทิ้งทันที"}
    elif "ransomware" in text or "wannacry" in text:
        return {"exp": "**Ransomware:** มัลแวร์เข้ารหัสข้อมูลเพื่อเรียกค่าไถ่", "rec": "**Action:** ห้ามรันเป้าหมายนี้เด็ดขาด! ลบทิ้งทันที"}
    elif "trojan" in text or "spyware" in text or "stealer" in text:
        return {"exp": "**Trojan/Spyware:** แอบขโมยข้อมูลหรือเปิดหลังบ้านให้แฮกเกอร์", "rec": "**Action:** ลบทิ้งทันที และทำการ Full Scan เครื่อง"}
    elif "hacktool" in text or "riskware" in text or "psexec" in text:
        return {"exp": "**Riskware / HackTool:** โปรแกรมเจาะระบบที่อาจเป็นอันตราย", "rec": "**Action:** หากไม่ได้ติดตั้งเองให้ลบทิ้ง"}
    elif "eicar" in text:
        return {"exp": "**Test File:** ไฟล์จำลองเพื่อใช้ทดสอบ ปลอดภัย 100%", "rec": "**Action:** ไม่ต้องดำเนินการใดๆ"}
    elif "password-protected" in text or "เข้ารหัสผ่าน" in text:
        return {"exp": "**Encrypted Archive:** ถูกล็อครหัสผ่าน ระบบสแกนไส้ในไม่ได้", "rec": "**Action:** ระมัดระวัง! ห้ามแตกไฟล์เด็ดขาด"}
    elif "❌" in text:
        return {"exp": "**Unknown Malware:** พบพฤติกรรมต้องสงสัย", "rec": "**Action:** หลีกเลี่ยงการเปิดใช้งาน"}
    
    return None

# ==========================================
# 3. ตั้งค่าบอท Discord
# ==========================================
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# ==========================================
# 4. เหตุการณ์ (Events)
# ==========================================
@client.event
async def on_ready():
    print(f'✅ {client.user} Status: Ready!')

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    # --- ฟังก์ชันผู้ช่วย: สร้างการ์ด UI (Embed) ---
    def create_embed(title, result, detail_name, detail_value, extra_fields=None):
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

        advice = get_threat_advice(result)
        if advice:
            embed.add_field(name="Threat Explanation", value=advice["exp"], inline=False)
            embed.add_field(name="Recommendation", value=advice["rec"], inline=False)

        # อัปเดตข้อความ Footer ล่างสุด
        embed.set_footer(text="VirusTotal Scanner")
        return embed

    # 1. ทดสอบสถานะบอท
    if message.content == 'Hello':
        await message.reply('Hi! Bot ready to scan!')

    # 2. ตรวจสอบลิงก์ (!link ...)
    if message.content.startswith('!link '):
        url_to_check = message.content.split(' ')[1]
        status_msg = await message.reply(f'Checking the link...: {url_to_check} ...')
        
        # เรียกใช้ check_virustotal_url
        result = scanner_api.check_virustotal_url(url_to_check, VT_API_KEY)

        embed = create_embed("Link Scanning Results", result, "URL", url_to_check)
        await status_msg.edit(content="", embed=embed)

    # 3. ตรวจสอบด้วย Hash (!check ...)
    if message.content.startswith('!check '):
        hash_to_check = message.content.split(' ')[1]
        status_msg = await message.reply('Checking hash...')
        
        # เรียกใช้ check_virustotal_file
        result = scanner_api.check_virustotal_file(hash_to_check, VT_API_KEY)
        
        embed = create_embed(
            "Hash Scanning Results", 
            result, 
            "Hash", 
            hash_to_check
        )
        await status_msg.edit(content="", embed=embed)

    # 4. ตรวจสอบความสมบูรณ์ของไฟล์ (!verify ...)
    if message.content.startswith('!verify ') and message.attachments:
        original_hash = message.content.split(' ')[1]
        attachment = message.attachments[0]
        status_msg = await message.reply(f'Checking file hash...: {attachment.filename} ...')
        
        file_bytes = await attachment.read()
                
        # เรียกใช้ verify_hash
        match, file_hash = scanner_api.verify_hash(file_bytes, original_hash)

        if match:
            result = "✅ Hash matched! The file has not been modified"
        else:
            result = "❌ Hash mismatch! File modified or corrupted"

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

    # 5. สแกนไฟล์ทั่วไปแบบออโต้
    elif message.attachments and not message.content.startswith('!verify'):
        for attachment in message.attachments:
            status_msg = await message.reply(f'Checking file...: {attachment.filename} ...')
            
            file_bytes = await attachment.read()

            if attachment.filename.lower().endswith('.zip'):
                try:
                    with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                        is_encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
                        if is_encrypted:
                            alert_msg = "❌ **Warning!** ไฟล์ถูกเข้ารหัสผ่าน (Password-Protected)"
                            embed = create_embed("⚠️ Security Alert", alert_msg, "File name", attachment.filename)
                            await status_msg.edit(content="", embed=embed)
                            continue
                except zipfile.BadZipFile:
                    pass
            
            # เรียกใช้ calculate_hash
            file_hash = scanner_api.calculate_hash(file_bytes)
            
            # เรียกใช้ check_virustotal_file
            result = scanner_api.check_virustotal_file(file_hash, VT_API_KEY)

            embed = create_embed(
                "File Scan Report",
                result,
                "File name", attachment.filename,
                extra_fields={
                    "SHA-256 Hash": f"`{file_hash}`"
                }
            )
            await status_msg.edit(content="", embed=embed)

# ==========================================
# 5. สั่งรันบอท
# ==========================================
client.run(TOKEN)
