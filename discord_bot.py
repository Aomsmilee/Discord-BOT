import discord
import scanner_api
import aiohttp

# 🚨 ใส่ Token และ API Key ตรงนี้
TOKEN = 'DISCORD_TOKEN'
VT_API_KEY = 'VIRUSTOTAL_API_KEY'

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

@client.event
async def on_ready():
    print(f'✅ {client.user} Status: Ready!')

@client.event
async def on_message(message):
    # ป้องกันไม่ให้บอทคุยกับตัวเอง
    if message.author == client.user:
        return

    # ฟังก์ชันสร้างการ์ด
    def create_embed(title, result, detail_name, detail_value, extra_fields=None):
        if "✅" in result:
            color = discord.Color.green()
        elif "❌" in result:
            color = discord.Color.red()
        else:
            color = discord.Color.orange()

        embed = discord.Embed(title=title, color=color)
        embed.add_field(name="Verification Results", value=result, inline=False)
        embed.add_field(name=detail_name, value=detail_value, inline=False)

        if extra_fields:
            for name, value in extra_fields.items():
                embed.add_field(name=name, value=value, inline=False)

        embed.set_footer(text="Sentinel Security System")
        return embed

    # 1. เช็คสถานะการทำงาน
    if message.content == 'Hello':
        await message.reply('Hi! Bot ready to scan!')

    # 2. เช็คลิ้งค์ (!link https://...)
    if message.content.startswith('!link '):
        url_to_check = message.content.split(' ')[1]
        status_msg = await message.reply(f'🔍 Checking the link...: {url_to_check} ...')
        
        result = scanner_api.check_virustotal_url(url_to_check, VT_API_KEY)
        embed = create_embed("Link Scanning Results", result, "URL", url_to_check)
        
        await status_msg.edit(content="", embed=embed)

    # 3. เช็คไฟล์ด้วย Hash (!check <hash>)
    if message.content.startswith('!check '):
        hash_to_check = message.content.split(' ')[1]
        status_msg = await message.reply('🔍 Checking hash...')
        
        result = scanner_api.check_virustotal_file(hash_to_check, VT_API_KEY)
        embed = create_embed("Hash Scanning Results", result, "Hash", hash_to_check)
        
        await status_msg.edit(content="", embed=embed)

    # 4. ตรวจสอบไฟล์ไม่ให้โดนดัดแปลง (!verify <hash> + แนบไฟล์)
    if message.content.startswith('!verify ') and message.attachments:
        original_hash = message.content.split(' ')[1]
        attachment = message.attachments[0]
        status_msg = await message.reply(f'🔍 Checking file hash...: {attachment.filename} ...')
        
        # ดาวน์โหลดไฟล์ชั่วคราวมาตรวจ
        async with aiohttp.ClientSession() as session:
            async with session.get(attachment.url) as resp:
                file_bytes = await resp.read()
                
        match, file_hash = scanner_api.verify_hash(file_bytes, original_hash)

        if match:
            result = "✅ Hash matched! The file has not been modified"
        else:
            result = "❌ Hash mismatch! File modified or corrupted"

        embed = create_embed(
            "🔐 Source Hash Integrity Report",
            result,
            "File name", attachment.filename,
            extra_fields={
                "Original Hash": f"`{original_hash}`",
                "File Hash": f"`{file_hash}`"
            }
        )
        await status_msg.edit(content="", embed=embed)

    # 5. สแกนไฟล์ทั่วไป
    elif message.attachments and not message.content.startswith('!verify'):
        for attachment in message.attachments:
            status_msg = await message.reply(f'🔍 Checking file...: {attachment.filename} ...')
            
            file_bytes = await attachment.read()
            file_hash = scanner_api.calculate_hash(file_bytes)
            result = scanner_api.check_virustotal_file(file_hash, VT_API_KEY)
            
            embed = create_embed(
                "📁 File Scan Report",
                result,
                "File name", attachment.filename,
                extra_fields={
                    "SHA-256 Hash": f"`{file_hash}`"
                }
            )
            await status_msg.edit(content="", embed=embed)

client.run(TOKEN)
