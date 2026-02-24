import hashlib
import requests
import base64

def calculate_hash(file_bytes):
    """คำนวณรหัส SHA-256 จากไฟล์"""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()

def verify_hash(file_bytes, original_hash):
    """
    เปรียบเทียบ Hash ต้นฉบับกับ Hash ของไฟล์ที่ดาวน์โหลดมา
    - file_bytes: ไฟล์ที่ต้องการตรวจสอบ
    - original_hash: Hash ต้นฉบับที่ได้จากเว็บผู้พัฒนา
    คืนค่าเป็น (ตรงกันไหม, hash_ของไฟล์)
    """
    file_hash = calculate_hash(file_bytes)
    original_hash = original_hash.strip().lower()
    file_hash_lower = file_hash.lower()
    match = file_hash_lower == original_hash
    return match, file_hash

def get_analysis_stats(response):
    """ฟังก์ชันช่วยแปลผลลัพธ์จาก VirusTotal"""
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        if malicious > 0:
            return f"❌ อันตราย! พบมัลแวร์/Phishing {malicious} รายการ"
        else:
            return "✅ ปลอดภัย (ไม่พบสิ่งผิดปกติในฐานข้อมูล)"
    elif response.status_code == 404:
        return "⚪ ไม่พบข้อมูลในระบบ (อาจเป็นลิ้งค์/ไฟล์ใหม่ที่ยังไม่เคยถูกสแกน)"
    else:
        return f"⚠️ ระบบขัดข้อง (Error: {response.status_code})"

def check_virustotal_file(file_hash, api_key):
    """เช็คไฟล์ด้วย Hash"""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return get_analysis_stats(response)

def check_virustotal_url(target_url, api_key):
    """เช็คลิ้งค์ (URL)"""
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return get_analysis_stats(response)