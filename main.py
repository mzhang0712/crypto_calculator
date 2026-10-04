import os
import json
import time
import random
import logging
from binascii import unhexlify, hexlify
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
from google.genai import types

# 引入密碼學函式庫
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# 1. 初始化 FastAPI 應用程式
app = FastAPI(
    title="AES 測試向量生成 API 後端",
    description="透過 Gemini 3.8-flash 模型的強型別 JSON 輸出，結合本機密碼學引擎校對",
    version="1.0.0"
)

# 2. 設定允許跨網域存取的來源 (開發環境可設為 ["*"] 允許所有來源)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # 允許任何前端網域存取
    allow_credentials=True,
    allow_methods=["*"],          # 允許所有 HTTP 方法 (POST, GET 等)
    allow_headers=["*"],          # 允許所有 HTTP Headers
)

# 2. 取得 uvicorn 的預設 logger，這樣印出來的格式會完全一致
logger = logging.getLogger("uvicorn.error")

# 3. 定義前端傳入的 Request 格式 (可選，讓使用者能指定生成組數)
class GeneratorRequest(BaseModel):
    num_vectors: int = 5

def verify_aes_cbc_math(key_hex, iv_hex, plaintext_hex, expected_ciphertext_hex):
    try:
        key = unhexlify(key_hex.strip())
        iv = unhexlify(iv_hex.strip())
        plaintext = unhexlify(plaintext_hex.strip())
        expected_ciphertext = unhexlify(expected_ciphertext_hex.strip())
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encrypter = cipher.encryptor()
        
        actual_ciphertext = encrypter.update(padded_data) + encrypter.finalize()
        is_correct = (actual_ciphertext == expected_ciphertext)
        actual_ciphertext_hex = hexlify(actual_ciphertext).decode('utf-8')
        
        return is_correct, actual_ciphertext_hex
    except Exception as e:
        return False, f"校對錯誤: {str(e)}"

# 3. 建立網頁 API 路由
@app.post("/api/generate-vectors")
async def generate_and_verify_vectors_api(request: GeneratorRequest):
    # 3. 使用 logger.info() 或 logger.error()
    print("\n\n>>>>>>>>>> [PRINT TEST] 路由被成功觸發了！ <<<<<<<<<<\n\n")

    logger.info(f"開始執行 AI 生成，請求組數: {request.num_vectors}")
    api_key = os.environ.get("GEMINI_API_KEY")
    
    if not api_key:
        raise HTTPException(status_code=500, detail="伺服器未設定 GEMINI_API_KEY 環境變數！")

    client = genai.Client(api_key=api_key)

    prompt = f"""
    Generate exactly {request.num_vectors} distinct test vectors for AES-CBC encryption algorithm.
    All strings must be pure hexadecimal representation (lowercase or uppercase, no '0x').
    Provide a mix of AES-128 (16-byte keys) and AES-256 (32-byte keys).
    The Plaintext should be data that requires PKCS#7 padding.
    Calculate the mathematically correct Ciphertext for each vector.
    """

    target_schema = {
        "type": "ARRAY",
        "items": {
            "type": "OBJECT",
            "properties": {
                "key": {"type": "STRING"},
                "iv": {"type": "STRING"},
                "plaintext": {"type": "STRING"},
                "ciphertext": {"type": "STRING"},
                "key_size_bits": {"type": "INTEGER"}
            },
            "required": ["key", "iv", "plaintext", "ciphertext", "key_size_bits"]
        }
    }

    max_retries = 10
    base_delay = 2
    response = None

    # 指數退避重試
    for attempt in range(1, max_retries + 1):
        try:
            chat = client.chats.create(
                model='gemini-3.8-flash',
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=target_schema,
                    thinking_config=types.ThinkingConfig(thinking_budget=1024)
                )
            )
            response = chat.send_message(prompt)
            break
        
        except Exception as e:
            logger.error(
                f"Gemini API 第 {attempt} 次呼叫失敗: "
                f"{type(e).__name__}: {str(e)}",
                exc_info=True
            )
            if "503" in str(e) or "UNAVAILABLE" in str(e):
                if attempt == max_retries:
                    raise HTTPException(status_code=503, detail="Gemini 伺服器繁忙，重試後依然無法連線。")
                # 計算指數延遲時間並加上隨機波動（Jitter），避免同時與其他使用者撞車
                delay = (base_delay ** attempt) + random.uniform(0.5, 1.5)
                print(f"⚠️ 伺服器過載 (503 UNAVAILABLE)。將於 {delay:.2f} 秒後自動重試...\n")
                time.sleep(delay)
            else:
                raise HTTPException(status_code=500, detail=f"呼叫 Gemini 失敗: {str(e)}")

    try:
        print(f"\n==== [DEBUG] Gemini 原始回應文字 ====\n{response.text}\n==================================")
        vectors = json.loads(response.text)
        verified_test_suite = []

        for vec in vectors:
            is_valid, actual_ct = verify_aes_cbc_math(
                vec['key'], vec['iv'], vec['plaintext'], vec['ciphertext']
            )
            if is_valid:
                vec['verification'] = "PASS"
            else:
                vec['ciphertext'] = actual_ct
                vec['verification'] = "FIXED_BY_BACKEND"
            verified_test_suite.append(vec)

        # 直接回傳 JSON，FastAPI 會自動轉為網頁 HTTP Response
        return {"status": "success", "data": verified_test_suite}

    except Exception as json_err:
        raise HTTPException(status_code=500, detail=f"資料解析與校對邏輯失敗: {str(json_err)}")

# 4. 啟動伺服器進入點
if __name__ == "__main__":
    import uvicorn
    # 啟動在本機 127.0.0.1 的 8000 埠口
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
