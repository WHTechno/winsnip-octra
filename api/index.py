import json
import base64
import hashlib
import time
import re
import random
import aiohttp
import asyncio
import hmac
import secrets
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import nacl.signing
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel
from typing import Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI(title="Octra Wallet API", version="3.0")

# Configuration
app.mount("/static", StaticFiles(directory="static"), name="static")

# Constants
μ = 1_000_000  # Micro unit conversion
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{40,48}$")  # Address regex

# Wallet state
wallet_state = {
    "priv": None,
    "addr": None,
    "rpc": "https://octra.network",
    "sk": None,
    "pub": None,
    "balance": 0.0,
    "nonce": 0,
    "last_updated": 0,
    "transactions": [],
    "encrypted_balance": 0.0,
    "pending_transfers": []
}

executor = ThreadPoolExecutor(max_workers=4)

# Data Models
class TransactionRequest(BaseModel):
    to: str
    amount: float
    message: Optional[str] = None

class MultiSendRequest(BaseModel):
    recipients: List[TransactionRequest]

class LoadWalletRequest(BaseModel):
    private_key: str

class EncryptBalanceRequest(BaseModel):
    amount: float

class DecryptBalanceRequest(BaseModel):
    amount: float

class PrivateTransferRequest(BaseModel):
    to: str
    amount: float

class ClaimTransferRequest(BaseModel):
    transfer_id: str

# Helper Functions
def base58_encode(data: bytes) -> str:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    x = int.from_bytes(data, 'big')
    result = ''
    while x > 0:
        x, r = divmod(x, 58)
        result = alphabet[r] + result
    return result.rjust(44, alphabet[0])

def load_wallet(base64_key: str = None) -> bool:
    try:
        if base64_key:
            decoded_key = base64.b64decode(base64_key, validate=True)
            if len(decoded_key) != 32:
                raise ValueError("Invalid private key length")
            wallet_state["priv"] = base64_key
            wallet_state["sk"] = nacl.signing.SigningKey(decoded_key)
            wallet_state["pub"] = base64.b64encode(wallet_state["sk"].verify_key.encode()).decode()
            pubkey_hash = hashlib.sha256(wallet_state["sk"].verify_key.encode()).digest()
            wallet_state["addr"] = "oct" + base58_encode(pubkey_hash)[:45]
            if not b58.match(wallet_state["addr"]):
                raise ValueError("Generated address is invalid")
            return True
        raise ValueError("No private key provided")
    except Exception as e:
        print(f"Wallet load error: {str(e)}")
        return False

async def make_request(method: str, path: str, data: dict = None, timeout: int = 10, headers: dict = None):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
        try:
            url = f"{wallet_state['rpc']}{path}"
            kwargs = {"headers": headers} if headers else {}
            if method == 'POST' and data:
                kwargs['json'] = data
                
            async with getattr(session, method.lower())(url, **kwargs) as resp:
                text = await resp.text()
                try:
                    return resp.status, text, json.loads(text) if text else None
                except json.JSONDecodeError:
                    return resp.status, text, None
        except Exception as e:
            return 0, str(e), None

async def update_wallet_state():
    now = time.time()
    if wallet_state["balance"] and (now - wallet_state["last_updated"]) < 30:
        return wallet_state["nonce"], wallet_state["balance"]

    results = await asyncio.gather(
        make_request('GET', f'/balance/{wallet_state["addr"]}'),
        make_request('GET', '/staging', None, 5),
        return_exceptions=True
    )

    # Balance response
    status, text, json_data = results[0] if not isinstance(results[0], Exception) else (0, str(results[0]), None)

    if status == 200 and json_data:
        wallet_state["nonce"] = int(json_data.get('nonce', 0))
        wallet_state["balance"] = float(json_data.get('balance', 0))
        wallet_state["last_updated"] = now

        # Staging transactions
        if len(results) > 1 and not isinstance(results[1], Exception):
            _, _, staging_data = results[1]
            if staging_data and 'staged_transactions' in staging_data:
                our_txs = [tx for tx in staging_data['staged_transactions']
                          if tx.get('from') == wallet_state["addr"]]
                if our_txs:
                    wallet_state["nonce"] = max(wallet_state["nonce"],
                        max(int(tx.get('nonce', 0)) for tx in our_txs))
    else:
        # Fallback if error
        wallet_state["nonce"] = 0
        wallet_state["balance"] = 0.0

    return wallet_state["nonce"], wallet_state["balance"]

def derive_encryption_key(privkey_b64: str) -> bytes:
    privkey_bytes = base64.b64decode(privkey_b64)
    salt = b"octra_encrypted_balance_v2"
    return hashlib.sha256(salt + privkey_bytes).digest()[:32]

def encrypt_client_balance(balance: int, privkey_b64: str) -> str:
    key = derive_encryption_key(privkey_b64)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = str(balance).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return "v2|" + base64.b64encode(nonce + ciphertext).decode()

def decrypt_client_balance(encrypted_data: str, privkey_b64: str) -> int:
    if not encrypted_data or encrypted_data == "0":
        return 0
    
    if not encrypted_data.startswith("v2|"):
        # Legacy v1 decryption (if needed)
        privkey_bytes = base64.b64decode(privkey_b64)
        salt = b"octra_encrypted_balance_v1"
        key = hashlib.sha256(salt + privkey_bytes).digest() + hashlib.sha256(privkey_bytes + salt).digest()
        key = key[:32]
        
        try:
            data = base64.b64decode(encrypted_data)
            if len(data) < 32:
                return 0
            
            nonce = data[:16]
            tag = data[16:32]
            encrypted = data[32:]
            
            expected_tag = hashlib.sha256(nonce + encrypted + key).digest()[:16]
            if not hmac.compare_digest(tag, expected_tag):
                return 0
            
            decrypted = bytearray()
            key_hash = hashlib.sha256(key + nonce).digest()
            for i, byte in enumerate(encrypted):
                decrypted.append(byte ^ key_hash[i % 32])
            
            return int(decrypted.decode())
        except:
            return 0
    
    # V2 decryption
    try:
        b64_data = encrypted_data[3:]
        raw = base64.b64decode(b64_data)
        
        if len(raw) < 28:
            return 0
        
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        key = derive_encryption_key(privkey_b64)
        aesgcm = AESGCM(key)
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return int(plaintext.decode())
    except:
        return 0

def derive_shared_secret_for_claim(my_privkey_b64: str, ephemeral_pubkey_b64: str) -> bytes:
    sk = nacl.signing.SigningKey(base64.b64decode(my_privkey_b64))
    my_pubkey_bytes = sk.verify_key.encode()
    eph_pub_bytes = base64.b64decode(ephemeral_pubkey_b64)
    
    if eph_pub_bytes < my_pubkey_bytes:
        smaller, larger = eph_pub_bytes, my_pubkey_bytes
    else:
        smaller, larger = my_pubkey_bytes, eph_pub_bytes
    
    combined = smaller + larger
    round1 = hashlib.sha256(combined).digest()
    round2 = hashlib.sha256(round1 + b"OCTRA_SYMMETRIC_V1").digest()
    return round2[:32]

def decrypt_private_amount(encrypted_data: str, shared_secret: bytes) -> Optional[int]:
    if not encrypted_data or not encrypted_data.startswith("v2|"):
        return None
    
    try:
        raw = base64.b64decode(encrypted_data[3:])
        if len(raw) < 28:
            return None
        
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        aesgcm = AESGCM(shared_secret)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return int(plaintext.decode())
    except:
        return None

async def get_encrypted_balance():
    # Try to get encrypted balance from server
    headers = {"X-Private-Key": wallet_state["priv"]}
    try:
        status, _, json_data = await make_request(
            'GET', 
            f'/view_encrypted_balance/{wallet_state["addr"]}', 
            headers=headers
        )
        
        if status == 200 and json_data:
            return {
                "public": float(json_data.get("public_balance", "0").split()[0]),
                "public_raw": int(json_data.get("public_balance_raw", "0")),
                "encrypted": float(json_data.get("encrypted_balance", "0").split()[0]),
                "encrypted_raw": int(json_data.get("encrypted_balance_raw", "0")),
                "total": float(json_data.get("total_balance", "0").split()[0])
            }
    except Exception as e:
        print(f"Error getting encrypted balance: {str(e)}")
    
    # Fallback to local state
    return {
        "public": wallet_state["balance"] or 0,
        "public_raw": int((wallet_state["balance"] or 0) * μ),
        "encrypted": wallet_state["encrypted_balance"] or 0,
        "encrypted_raw": int((wallet_state["encrypted_balance"] or 0) * μ),
        "total": (wallet_state["balance"] or 0) + (wallet_state["encrypted_balance"] or 0)
    }

async def get_public_key(address: str) -> Optional[str]:
    status, _, json_data = await make_request('GET', f'/public_key/{address}')
    if status == 200 and json_data:
        return json_data.get("public_key")
    return None

async def create_transaction(to: str, amount: float, message: str = None):
    tx = {
        "from": wallet_state["addr"],
        "to_": to,
        "amount": str(int(amount * μ)),
        "nonce": wallet_state["nonce"] + 1,
        "ou": "1" if amount < 1000 else "3",
        "timestamp": time.time() + random.random() * 0.01
    }
    if message:
        tx["message"] = message

    tx_json = json.dumps({k: v for k, v in tx.items() if k != "message"}, separators=(",", ":"))
    signature = base64.b64encode(wallet_state["sk"].sign(tx_json.encode()).signature).decode()
    return {
        **tx,
        "signature": signature,
        "public_key": wallet_state["pub"],
        "hash": hashlib.sha256(tx_json.encode()).hexdigest()
    }

async def update_pending_transfers():
    headers = {"X-Private-Key": wallet_state["priv"]}
    status, _, json_data = await make_request(
        'GET', 
        f'/pending_private_transfers?address={wallet_state["addr"]}', 
        headers=headers
    )
    
    if status == 200 and json_data:
        transfers = json_data.get("pending_transfers", [])
        wallet_state["pending_transfers"] = []
        
        for transfer in transfers:
            decrypted_amount = None
            if transfer.get('encrypted_data') and transfer.get('ephemeral_key'):
                shared_secret = derive_shared_secret_for_claim(
                    wallet_state["priv"],
                    transfer['ephemeral_key']
                )
                decrypted_amount = decrypt_private_amount(
                    transfer['encrypted_data'],
                    shared_secret
                )
            
            wallet_state["pending_transfers"].append({
                "id": transfer.get('id'),
                "sender": transfer.get('sender'),
                "amount": decrypted_amount / μ if decrypted_amount else None,
                "epoch_id": transfer.get('epoch_id'),
                "timestamp": transfer.get('timestamp'),
                "status": "claimable"
            })

# API Endpoints
@app.post("/api/load_wallet")
async def api_load_wallet(data: LoadWalletRequest):
    if not load_wallet(data.private_key):
        raise HTTPException(status_code=400, detail="Invalid private key")
    return {"status": "success", "address": wallet_state["addr"]}

@app.get("/api/wallet")
async def api_get_wallet():
    if not wallet_state["addr"]:
        raise HTTPException(status_code=400, detail="No wallet loaded")

    nonce, balance = await update_wallet_state()
    encrypted_data = await get_encrypted_balance()
    await update_pending_transfers()

    return {
        "address": wallet_state["addr"],
        "balance": f"{balance:.6f}",
        "nonce": nonce,
        "public_key": wallet_state["pub"],
        "encrypted_balance": encrypted_data,
        "transactions": wallet_state["transactions"][:20],
        "pending_transfers": wallet_state["pending_transfers"]
    }

@app.post("/api/send")
async def api_send_transaction(tx: TransactionRequest):
    if not b58.match(tx.to):
        raise HTTPException(status_code=400, detail="Invalid address")
    if tx.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount")

    nonce, balance = await update_wallet_state()
    if not balance or balance < tx.amount:
        raise HTTPException(status_code=400, detail=f"Insufficient balance ({balance:.6f} < {tx.amount})")

    transaction = await create_transaction(tx.to, tx.amount, tx.message)
    status, response, _ = await make_request('POST', '/send-tx', transaction)

    if status == 200:
        wallet_state["transactions"].insert(0, {
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'hash': transaction["hash"],
            'amt': tx.amount,
            'to': tx.to,
            'type': 'out',
            'ok': True,
            'message': tx.message
        })
        wallet_state["balance"] -= tx.amount
        return {"status": "success", "tx_hash": transaction["hash"]}

    raise HTTPException(status_code=400, detail="Transaction failed")

@app.post("/api/multi_send")
async def api_multi_send(data: MultiSendRequest):
    if not data.recipients or len(data.recipients) == 0:
        raise HTTPException(status_code=400, detail="No recipients provided")

    # Validate all recipients first
    for recipient in data.recipients:
        if not b58.match(recipient.to):
            raise HTTPException(status_code=400, detail=f"Invalid address: {recipient.to}")
        if recipient.amount <= 0:
            raise HTTPException(status_code=400, detail=f"Invalid amount for {recipient.to}")

    # Calculate total amount
    total_amount = sum(r.amount for r in data.recipients)
    
    # Check balance
    nonce, balance = await update_wallet_state()
    if not balance or balance < total_amount:
        raise HTTPException(status_code=400, 
                          detail=f"Insufficient balance ({balance:.6f} < {total_amount})")

    # Prepare all transactions
    transactions = []
    for i, recipient in enumerate(data.recipients):
        transactions.append(await create_transaction(
            recipient.to, 
            recipient.amount, 
            recipient.message
        ))

    # Send transactions in batches
    batch_size = 5
    results = []
    for i in range(0, len(transactions), batch_size):
        batch = transactions[i:i + batch_size]
        tasks = [make_request('POST', '/send-tx', tx) for tx in batch]
        batch_results = await asyncio.gather(*tasks)
        results.extend(batch_results)

    # Process results
    success_count = 0
    failed_count = 0
    tx_hashes = []
    
    for i, (status, response, _) in enumerate(results):
        if status == 200:
            success_count += 1
            tx_hashes.append(transactions[i]["hash"])
            wallet_state["transactions"].insert(0, {
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hash': transactions[i]["hash"],
                'amt': data.recipients[i].amount,
                'to': data.recipients[i].to,
                'type': 'out',
                'ok': True,
                'message': data.recipients[i].message
            })
        else:
            failed_count += 1

    # Update balance
    wallet_state["balance"] -= sum(r.amount for i, r in enumerate(data.recipients) 
                              if i < len(results) and results[i][0] == 200)

    return {
        "status": "partial" if failed_count > 0 else "success",
        "success_count": success_count,
        "failed_count": failed_count,
        "tx_hashes": tx_hashes
    }

@app.post("/api/encrypt_balance")
async def api_encrypt_balance(data: EncryptBalanceRequest):
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    enc_data = await get_encrypted_balance()
    if not enc_data:
        raise HTTPException(status_code=400, detail="Cannot get encrypted balance info")

    current_public = enc_data['public_raw']
    if current_public < int(data.amount * μ):
        raise HTTPException(status_code=400, detail="Insufficient public balance")

    new_encrypted = enc_data['encrypted_raw'] + int(data.amount * μ)
    encrypted_value = encrypt_client_balance(new_encrypted, wallet_state["priv"])

    payload = {
        "address": wallet_state["addr"],
        "amount": str(int(data.amount * μ)),
        "private_key": wallet_state["priv"],
        "encrypted_data": encrypted_value
    }

    status, response, json_data = await make_request(
        'POST', 
        '/encrypt_balance', 
        payload,
        headers={"X-Private-Key": wallet_state["priv"]}
    )

    if status == 200:
        wallet_state["balance"] -= data.amount
        wallet_state["encrypted_balance"] += data.amount
        return {"status": "success", "tx_hash": json_data.get("tx_hash") if json_data else None}
    
    error = json_data.get("error") if json_data else response
    raise HTTPException(status_code=400, detail=error)

@app.post("/api/decrypt_balance")
async def api_decrypt_balance(data: DecryptBalanceRequest):
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    enc_data = await get_encrypted_balance()
    if not enc_data:
        raise HTTPException(status_code=400, detail="Cannot get encrypted balance info")

    current_encrypted = enc_data['encrypted_raw']
    if current_encrypted < int(data.amount * μ):
        raise HTTPException(status_code=400, detail="Insufficient encrypted balance")

    new_encrypted = current_encrypted - int(data.amount * μ)
    encrypted_value = encrypt_client_balance(new_encrypted, wallet_state["priv"])

    payload = {
        "address": wallet_state["addr"],
        "amount": str(int(data.amount * μ)),
        "private_key": wallet_state["priv"],
        "encrypted_data": encrypted_value
    }

    status, response, json_data = await make_request(
        'POST', 
        '/decrypt_balance', 
        payload,
        headers={"X-Private-Key": wallet_state["priv"]}
    )

    if status == 200:
        wallet_state["balance"] += data.amount
        wallet_state["encrypted_balance"] -= data.amount
        return {"status": "success", "tx_hash": json_data.get("tx_hash") if json_data else None}
    
    error = json_data.get("error") if json_data else response
    raise HTTPException(status_code=400, detail=error)

@app.post("/api/private_transfer")
async def api_private_transfer(data: PrivateTransferRequest):
    if not b58.match(data.to):
        raise HTTPException(status_code=400, detail="Invalid recipient address")
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    if data.to == wallet_state["addr"]:
        raise HTTPException(status_code=400, detail="Cannot send to yourself")

    # Check encrypted balance
    enc_data = await get_encrypted_balance()
    if not enc_data or enc_data['encrypted_raw'] < int(data.amount * μ):
        raise HTTPException(status_code=400, detail="Insufficient encrypted balance")

    # Get recipient's public key
    recipient_pubkey = await get_public_key(data.to)
    if not recipient_pubkey:
        raise HTTPException(status_code=400, detail="Recipient has no public key")

    payload = {
        "from": wallet_state["addr"],
        "to": data.to,
        "amount": str(int(data.amount * μ)),
        "from_private_key": wallet_state["priv"],
        "to_public_key": recipient_pubkey
    }

    status, response, json_data = await make_request(
        'POST', 
        '/private_transfer', 
        payload,
        headers={"X-Private-Key": wallet_state["priv"]}
    )

    if status == 200:
        wallet_state["encrypted_balance"] -= data.amount
        return {
            "status": "success",
            "tx_hash": json_data.get("tx_hash"),
            "ephemeral_key": json_data.get("ephemeral_key")
        }
    
    error = json_data.get("error") if json_data else response
    raise HTTPException(status_code=400, detail=error)

@app.post("/api/claim_transfer")
async def api_claim_transfer(data: ClaimTransferRequest):
    if not data.transfer_id:
        raise HTTPException(status_code=400, detail="Transfer ID required")

    await update_pending_transfers()
    transfer = next((t for t in wallet_state["pending_transfers"] 
                   if t["id"] == data.transfer_id), None)
    
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    payload = {
        "recipient_address": wallet_state["addr"],
        "private_key": wallet_state["priv"],
        "transfer_id": data.transfer_id
    }

    status, response, json_data = await make_request(
        'POST', 
        '/claim_private_transfer', 
        payload,
        headers={"X-Private-Key": wallet_state["priv"]}
    )

    if status == 200:
        wallet_state["encrypted_balance"] += transfer["amount"] if transfer["amount"] else 0
        await update_pending_transfers()
        return {
            "status": "success",
            "amount": transfer["amount"],
            "tx_hash": json_data.get("tx_hash") if json_data else None
        }
    
    error = json_data.get("error") if json_data else response
    raise HTTPException(status_code=400, detail=error)

@app.get("/api/pending_transfers")
async def api_get_pending_transfers():
    await update_pending_transfers()
    return {
        "status": "success",
        "transfers": wallet_state["pending_transfers"]
    }

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    try:
        with open("static/index.html") as f:
            return HTMLResponse(content=f.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to serve index: {str(e)}")

@app.on_event("startup")
async def startup_event():
    wallet_state.update({
        "priv": None,
        "addr": None,
        "sk": None,
        "pub": None,
        "balance": 0.0,
        "nonce": 0,
        "last_updated": 0,
        "transactions": [],
        "encrypted_balance": 0.0,
        "pending_transfers": []
    })

@app.on_event("shutdown")
async def shutdown_event():
    executor.shutdown(wait=False)