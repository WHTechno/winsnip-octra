import json
import base64
import hashlib
import time
import re
import random
import aiohttp
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import nacl.signing
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel
from typing import Optional, List, Dict

app = FastAPI(title="Octra Wallet API", version="2.0")

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
    "encrypted_balance": 0.0
}

executor = ThreadPoolExecutor(max_workers=4)

# Data models
class TransactionRequest(BaseModel):
    to: str
    amount: float
    message: Optional[str] = None

class LoadWalletRequest(BaseModel):
    private_key: str

class PrivateTransferRequest(BaseModel):
    to: str
    amount: float

class ClaimTransferRequest(BaseModel):
    transfer_id: str

class BalanceOperationRequest(BaseModel):
    amount: float

# Helpers
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

async def make_request(method: str, path: str, data: dict = None, timeout: int = 10):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
        try:
            url = f"{wallet_state['rpc']}{path}"
            async with getattr(session, method.lower())(url, json=data) as resp:
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
        # fallback if error
        wallet_state["nonce"] = 0
        wallet_state["balance"] = 0.0

    return wallet_state["nonce"], wallet_state["balance"]

async def get_encrypted_balance():
    return {
        "public": wallet_state["balance"] or 0,
        "encrypted": wallet_state["encrypted_balance"] or 0,
        "total": wallet_state["balance"] or 0
    }

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

# Cryptographic operations
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

# API endpoints
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

    return {
        "address": wallet_state["addr"],
        "balance": f"{balance:.6f}",
        "nonce": nonce,
        "public_key": wallet_state["pub"],
        "encrypted_balance": encrypted_data,
        "transactions": wallet_state["transactions"][:20],
        "pending_transactions": [tx for tx in wallet_state["transactions"] if not tx.get("epoch")]
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
            'message': tx.message,
            'epoch': None
        })
        wallet_state["balance"] -= tx.amount
        return {"status": "success", "tx_hash": transaction["hash"]}

    raise HTTPException(status_code=400, detail="Transaction failed")

@app.post("/api/private_transfer")
async def api_private_transfer(tx: PrivateTransferRequest):
    if not wallet_state["addr"]:
        raise HTTPException(status_code=400, detail="No wallet loaded")
    
    if not b58.match(tx.to):
        raise HTTPException(status_code=400, detail="Invalid address")
    if tx.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount")
    
    encrypted_data = await get_encrypted_balance()
    if encrypted_data["encrypted"] < tx.amount:
        raise HTTPException(status_code=400, detail="Insufficient encrypted balance")
    
    # In a real implementation, we would encrypt the amount here
    data = {
        "from": wallet_state["addr"],
        "to": tx.to,
        "amount": str(int(tx.amount * μ)),
        "from_private_key": wallet_state["priv"]
    }
    
    status, response, result = await make_request('POST', '/private_transfer', data)
    
    if status == 200:
        wallet_state["encrypted_balance"] -= tx.amount
        wallet_state["transactions"].insert(0, {
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'transfer_id': result.get("transfer_id"),
            'amt': tx.amount,
            'to': tx.to,
            'type': 'private_out',
            'ok': True,
            'epoch': None
        })
        return {"status": "success", "transfer_id": result.get("transfer_id")}
    raise HTTPException(status_code=400, detail=result.get("error", "Private transfer failed"))

@app.get("/api/pending_private_transfers")
async def api_get_pending_transfers():
    if not wallet_state["addr"]:
        raise HTTPException(status_code=400, detail="No wallet loaded")
    
    status, _, result = await make_request('GET', f'/pending_private_transfers?address={wallet_state["addr"]}')
    
    if status == 200:
        transfers = result.get("pending_transfers", [])
        return {"transfers": transfers}
    raise HTTPException(status_code=400, detail="Failed to get pending transfers")

@app.post("/api/claim_private_transfer")
async def api_claim_transfer(claim: ClaimTransferRequest):
    if not wallet_state["addr"]:
        raise HTTPException(status_code=400, detail="No wallet loaded")
    
    claim_data = {
        "recipient_address": wallet_state["addr"],
        "private_key": wallet_state["priv"],
        "transfer_id": claim.transfer_id
    }
    
    status, _, result = await make_request('POST', '/claim_private_transfer', claim_data)
    
    if status == 200:
        amount = float(result.get("amount", 0)) / μ
        wallet_state["encrypted_balance"] += amount
        wallet_state["transactions"].insert(0, {
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'transfer_id': claim.transfer_id,
            'amt': amount,
            'from': result.get("from"),
            'type': 'private_in',
            'ok': True,
            'epoch': None
        })
        return {"status": "success", "amount": amount}
    raise HTTPException(status_code=400, detail=result.get("error", "Claim failed"))

@app.post("/api/encrypt_balance")
async def api_encrypt_balance(op: BalanceOperationRequest):
    if not wallet_state["addr"]:
        raise HTTPException(status_code=400, detail="No wallet loaded")
    
    _, balance = await update_wallet_state()
    if balance < op.amount + 1:  # +1 for fee
        raise HTTPException(status_code=400, detail="Insufficient public balance")
    
    encrypted_value = encrypt_client_balance(int(op.amount * μ), wallet_state["priv"])
    
    encrypted_data = {
        "address": wallet_state["addr"],
        "amount": str(int(op.amount * μ)),
        "private_key": wallet_state["priv"],
        "encrypted_data": encrypted_value
    }
    
    status, _, result = await make_request('POST', '/encrypt_balance', encrypted_data)
    
    if status == 200:
        wallet_state["balance"] -= op.amount + 1
        wallet_state["encrypted_balance"] += op.amount
        wallet_state["transactions"].insert(0, {
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'tx_hash': result.get("tx_hash"),
            'amt': op.amount,
            'type': 'encrypt',
            'ok': True,
            'epoch': None
        })
        return {"status": "success", "tx_hash": result.get("tx_hash")}
    raise HTTPException(status_code=400, detail=result.get("error", "Encryption failed"))

@app.post("/api/decrypt_balance")
async def api_decrypt_balance(op: BalanceOperationRequest):
    if not wallet_state["addr"]:
        raise HTTPException(status_code=400, detail="No wallet loaded")
    
    encrypted_data = await get_encrypted_balance()
    if encrypted_data["encrypted"] < op.amount:
        raise HTTPException(status_code=400, detail="Insufficient encrypted balance")
    
    # In a real implementation, we would encrypt the remaining balance here
    decrypted_data = {
        "address": wallet_state["addr"],
        "amount": str(int(op.amount * μ)),
        "private_key": wallet_state["priv"]
    }
    
    status, _, result = await make_request('POST', '/decrypt_balance', decrypted_data)
    
    if status == 200:
        wallet_state["encrypted_balance"] -= op.amount
        wallet_state["balance"] += op.amount
        wallet_state["transactions"].insert(0, {
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'tx_hash': result.get("tx_hash"),
            'amt': op.amount,
            'type': 'decrypt',
            'ok': True,
            'epoch': None
        })
        return {"status": "success", "tx_hash": result.get("tx_hash")}
    raise HTTPException(status_code=400, detail=result.get("error", "Decryption failed"))

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
        "encrypted_balance": 0.0
    })

@app.on_event("shutdown")
async def shutdown_event():
    executor.shutdown(wait=False)