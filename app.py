import os
import json
import hashlib
import datetime as dt
import base64
from functools import wraps
from urllib.parse import urlencode

import pandas as pd
import requests
import jwt
from flask import Flask, request, jsonify, render_template, redirect
from dotenv import load_dotenv

load_dotenv()

# =========================
# Config
# =========================
APP_DIR = os.path.dirname(__file__)
TOKENS_FILE = os.path.join(APP_DIR, "tokens.json")
LICENSE_FILE = os.path.join(APP_DIR, "licenses.json")

JWT_SECRET = os.getenv("JWT_SECRET", "dev_jwt_change_me")
SECRET_KEY = os.getenv("SECRET_KEY", "dev_change_me")

AO_PI_SAVE_PATH = os.getenv("AO_PI_SAVE_PATH", "/api/purchase-invoice/bulk-save.do")

OAUTH_AUTHORIZE_URL = "https://account.accurate.id/oauth/authorize"
OAUTH_TOKEN_URL = "https://account.accurate.id/oauth/token"
ACCOUNT_DB_LIST_URL = "https://account.accurate.id/api/db-list.do"
ACCOUNT_OPEN_DB_URL = "https://account.accurate.id/api/open-db.do"

LAST_DEBUG = {
    "time": None,
    "form_sample": None,
    "url": None,
    "headers": None,
    "response_status": None,
    "response": None,
    "summary": None,
}

PI_TEMPLATE_COLUMNS = [
    # grouping/helper
    "SEQ", "NUMBER",

    # header
    "VENDORNO", "BILLNUMBER", "TRANSDATE", "DESCRIPTION",
    "BRANCHID", "BRANCHNAME", "CASHDISCPERCENT", "CASHDISCOUNT",
    "CURRENCYCODE", "RATE", "FISCALRATE", "PAYMENTTERMNAME",
    "SHIPDATE", "SHIPMENTNAME", "FOBNAME", "TOADDRESS",
    "TAXABLE", "INCLUSIVETAX", "TAXDATE", "TAXNUMBER", "TAX1NAME",
    "DOCUMENTCODE", "DOCUMENTTRANSACTION", "VENDORTAXTYPE",
    "REVERSEINVOICE", "INVOICEDP", "INPUTDOWNPAYMENT",
    "ORDERDOWNPAYMENTNUMBER", "FILLPRICEBYVENDORPRICE",
    "TYPEAUTONUMBER", "ID",

    # detail item
    "ITEMNO", "UNITPRICE", "QTY", "DETAILNAME", "DETAILNOTES",
    "ITEMUNITNAME", "ITEMDISCPERCENT", "ITEMCASHDISCOUNT",
    "WAREHOUSENAME", "PROJECTNO", "DEPARTMENTNAME",
    "PURCHASEORDERNUMBER", "PURCHASEREQUISITIONNUMBER", "RECEIVEITEMNUMBER",
    "USETAX1", "USETAX2", "USETAX3", "DETAILITEMID", "DETAILITEMSTATUS",
    "ITEMCLASS1", "ITEMCLASS2", "ITEMCLASS3", "ITEMCLASS4", "ITEMCLASS5",
    "ITEMCLASS6", "ITEMCLASS7", "ITEMCLASS8", "ITEMCLASS9", "ITEMCLASS10",

    # detail expense
    "EXPENSEACCOUNTNO", "EXPENSEAMOUNT", "EXPENSENAME", "EXPENSENOTES",
    "EXPENSECURRENCYCODE", "EXPENSEAMOUNTCURRENCY", "EXPENSEDEPARTMENTNAME",
    "EXPENSEPURCHASEORDERNUMBER", "CHARGEDVENDORNAME", "ALLOCATETOITEMCOST",
    "EXPENSEID", "EXPENSESTATUS",
    "EXPENSECLASS1", "EXPENSECLASS2", "EXPENSECLASS3", "EXPENSECLASS4", "EXPENSECLASS5",
    "EXPENSECLASS6", "EXPENSECLASS7", "EXPENSECLASS8", "EXPENSECLASS9", "EXPENSECLASS10",

    # detail down payment
    "DPINVOICENUMBER", "DPPAYMENTAMOUNT", "DPID", "DPSTATUS",
]

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY


# =========================
# Utils: token file
# =========================
def save_tokens(data: dict):
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_tokens():
    if not os.path.exists(TOKENS_FILE):
        return {}
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            txt = f.read().strip()
            if not txt:
                return {}
            return json.loads(txt)
    except Exception:
        return {}


# =========================
# Utils: license & auth
# =========================
def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_licenses():
    if not os.path.exists(LICENSE_FILE):
        return [
            {
                "email": "demo@aca-aol.id",
                "password_sha256": sha256("1234"),
                "active": True,
                "expires": None,
                "customer_name": "Demo User",
            }
        ]
    with open(LICENSE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def license_valid(email: str, password: str):
    licenses = load_licenses()
    email = (email or "").strip().lower()

    lic = next(
        (x for x in licenses if str(x.get("email", "")).strip().lower() == email),
        None
    )

    if not lic:
        return False, "Email tidak terdaftar", None

    if not lic.get("active"):
        return False, "Akun tidak aktif", None

    expires = lic.get("expires")
    if expires:
        try:
            exp_dt = dt.datetime.fromisoformat(expires + "T23:59:59")
            if dt.datetime.now() > exp_dt:
                return False, "Akun expired", None
        except Exception:
            return False, "Format expires di licenses.json salah", None

    if sha256(password) != lic.get("password_sha256"):
        return False, "Password salah", None

    return True, "OK", lic


def make_token(email: str) -> str:
    payload = {
        "email": email,
        "exp": dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=12),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"ok": False, "message": "Unauthorized"}), 401
        token = auth[7:]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except Exception:
            return jsonify({"ok": False, "message": "Invalid session"}), 401
        return fn(*args, **kwargs)

    return wrapper


# =========================
# OAuth helpers
# =========================
def refresh_access_token_if_needed():
    tokens = load_tokens()
    access_token = (tokens.get("access_token") or "").strip()
    refresh_token = (tokens.get("refresh_token") or "").strip()
    expires_at = (tokens.get("expires_at") or "").strip()

    if not access_token:
        return tokens

    if not expires_at:
        return tokens

    try:
        exp = dt.datetime.fromisoformat(expires_at)
        if dt.datetime.now() < exp - dt.timedelta(minutes=2):
            return tokens
    except Exception:
        return tokens

    if not refresh_token:
        return tokens

    client_id = (os.getenv("AO_CLIENT_ID") or "").strip()
    client_secret = (os.getenv("AO_CLIENT_SECRET") or "").strip()
    if not client_id or not client_secret:
        return tokens

    basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {basic}"}
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}

    r = requests.post(OAUTH_TOKEN_URL, headers=headers, data=data, timeout=60)
    if not r.ok:
        return tokens

    j = r.json()
    expires_in = int(j.get("expires_in") or 3600)
    new_exp = dt.datetime.now() + dt.timedelta(seconds=expires_in)

    tokens.update(
        {
            "access_token": j.get("access_token"),
            "refresh_token": j.get("refresh_token") or refresh_token,
            "expires_at": new_exp.isoformat(),
            "updated_at": dt.datetime.now().isoformat(),
        }
    )
    save_tokens(tokens)
    return tokens


def accurate_post(path: str, data: dict):
    tokens = refresh_access_token_if_needed()
    access_token = (tokens.get("access_token") or "").strip()
    host = (tokens.get("host") or "").strip()
    x_session_id = (tokens.get("x_session_id") or "").strip()

    if not access_token or not host or not x_session_id:
        raise ValueError("OAuth belum lengkap. Connect + pilih DB dulu.")

    url = f"{host}/accurate{path}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Session-ID": x_session_id,
        "Accept": "application/json",
    }

    return requests.post(url, headers=headers, data=data, timeout=120)


# =========================
# Excel helpers
# =========================
def normalize_column_name(col):
    return str(col).strip().upper()


def parse_date_ddmmyyyy(val):
    if val is None:
        return None

    if isinstance(val, (dt.datetime, dt.date)):
        d = val.date() if isinstance(val, dt.datetime) else val
        return d.strftime("%d/%m/%Y")

    if isinstance(val, (int, float)) and str(val).strip() != "":
        try:
            base = dt.datetime(1899, 12, 30)
            d = base + dt.timedelta(days=float(val))
            return d.strftime("%d/%m/%Y")
        except Exception:
            pass

    s = str(val).strip()
    if not s:
        return None

    for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y"):
        try:
            d = dt.datetime.strptime(s, fmt)
            return d.strftime("%d/%m/%Y")
        except Exception:
            continue

    try:
        d = pd.to_datetime(s, dayfirst=True, errors="raise")
        return d.strftime("%d/%m/%Y")
    except Exception:
        return None


def parse_bool(val):
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("true", "1", "yes", "y", "ya"):
        return True
    if s in ("false", "0", "no", "n", "tidak", ""):
        return False
    return None


def parse_money(val, default=None):
    if val is None:
        return default

    if isinstance(val, (int, float)) and not pd.isna(val):
        return float(val)

    s = str(val).strip()
    if s == "":
        return default

    try:
        return float(s.replace(",", ""))
    except Exception:
        return default


def parse_int(val, default=None):
    if val is None or str(val).strip() == "":
        return default
    try:
        return int(float(str(val).replace(",", "").strip()))
    except Exception:
        return default


def clean_str(val):
    return str(val).strip() if val is not None else ""


# =========================
# Purchase Invoice Builder
# =========================
def build_purchase_invoice_payload_from_df(df: pd.DataFrame):
    df = df.rename(columns=lambda c: normalize_column_name(c))
    df = df.fillna("")

    required_cols = ["VENDORNO", "TRANSDATE"]
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"Kolom wajib tidak ada: {col}")

    normalized_rows = []
    for idx, row in df.iterrows():
        line_no = idx + 2

        vendor_no = clean_str(row.get("VENDORNO"))
        if not vendor_no:
            raise ValueError(f"Row {line_no}: VENDORNO kosong")

        trans_date = parse_date_ddmmyyyy(row.get("TRANSDATE"))
        if not trans_date:
            raise ValueError(f"Row {line_no}: TRANSDATE tidak valid")

        item_no = clean_str(row.get("ITEMNO"))
        if item_no:
            unit_price = parse_money(row.get("UNITPRICE"))
            if unit_price is None:
                raise ValueError(f"Row {line_no}: UNITPRICE kosong / tidak valid")
        else:
            unit_price = parse_money(row.get("UNITPRICE"))

        number = clean_str(row.get("NUMBER"))

        normalized_rows.append({
            **row.to_dict(),
            "VENDORNO": vendor_no,
            "TRANSDATE": trans_date,
            "NUMBER": number,
            "UNITPRICE": unit_price,
        })

    auto_i = 1

    def auto_pi_no(date_str, i):
        d = date_str.replace("/", "")
        return f"PI-{d}-{i:03d}"

    grouped = {}
    for r in normalized_rows:
        if not r["NUMBER"]:
            r["NUMBER"] = auto_pi_no(r["TRANSDATE"], auto_i)
            auto_i += 1
        grouped.setdefault(r["NUMBER"], []).append(r)

    data = []

    for number, rows in grouped.items():
        def seq_key(x):
            s = clean_str(x.get("SEQ"))
            try:
                return int(float(s))
            except Exception:
                return 999999

        rows = sorted(rows, key=seq_key)
        head = rows[0]

        tx = {
            "vendorNo": head["VENDORNO"],
            "transDate": head["TRANSDATE"],
            "number": number,
            "detailItem": []
        }

        header_map = {
            "BILLNUMBER": "billNumber",
            "BRANCHID": "branchId",
            "BRANCHNAME": "branchName",
            "CASHDISCPERCENT": "cashDiscPercent",
            "CASHDISCOUNT": "cashDiscount",
            "CURRENCYCODE": "currencyCode",
            "DESCRIPTION": "description",
            "DOCUMENTCODE": "documentCode",
            "DOCUMENTTRANSACTION": "documentTransaction",
            "FILLPRICEBYVENDORPRICE": "fillPriceByVendorPrice",
            "FISCALRATE": "fiscalRate",
            "FOBNAME": "fobName",
            "ID": "id",
            "INCLUSIVETAX": "inclusiveTax",
            "INPUTDOWNPAYMENT": "inputDownPayment",
            "INVOICEDP": "invoiceDp",
            "ORDERDOWNPAYMENTNUMBER": "orderDownPaymentNumber",
            "PAYMENTTERMNAME": "paymentTermName",
            "RATE": "rate",
            "REVERSEINVOICE": "reverseInvoice",
            "SHIPDATE": "shipDate",
            "SHIPMENTNAME": "shipmentName",
            "TAX1NAME": "tax1Name",
            "TAXDATE": "taxDate",
            "TAXNUMBER": "taxNumber",
            "TAXABLE": "taxable",
            "TOADDRESS": "toAddress",
            "TYPEAUTONUMBER": "typeAutoNumber",
            "VENDORTAXTYPE": "vendorTaxType",
        }

        for src, dst in header_map.items():
            val = head.get(src, "")
            if clean_str(val) == "":
                continue

            if src in ("CASHDISCOUNT", "FISCALRATE", "INPUTDOWNPAYMENT", "RATE"):
                val = parse_money(val)
            elif src in ("BRANCHID", "ID", "TYPEAUTONUMBER"):
                val = parse_int(val)
            elif src in ("FILLPRICEBYVENDORPRICE", "INCLUSIVETAX", "INVOICEDP", "REVERSEINVOICE", "TAXABLE"):
                val = parse_bool(val)
            elif src in ("SHIPDATE", "TAXDATE"):
                val = parse_date_ddmmyyyy(val)

            if val not in (None, ""):
                tx[dst] = val

        for r in rows:
            # ===== DETAIL ITEM =====
            item_no = clean_str(r.get("ITEMNO"))
            if item_no:
                item = {
                    "itemNo": item_no,
                    "unitPrice": parse_money(r.get("UNITPRICE"), 0),
                }

                qty = parse_money(r.get("QTY"))
                if qty is not None:
                    item["quantity"] = qty

                optional_item_map = {
                    "DETAILNAME": "detailName",
                    "DETAILNOTES": "detailNotes",
                    "ITEMUNITNAME": "itemUnitName",
                    "ITEMDISCPERCENT": "itemDiscPercent",
                    "ITEMCASHDISCOUNT": "itemCashDiscount",
                    "WAREHOUSENAME": "warehouseName",
                    "PROJECTNO": "projectNo",
                    "DEPARTMENTNAME": "departmentName",
                    "PURCHASEORDERNUMBER": "purchaseOrderNumber",
                    "PURCHASEREQUISITIONNUMBER": "purchaseRequisitionNumber",
                    "RECEIVEITEMNUMBER": "receiveItemNumber",
                    "DETAILITEMID": "id",
                    "DETAILITEMSTATUS": "_status",
                }

                for src, dst in optional_item_map.items():
                    val = r.get(src, "")
                    if clean_str(val) == "":
                        continue
                    if src in ("ITEMCASHDISCOUNT",):
                        val = parse_money(val)
                    elif src in ("DETAILITEMID",):
                        val = parse_int(val)
                    item[dst] = val

                for src, dst in (("USETAX1", "useTax1"), ("USETAX2", "useTax2"), ("USETAX3", "useTax3")):
                    val = parse_bool(r.get(src))
                    if val is not None:
                        item[dst] = val

                for i in range(1, 11):
                    src = f"ITEMCLASS{i}"
                    val = clean_str(r.get(src, ""))
                    if val:
                        item[f"dataClassification{i}Name"] = val

                tx["detailItem"].append(item)

            # ===== DETAIL EXPENSE =====
            exp_account = clean_str(r.get("EXPENSEACCOUNTNO"))
            exp_amount = parse_money(r.get("EXPENSEAMOUNT"))
            exp_name = clean_str(r.get("EXPENSENAME"))
            has_expense = any([
                exp_account,
                exp_amount is not None,
                exp_name,
                clean_str(r.get("EXPENSENOTES")),
                clean_str(r.get("EXPENSECURRENCYCODE")),
                clean_str(r.get("EXPENSEPURCHASEORDERNUMBER")),
            ])

            if has_expense:
                if "detailExpense" not in tx:
                    tx["detailExpense"] = []

                exp = {}
                if exp_account:
                    exp["accountNo"] = exp_account
                if exp_amount is not None:
                    exp["expenseAmount"] = exp_amount
                if exp_name:
                    exp["expenseName"] = exp_name

                exp_map = {
                    "EXPENSENOTES": "expenseNotes",
                    "EXPENSECURRENCYCODE": "expenseCurrencyCode",
                    "EXPENSEAMOUNTCURRENCY": "amountCurrency",
                    "EXPENSEDEPARTMENTNAME": "departmentName",
                    "EXPENSEPURCHASEORDERNUMBER": "purchaseOrderNumber",
                    "CHARGEDVENDORNAME": "chargedVendorName",
                    "ALLOCATETOITEMCOST": "allocateToItemCost",
                    "EXPENSEID": "id",
                    "EXPENSESTATUS": "_status",
                }

                for src, dst in exp_map.items():
                    val = r.get(src, "")
                    if clean_str(val) == "":
                        continue
                    if src in ("EXPENSEAMOUNTCURRENCY",):
                        val = parse_money(val)
                    elif src in ("ALLOCATETOITEMCOST",):
                        val = parse_bool(val)
                    elif src in ("EXPENSEID",):
                        val = parse_int(val)
                    exp[dst] = val

                for i in range(1, 11):
                    src = f"EXPENSECLASS{i}"
                    val = clean_str(r.get(src, ""))
                    if val:
                        exp[f"dataClassification{i}Name"] = val

                if exp:
                    tx["detailExpense"].append(exp)

            # ===== DETAIL DOWN PAYMENT =====
            dp_invoice = clean_str(r.get("DPINVOICENUMBER"))
            dp_payment = parse_money(r.get("DPPAYMENTAMOUNT"))
            dp_id = parse_int(r.get("DPID"))
            dp_status = clean_str(r.get("DPSTATUS"))

            if dp_invoice or dp_payment is not None or dp_id is not None or dp_status:
                if "detailDownPayment" not in tx:
                    tx["detailDownPayment"] = []

                dp = {}
                if dp_invoice:
                    dp["invoiceNumber"] = dp_invoice
                if dp_payment is not None:
                    dp["paymentAmount"] = dp_payment
                if dp_id is not None:
                    dp["id"] = dp_id
                if dp_status:
                    dp["_status"] = dp_status

                if dp:
                    tx["detailDownPayment"].append(dp)

        if len(tx.get("detailItem", [])) == 0:
            raise ValueError(f"Invoice {number}: minimal harus ada 1 detail item dengan ITEMNO")

        data.append(tx)

    return {"data": data}


def purchase_invoice_payload_to_form_params(payload: dict) -> dict:
    out = {}

    for i, tx in enumerate(payload.get("data", [])):
        for k, v in tx.items():
            if k in ("detailItem", "detailExpense", "detailDownPayment"):
                continue
            if v in (None, ""):
                continue
            out[f"data[{i}].{k}"] = v

        for j, item in enumerate(tx.get("detailItem", [])):
            for k, v in item.items():
                if v in (None, ""):
                    continue
                out[f"data[{i}].detailItem[{j}].{k}"] = v

        for j, exp in enumerate(tx.get("detailExpense", [])):
            for k, v in exp.items():
                if v in (None, ""):
                    continue
                out[f"data[{i}].detailExpense[{j}].{k}"] = v

        for j, dp in enumerate(tx.get("detailDownPayment", [])):
            for k, v in dp.items():
                if v in (None, ""):
                    continue
                out[f"data[{i}].detailDownPayment[{j}].{k}"] = v

    return {k: str(v) for k, v in out.items()}


# =========================
# Routes: UI
# =========================
@app.get("/")
def home():
    return render_template("index.html")


# =========================
# Routes: login/license
# =========================
@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not email or not password:
        return jsonify({"ok": False, "message": "Email & password wajib"}), 400

    ok, msg, lic = license_valid(email, password)
    if not ok:
        return jsonify({"ok": False, "message": msg}), 401

    token = make_token(email)

    return jsonify({
        "ok": True,
        "token": token,
        "customer_name": lic.get("customer_name"),
        "email": email
    })


# =========================
# Routes: status
# =========================
@app.get("/api/ao-status")
def api_ao_status():
    tokens = load_tokens()
    return jsonify(
        {
            "ok": True,
            "has_token": bool((tokens.get("access_token") or "").strip()),
            "has_session": bool((tokens.get("host") or "").strip()) and bool((tokens.get("x_session_id") or "").strip()),
            "db_id": tokens.get("db_id"),
            "db_alias": tokens.get("db_alias"),
        }
    )


@app.get("/api/debug-last")
def api_debug_last():
    return jsonify({"ok": True, **LAST_DEBUG})


@app.post("/api/ao-logout")
def api_ao_logout():
    if os.path.exists(TOKENS_FILE):
        os.remove(TOKENS_FILE)
    return jsonify({"ok": True})


# =========================
# Routes: build payload PI
# =========================
@app.post("/api/build-purchase-invoice")
@require_auth
def api_build_purchase_invoice():
    if "file" not in request.files:
        return jsonify({"ok": False, "message": "File tidak ditemukan"}), 400

    f = request.files["file"]
    if not f.filename.lower().endswith((".xlsx", ".xls")):
        return jsonify({"ok": False, "message": "File harus Excel (.xlsx/.xls)"}), 400

    try:
        df = pd.read_excel(f)
        built = build_purchase_invoice_payload_from_df(df)

        tx_count = len(built.get("data", []))
        item_count = sum(len(x.get("detailItem", [])) for x in built.get("data", []))
        expense_count = sum(len(x.get("detailExpense", [])) for x in built.get("data", []))
        dp_count = sum(len(x.get("detailDownPayment", [])) for x in built.get("data", []))

        return jsonify({
            "ok": True,
            "payload": built,
            "summary": {
                "transactions": tx_count,
                "lines": item_count,
                "expenses": expense_count,
                "downPayments": dp_count,
            }
        })
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 400


# =========================
# Routes: import Purchase Invoice
# =========================
@app.post("/api/import-purchase-invoice")
@require_auth
def api_import_purchase_invoice():
    body = request.get_json(silent=True) or {}
    payload = body.get("payload")

    if not payload or "data" not in payload:
        return jsonify({"ok": False, "message": "payload kosong"}), 400

    tokens = refresh_access_token_if_needed()
    access_token = (tokens.get("access_token") or "").strip()
    host = (tokens.get("host") or "").strip()
    x_session = (tokens.get("x_session_id") or "").strip()

    if not access_token or not host or not x_session:
        return jsonify({
            "ok": False,
            "message": "OAuth belum lengkap. Connect + pilih DB dulu."
        }), 400

    url = f"{host}/accurate{AO_PI_SAVE_PATH}"

    results = []
    success_count = 0
    failed_count = 0

    try:
        for idx, tx in enumerate(payload.get("data", []), start=1):
            invoice_no = str(tx.get("number") or f"TX-{idx}").strip()
            trans_date = str(tx.get("transDate") or "-").strip()
            vendor_no = str(tx.get("vendorNo") or "-").strip()
            tx_errors = []
            resp_json = None
            tx_ok = False

            try:
                single_payload = {"data": [tx]}
                form_params = purchase_invoice_payload_to_form_params(single_payload)

                r = accurate_post(AO_PI_SAVE_PATH, data=form_params)

                try:
                    resp_json = r.json()
                except Exception:
                    resp_json = {"raw": r.text}

                if r.ok and isinstance(resp_json, dict) and resp_json.get("s") is True:
                    tx_ok = True
                    success_count += 1
                else:
                    failed_count += 1

                    if isinstance(resp_json, dict):
                        if isinstance(resp_json.get("d"), list):
                            tx_errors = [str(x) for x in resp_json.get("d", [])]
                        elif resp_json.get("d"):
                            tx_errors = [str(resp_json.get("d"))]
                        elif resp_json.get("message"):
                            tx_errors = [str(resp_json.get("message"))]
                        elif resp_json.get("error"):
                            tx_errors = [str(resp_json.get("error"))]
                        else:
                            tx_errors = ["Transaksi ditolak Accurate."]
                    else:
                        tx_errors = ["Response Accurate tidak dikenali."]

                if idx == 1:
                    LAST_DEBUG["form_sample"] = dict(list(form_params.items())[:120])

            except Exception as ex:
                failed_count += 1
                tx_errors = [str(ex)]

            results.append({
                "index": idx,
                "number": invoice_no,
                "transDate": trans_date,
                "vendorNo": vendor_no,
                "ok": tx_ok,
                "errors": tx_errors,
                "raw_response": resp_json
            })

        summary = {
            "total": len(results),
            "success": success_count,
            "failed": failed_count
        }

        LAST_DEBUG["time"] = dt.datetime.now().isoformat()
        LAST_DEBUG["url"] = url
        LAST_DEBUG["headers"] = {
            "Authorization": "Bearer ***",
            "X-Session-ID": x_session
        }
        LAST_DEBUG["response_status"] = 200 if failed_count == 0 else 400
        LAST_DEBUG["response"] = results
        LAST_DEBUG["summary"] = summary

        if failed_count == 0:
            return jsonify({
                "ok": True,
                "message": "Import berhasil",
                "summary": summary,
                "results": results
            }), 200

        return jsonify({
            "ok": False,
            "message": "Import selesai",
            "summary": summary,
            "results": results
        }), 400

    except Exception as e:
        return jsonify({
            "ok": False,
            "message": str(e)
        }), 500


# =========================
# Routes: OAuth
# =========================
@app.get("/oauth/start")
def oauth_start():
    client_id = (os.getenv("AO_CLIENT_ID") or "").strip()
    redirect_uri = (os.getenv("AO_REDIRECT_URI") or "").strip()
    scope = (os.getenv("AO_SCOPE") or "").strip()

    if not client_id or not redirect_uri or not scope:
        return (
            jsonify(
                {
                    "ok": False,
                    "message": "OAuth env belum lengkap. Isi AO_CLIENT_ID, AO_REDIRECT_URI, AO_SCOPE di .env",
                }
            ),
            500,
        )

    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
    }

    url = OAUTH_AUTHORIZE_URL + "?" + urlencode(params)
    return redirect(url, code=302)


@app.get("/oauth/callback")
def oauth_callback():
    code = (request.args.get("code") or "").strip()
    if not code:
        return "Tidak ada parameter code. OAuth ditolak / gagal.", 400

    client_id = (os.getenv("AO_CLIENT_ID") or "").strip()
    client_secret = (os.getenv("AO_CLIENT_SECRET") or "").strip()
    redirect_uri = (os.getenv("AO_REDIRECT_URI") or "").strip()
    if not client_id or not client_secret or not redirect_uri:
        return "OAuth env belum lengkap. Isi AO_CLIENT_ID/AO_CLIENT_SECRET/AO_REDIRECT_URI di .env", 500

    basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {basic}"}
    data = {"code": code, "grant_type": "authorization_code", "redirect_uri": redirect_uri}

    r = requests.post(OAUTH_TOKEN_URL, headers=headers, data=data, timeout=60)
    try:
        j = r.json()
    except Exception:
        j = {"raw": r.text}

    if not r.ok:
        return jsonify({"ok": False, "message": "Gagal tukar code ke token", "response": j}), r.status_code

    expires_in = int(j.get("expires_in") or 3600)
    exp = dt.datetime.now() + dt.timedelta(seconds=expires_in)

    tokens = load_tokens()
    tokens.update(
        {
            "access_token": j.get("access_token"),
            "refresh_token": j.get("refresh_token"),
            "scope": j.get("scope"),
            "token_type": j.get("token_type"),
            "expires_at": exp.isoformat(),
            "updated_at": dt.datetime.now().isoformat(),
        }
    )
    save_tokens(tokens)

    return """
    <script>
      window.location.href = "/";
    </script>
    """


# =========================
# Routes: db list & open db
# =========================
@app.get("/api/db-list")
def api_db_list():
    tokens = refresh_access_token_if_needed()
    access_token = (tokens.get("access_token") or "").strip()
    if not access_token:
        return jsonify({"ok": False, "message": "Belum connect OAuth. Klik Connect Accurate dulu."}), 401

    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(ACCOUNT_DB_LIST_URL, headers=headers, timeout=60)

    try:
        j = r.json()
    except Exception:
        j = {"raw": r.text}

    if not r.ok:
        return jsonify({"ok": False, "message": "db-list gagal", "status": r.status_code, "response": j}), r.status_code

    return jsonify({"ok": True, "response": j})


@app.post("/api/open-db")
def api_open_db():
    body = request.get_json(silent=True) or {}
    db_id = str(body.get("id") or "").strip()
    db_alias = str(body.get("alias") or "").strip()

    tokens = refresh_access_token_if_needed()
    access_token = (tokens.get("access_token") or "").strip()
    if not access_token:
        return jsonify({"ok": False, "message": "Belum connect OAuth."}), 401
    if not db_id:
        return jsonify({"ok": False, "message": "db id kosong."}), 400

    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(ACCOUNT_OPEN_DB_URL, headers=headers, params={"id": db_id}, timeout=60)

    try:
        j = r.json()
    except Exception:
        j = {"raw": r.text}

    if not r.ok:
        return jsonify({"ok": False, "message": "open-db gagal", "status": r.status_code, "response": j}), r.status_code

    tokens.update(
        {
            "db_id": db_id,
            "db_alias": db_alias or tokens.get("db_alias"),
            "host": j.get("host"),
            "x_session_id": j.get("session"),
            "updated_at": dt.datetime.now().isoformat(),
        }
    )
    save_tokens(tokens)

    return jsonify({"ok": True, "response": j})


# =========================
# Template download
# =========================
@app.get("/api/template")
def api_template():
    sample_row_1 = {col: "" for col in PI_TEMPLATE_COLUMNS}
    sample_row_1.update({
        "SEQ": "1",
        "NUMBER": "PI-31032026-001",
        "VENDORNO": "VEND-001",
        "BILLNUMBER": "BILL-001",
        "TRANSDATE": "31/03/2026",
        "DESCRIPTION": "Pembelian sample",
        "CURRENCYCODE": "IDR",
        "RATE": "1",
        "PAYMENTTERMNAME": "COD",
        "SHIPDATE": "31/03/2026",
        "TAXABLE": "true",
        "INCLUSIVETAX": "false",
        "DOCUMENTCODE": "INVOICE",
        "VENDORTAXTYPE": "PRLHNDLMNEGERI_BKN_PPN",
        "ITEMNO": "ITEM-001",
        "UNITPRICE": "100000",
        "QTY": "2",
        "DETAILNAME": "Barang sample A",
        "ITEMUNITNAME": "PCS",
        "WAREHOUSENAME": "UTAMA",
        "USETAX1": "true",
    })

    sample_row_2 = sample_row_1.copy()
    sample_row_2.update({
        "SEQ": "2",
        "ITEMNO": "ITEM-002",
        "DETAILNAME": "Barang sample B",
        "UNITPRICE": "50000",
        "QTY": "1",
    })

    csv_lines = []
    csv_lines.append(",".join(PI_TEMPLATE_COLUMNS))

    for row in [sample_row_1, sample_row_2]:
        vals = []
        for col in PI_TEMPLATE_COLUMNS:
            val = str(row.get(col, ""))
            if "," in val or '"' in val or "\n" in val:
                val = '"' + val.replace('"', '""') + '"'
            vals.append(val)
        csv_lines.append(",".join(vals))

    csv = "\n".join(csv_lines)

    return app.response_class(
        csv,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=template-purchase-invoice.csv"},
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "3000"))
    app.run(host="0.0.0.0", port=port, debug=False)
