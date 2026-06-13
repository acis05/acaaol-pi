# ACA-AOL Purchase Invoice

Importer Excel ke Accurate Online modul Purchase Invoice.

## Endpoint Accurate

`/api/purchase-invoice/bulk-save.do`

## Scope OAuth

`purchase_invoice_save`

## Railway Variables

```env
JWT_SECRET=change_me_min_32_characters_for_production
SECRET_KEY=change_me_min_32_characters_for_production
AO_CLIENT_ID=your_accurate_client_id
AO_CLIENT_SECRET=your_accurate_client_secret
AO_REDIRECT_URI=https://pi.aca-aol.id/oauth/callback
AO_SCOPE=purchase_invoice_save
AO_PI_SAVE_PATH=/api/purchase-invoice/bulk-save.do
```

## Local Run

```bash
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
python app.py
```

Buka http://127.0.0.1:3000

## Login Demo

- demo@aca-aol.id / 1234

## Excel

Download template dari tombol `Download Template` di aplikasi.

Konsep:
- `NUMBER` sama akan digabung menjadi 1 Purchase Invoice.
- 1 baris bisa berisi detail item, detail expense, dan/atau down payment.
- Minimal setiap invoice harus punya `VENDORNO`, `TRANSDATE`, dan minimal 1 baris detail item dengan `ITEMNO` + `UNITPRICE`.
