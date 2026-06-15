# ACA-AOL Purchase Invoice + Admin Panel

Admin panel:

```text
/admin
```

Set Railway Variables:

```env
ADMIN_EMAIL=admin@aca-aol.id
ADMIN_PASSWORD=password_admin_yang_aman
```

Fitur admin:
- tambah customer baru
- generate password SHA256 otomatis
- edit nama PT, expired, max database, password
- suspend/aktifkan customer
- reset database terdaftar

Customer login tetap lewat halaman utama `/`.
