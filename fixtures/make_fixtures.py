#!/usr/bin/env python3
"""Synthetic bank-statement fixtures for the BB Money import engine.

These are NOT real Commercial Bank statements. They are hand-built PDFs shaped like
one, so the parser can be proven against a clean month, a password-protected file, a
scanned page, a malformed table and a duplicate-heavy month before any real statement
exists. A profile is only ever called SUPPORTED after a real sample parses.

PDFs are written by hand rather than with a library because none is installed, and
because hand-writing gives exact control of text coordinates, which is the thing the
row reconstruction actually depends on.

The locked fixture implements the PDF standard security handler, revision 2, RC4
40-bit. A password path that has never opened an encrypted file is not tested.
"""
import hashlib, os, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
PAD = bytes([
    0x28,0xBF,0x4E,0x5E,0x4E,0x75,0x8A,0x41,0x64,0x00,0x4E,0x56,0xFF,0xFA,0x01,0x08,
    0x2E,0x2E,0x00,0xB6,0xD0,0x68,0x3E,0x80,0x2F,0x0C,0xA9,0xFE,0x64,0x53,0x69,0x7A])
FILE_ID = bytes.fromhex('bb0d1e2f3a4b5c6d7e8f90a1b2c3d4e5')

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out, i, j = bytearray(), 0, 0
    for ch in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

def pad_pw(pw):
    b = pw.encode('latin-1')[:32]
    return b + PAD[:32 - len(b)]

def compute_O(owner_pw, user_pw):
    h = hashlib.md5(pad_pw(owner_pw)).digest()
    return rc4(h[:5], pad_pw(user_pw))

def compute_key(user_pw, O, P):
    m = hashlib.md5()
    m.update(pad_pw(user_pw))
    m.update(O)
    m.update(P.to_bytes(4, 'little', signed=True))
    m.update(FILE_ID)
    return m.digest()[:5]

def compute_U(key):
    return rc4(key, PAD)

def obj_key(key, num, gen):
    m = hashlib.md5()
    m.update(key)
    m.update(num.to_bytes(3, 'little'))
    m.update(gen.to_bytes(2, 'little'))
    return m.digest()[:min(len(key) + 5, 16)]

# Helvetica widths, enough for right-aligning figures accurately
def text_w(s, size):
    total = 0
    for ch in s:
        if ch.isdigit(): total += 556
        elif ch in ',.': total += 278
        elif ch == ' ': total += 278
        elif ch == '-': total += 333
        elif ch.isupper(): total += 667
        else: total += 556
    return total * size / 1000.0

def esc(s):
    return s.replace('\\', r'\\').replace('(', r'\(').replace(')', r'\)')

class PDF:
    """Minimal writer: base-14 Helvetica text at exact coordinates, optional RC4."""
    def __init__(self, encrypt_user_pw=None):
        self.pages = []
        self.enc_pw = encrypt_user_pw

    def add_page(self, ops, image=None):
        self.pages.append({'ops': ops, 'image': image})

    def build(self):
        objs = {}          # num -> bytes (already serialised body)
        streams = {}       # num -> (dict_str, raw_bytes)
        n_pages = len(self.pages)
        # 1 catalog, 2 pages, 3 font, then per page: page obj + content (+ image)
        num = 4
        page_nums, content_nums, image_nums = [], [], []
        for p in self.pages:
            page_nums.append(num); num += 1
            content_nums.append(num); num += 1
            if p['image'] is not None:
                image_nums.append(num); num += 1
            else:
                image_nums.append(None)

        objs[1] = b'<< /Type /Catalog /Pages 2 0 R >>'
        kids = ' '.join(f'{n} 0 R' for n in page_nums)
        objs[2] = f'<< /Type /Pages /Count {n_pages} /Kids [{kids}] >>'.encode()
        objs[3] = b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'

        for i, p in enumerate(self.pages):
            res = '/Font << /F1 3 0 R >>'
            if image_nums[i]:
                res += f' /XObject << /Im0 {image_nums[i]} 0 R >>'
            objs[page_nums[i]] = (
                f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] '
                f'/Resources << {res} >> /Contents {content_nums[i]} 0 R >>').encode()
            streams[content_nums[i]] = ('<< /Length %d >>', p['ops'].encode('latin-1'))
            if image_nums[i]:
                w, h, raw = p['image']
                comp = zlib.compress(raw)
                streams[image_nums[i]] = (
                    '<< /Type /XObject /Subtype /Image /Width %d /Height %d '
                    '/ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode '
                    '/Length %%d >>' % (w, h), comp)

        enc_num = None
        key = None
        if self.enc_pw is not None:
            P = -1
            O = compute_O('bbmoney-owner', self.enc_pw)
            key = compute_key(self.enc_pw, O, P)
            U = compute_U(key)
            enc_num = num
            objs[enc_num] = (
                b'<< /Filter /Standard /V 1 /R 2 /Length 40 /P -1 /O <'
                + O.hex().encode() + b'> /U <' + U.hex().encode() + b'> >>')
            num += 1

        out = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
        offsets = {}
        for onum in sorted(set(list(objs.keys()) + list(streams.keys()))):
            offsets[onum] = len(out)
            out += f'{onum} 0 obj\n'.encode()
            if onum in streams:
                dict_tpl, raw = streams[onum]
                data = raw
                if key is not None and onum != enc_num:
                    data = rc4(obj_key(key, onum, 0), data)
                out += (dict_tpl % len(data)).encode() + b'\nstream\n' + data + b'\nendstream\n'
            else:
                body = objs[onum]
                out += body + b'\n'
            out += b'endobj\n'

        xref_at = len(out)
        maxn = max(offsets) + 1
        out += f'xref\n0 {maxn}\n'.encode()
        out += b'0000000000 65535 f \n'
        for i in range(1, maxn):
            if i in offsets:
                out += f'{offsets[i]:010d} 00000 n \n'.encode()
            else:
                out += b'0000000000 65535 f \n'
        trailer = f'<< /Size {maxn} /Root 1 0 R /ID [<{FILE_ID.hex()}> <{FILE_ID.hex()}>]'
        if enc_num:
            trailer += f' /Encrypt {enc_num} 0 R'
        trailer += ' >>'
        out += b'trailer\n' + trailer.encode() + b'\nstartxref\n' + str(xref_at).encode() + b'\n%%EOF\n'
        return bytes(out)

# ── layout, shaped like a Sri Lankan bank statement ───────────────────────
COLS = {'date': 42, 'desc': 108, 'wd_right': 400, 'dep_right': 478, 'bal_right': 556}
SIZE = 8.5

def T(x, y, s, size=SIZE, bold=False):
    return f'BT /F1 {size} Tf 1 0 0 1 {x:.2f} {y:.2f} Tm ({esc(s)}) Tj ET\n'

def TR(x_right, y, s, size=SIZE):
    return T(x_right - text_w(s, size), y, s, size)

def header(y, period, page_no=1, pages=1):
    o = ''
    o += T(42, y, 'COMMERCIAL BANK OF CEYLON PLC', 12)
    o += T(42, y - 15, 'Statement of Account', 10)
    o += T(42, y - 32, 'Account No: 8001234567890    Currency: LKR    Branch: Kollupitiya')
    o += T(42, y - 44, f'Statement Period: {period}')
    o += T(42, y - 56, f'Page {page_no} of {pages}')
    hy = y - 76
    o += T(COLS['date'], hy, 'Date', 8.5)
    o += T(COLS['desc'], hy, 'Description', 8.5)
    o += TR(COLS['wd_right'], hy, 'Withdrawals', 8.5)
    o += TR(COLS['dep_right'], hy, 'Deposits', 8.5)
    o += TR(COLS['bal_right'], hy, 'Balance', 8.5)
    return o, hy - 16

def money(v):
    return f'{v:,.2f}'

def rows_block(rows, y):
    """rows: (date, desc, withdrawal, deposit, balance, extra_desc_line)"""
    o = ''
    for (d, desc, wd, dep, bal, cont) in rows:
        if d: o += T(COLS['date'], y, d)
        o += T(COLS['desc'], y, desc)
        if wd is not None: o += TR(COLS['wd_right'], y, money(wd))
        if dep is not None: o += TR(COLS['dep_right'], y, money(dep))
        if bal is not None: o += TR(COLS['bal_right'], y, money(bal))
        y -= 13
        if cont:
            o += T(COLS['desc'] + 6, y, cont)
            y -= 13
    return o, y

def build_clean():
    bal = 285320.50
    raw = [
        ('01/07/2026','KEELLS SUPER LIBERTY PLZ COL03', 12450.00, None, None),
        ('02/07/2026','UBER *EATS PENDING COLOMBO', 2340.00, None, None),
        ('02/07/2026','PICKME*TRIP 884213', 860.00, None, None),
        ('03/07/2026','DIALOG AXIATA PLC BILL PAY', 1499.00, None, None),
        ('04/07/2026','CARGILLS FOOD CITY 112 BAM', 5600.00, None, None),
        ('05/07/2026','CEYPETCO FUEL STATION 0421', 9800.00, None, None),
        ('06/07/2026','SALARY CREDIT JULY', None, 450000.00, None),
        ('07/07/2026','FUND TRANSFER TO 8009988776', 60000.00, None, None),
        ('08/07/2026','DARAZ*ORDER 9912004', 4250.00, None, None),
        ('09/07/2026','KEELLS SUPER LIBERTY PLZ COL03', 7320.00, None, None),
        ('10/07/2026','SERVICE CHARGE MONTHLY', 350.00, None, None),
        ('11/07/2026','UBER *EATS PENDING COLOMBO', 3200.00, None, None),
        ('12/07/2026','PICKME FOOD ORDER 22119', 2750.00, None, None),
        ('13/07/2026','ATM WDL KOLLUPITIYA 0912', 20000.00, None, None),
        ('14/07/2026','KEELLS SUPER LIBERTY PLZ COL03', 9880.00, None, None),
        ('15/07/2026','REVERSAL DARAZ*ORDER 9912004', None, 4250.00, None),
        ('16/07/2026','ASIRI CENTRAL HOSPITAL', 8600.00, None, None),
        ('17/07/2026','KEELLS SUPER LIBERTY PLZ COL03', 6410.00, None, None),
        ('18/07/2026','LECO ELECTRICITY BILL', 7240.00, None, None),
        ('19/07/2026','UBER *EATS PENDING COLOMBO', 1980.00, None, None),
        ('20/07/2026','STAMP DUTY', 50.00, None, None),
        ('21/07/2026','SPAR SUPERMARKET RAJAGIRIYA', 4380.00, None, None),
        ('22/07/2026','KAPRUKA ONLINE ORDER', 3120.00, None, None),
        ('23/07/2026','NWSDB WATER BILL', 1860.00, None, None),
        ('24/07/2026','PICKME*TRIP 991020', 1240.00, None, None),
        ('25/07/2026','CEFT INWARD FROM 7712340', None, 25000.00, None),
        ('26/07/2026','KEELLS SUPER LIBERTY PLZ COL03', 11020.00, None, None),
        ('27/07/2026','MOBITEL POSTPAID BILL', 2450.00, None, None),
        ('28/07/2026','ODEL COLOMBO 07', 6890.00, None, None),
        ('29/07/2026','UBER *EATS PENDING COLOMBO', 2620.00, None, None),
    ]
    rows = []
    for (d, desc, wd, dep, _) in raw:
        bal = bal - (wd or 0) + (dep or 0)
        rows.append((d, desc, wd, dep, bal, None))
    p = PDF()
    ops, y = header(800, '01 Jul 2026 to 31 Jul 2026', 1, 2)
    first, y = rows_block(rows[:22], y)
    ops += first
    ops += T(COLS['desc'], y - 6, 'CARRIED FORWARD')
    ops += TR(COLS['bal_right'], y - 6, money(rows[21][4]))
    p.add_page(ops)
    ops2, y2 = header(800, '01 Jul 2026 to 31 Jul 2026', 2, 2)
    second, y2 = rows_block(rows[22:], y2)
    ops2 += second
    ops2 += T(COLS['desc'], y2 - 10, 'CLOSING BALANCE')
    ops2 += TR(COLS['bal_right'], y2 - 10, money(rows[-1][4]))
    p.add_page(ops2)
    return p.build()

def build_dupes():
    """A month whose lines deliberately collide with hand-typed entries."""
    bal = 120000.00
    raw = [
        ('03/08/2026','KEELLS SUPER LIBERTY PLZ COL03', 3480.25, None),   # exact manual match
        ('04/08/2026','UBER *EATS PENDING COLOMBO', 2340.00, None),       # manual, 1 day out
        ('05/08/2026','PICKME*TRIP 100221', 860.00, None),                # manual, same amount twice
        ('06/08/2026','PICKME*TRIP 100377', 860.00, None),
        ('07/08/2026','CARGILLS FOOD CITY 112 BAM', 5600.00, None),       # manual, 3 days out
        ('08/08/2026','DIALOG AXIATA PLC BILL PAY', 1499.00, None),
        ('09/08/2026','KEELLS SUPER LIBERTY PLZ COL03', 12450.00, None),
        ('10/08/2026','UBER *EATS PENDING COLOMBO', 3200.00, None),
        ('11/08/2026','SERVICE CHARGE MONTHLY', 350.00, None),
        ('12/08/2026','CEYPETCO FUEL STATION 0421', 9800.00, None),
    ]
    rows = []
    for (d, desc, wd, dep) in raw:
        bal = bal - (wd or 0) + (dep or 0)
        rows.append((d, desc, wd, dep, bal, None))
    p = PDF()
    ops, y = header(800, '01 Aug 2026 to 31 Aug 2026')
    block, y = rows_block(rows, y)
    p.add_page(ops + block)
    return p.build()

def build_malformed():
    """Everything a real statement does that a naive parser gets wrong."""
    p = PDF()
    ops, y = header(800, '01 Jun 2026 to 30 Jun 2026')
    rows = [
        ('01/06/2026','KEELLS SUPER LIBERTY PLZ COL03 PURCHASE MADE ON', 8420.00, None, 210000.00,
         'CARD ENDING 4412 REF 99120043'),                      # wrapped description
        ('2/6/2026','UBER *EATS PENDING', 1980.00, None, 208020.00, None),   # single digit date
        (None,'CONTINUATION OF PREVIOUS ENTRY', None, None, None, None),      # orphan line
        ('03/06/2026','PICKME*TRIP 55021 REF 4412', 640.00, None, None, None),# no balance
        ('04/06/2026','SOMETHING WITH 12,450.00 IN THE TEXT', 320.00, None, 207060.00, None),
        ('05/06/2026','CHEQUE DEPOSIT 004521', None, 15000.00, 222060.00, None),
        ('06/06/2026','', 500.00, None, 221560.00, None),                    # empty description
    ]
    block, y = rows_block(rows, y)
    ops += block
    ops += T(42, y - 20, 'COMMERCIAL BANK OF CEYLON PLC', 12)   # header repeated mid page
    ops += T(COLS['date'], y - 40, 'Date')
    ops += T(COLS['desc'], y - 40, 'Description')
    rows2 = [('07/06/2026','LECO ELECTRICITY BILL', 6240.00, None, 215320.00, None)]
    block2, _ = rows_block(rows2, y - 56)
    p.add_page(ops + block2)
    return p.build()

def build_scanned():
    """An image-only page. No text at all, so the app must say it needs OCR."""
    w, h = 120, 160
    raw = bytearray()
    for yy in range(h):
        for xx in range(w):
            raw.append(40 if (12 < yy < 22 and 10 < xx < 100) else 235)
    p = PDF()
    ops = f'q 500 0 0 660 48 120 cm /Im0 Do Q\n'
    p.add_page(ops, image=(w, h, bytes(raw)))
    return p.build()

def build_locked():
    """Same clean month, encrypted. Password is NIC-shaped, as emailed ones are."""
    bal = 95000.00
    raw = [
        ('01/05/2026','KEELLS SUPER LIBERTY PLZ COL03', 6240.00, None),
        ('02/05/2026','UBER *EATS PENDING COLOMBO', 1890.00, None),
        ('03/05/2026','DIALOG AXIATA PLC BILL PAY', 1499.00, None),
        ('04/05/2026','PICKME*TRIP 220114', 720.00, None),
        ('05/05/2026','SALARY CREDIT MAY', None, 450000.00),
    ]
    rows = []
    for (d, desc, wd, dep) in raw:
        bal = bal - (wd or 0) + (dep or 0)
        rows.append((d, desc, wd, dep, bal, None))
    p = PDF(encrypt_user_pw='941234567V')
    ops, y = header(800, '01 May 2026 to 31 May 2026')
    block, y = rows_block(rows, y)
    p.add_page(ops + block)
    return p.build()

def main():
    made = []
    for name, fn in [('cb-clean.pdf', build_clean), ('cb-dupes.pdf', build_dupes),
                     ('cb-malformed.pdf', build_malformed), ('cb-scanned.pdf', build_scanned),
                     ('cb-locked.pdf', build_locked)]:
        data = fn()
        path = os.path.join(HERE, name)
        open(path, 'wb').write(data)
        made.append((name, len(data)))
        print('%-18s %6d bytes' % (name, len(data)))
    print('\nwrote %d fixtures to %s' % (len(made), HERE))

main()
