"""Independent out-of-generator CHALLENGE benchmark (Regime C): hand-authored frames and hand-written lexicons.

This module does NOT import data2's lexicons, cue banks or key grammar (only the ``Example2`` dataclass). Frames,
field names, names, handles and negative vocabulary were written separately, deliberately mimicking HTTP-extracted
field shapes (``json_body.*``, ``query_parameter.*``, ``form.*``, ``header.*``, ``body.text``). It is still SYNTHETIC
and written by the same engineer/tool as the rest of the ML workstream: this is **out-of-generator synthetic
validation, not real-world validation**.

The generated file ``datasets/challenge_v1.jsonl.gz`` is the frozen artifact (sha256 in its manifest); this module is
its provenance. The challenge set must never be used for model selection or tuning.

Annotation conventions (identical to the training data): one span per person name incl. middle initial and
``Last, First``; honorifics (Mr., Dr.) and ``@`` excluded; e-mail addresses, IDs, hashes, hostnames are NOT entities;
a username is a human-chosen account handle (not a numeric/hash id); organisations, places, products, files and job
titles (even when they look like names) are NOT entities.
"""
from __future__ import annotations

import random
import re
from typing import Sequence

from .data2 import Example2
from .spans import spans_to_tags, tokenize

SEED = 90210

FIRST = ("Aaliyah Abdul Adriana Akira Alejandro Amélie Anders Anil Beatriz Bogdan Brianna Callum Camille Carlos Chidi "
         "Dagmar Dariusz Deepa Dimitri Eamon Elif Emeka Esperanza Farid Fiona Gabriela Gianluca Giorgos Hanna Haruto Hassan "
         "Ingrid Iman Ivana Jamal Jerome Joaquín Kasper Katarzyna Kwame Lakshmi Lars Leila Lucas Lucía Mateus Mei-Ling "
         "Mikhail Minh Naledi Nadia Niamh Olu Pablo Priyanka Rafael Rania Rosalind Ruben Saoirse Sebastián Siddharth "
         "Sofía Soo-jin Tariq Thandi Tomasz Ulrich Valentina Vikram Wojciech Xavier Yasmin Yuki Zainab Zeynep Bríd "
         "Cormac Delphine Evander Freya Gustavo Henrik Isidora Jovan Klaus Linnea Matilda Nikolai Ottilie Paloma Quentin "
         "Rohan Simone Teodor Ursula Viktor Wilhelmina Yusuf Zoé Amara Bashir Cyrus Dalia Ezekiel Flora Ghada "
         "Hiroshi Ilse Jun Kofi Leandro Marisol Noor Odalys Percy Radhika Stellan Tove Uma Vaclav Willem").split()
LAST = ("Abara Alvarenga Andersson Bakker Bellamy Bianchi Boateng Brennan Castellanos Chaudhry Cohen Dabrowski Delacroix "
        "Demir Dlamini Eriksen Fernandes Fitzgerald Fofanah Gallagher Gruber Haidari Halloran Hashimoto Hoffmann Ibrahim "
        "Iyer Jankowski Jovanovic Kaczmarek Kamara Kowalczyk Laurent Lindgren Lopes Macdonald Mahlangu Marchetti Mbeki "
        "Moreau Murphy Nakamura Nikolaidis Novak Obuya Ogunleye Okonkwo O'Neil Pereira Petrov Quispe Rahman Reyes Rossi "
        "Sandoval Schmid Sengupta Silvestri Sokolov Stoica Takahashi Tavares Thorsen Torres Uchenna Valdez Varga "
        "Vasquez Villanueva Wagner Weiss Wojcik Yamamoto Yilmaz Zielinski Zhao Zimmermann "
        "Abernathy Blackwood Calloway Dunmore Ellsworth Fairchild Grantham Hollis Ingram Jessup Kingsley Lockhart "
        "Merriweather Northcott Ormsby Pemberton Quayle Rutherford Sinclair Thackeray Underhill Vandermolen Whitlock").split() \
    + ["van der Meer", "de la Cruz", "Al-Sayed", "Mac Giolla", "von Reuter", "Ben-David"]
FIRST_NL = ["Анастасия", "Игорь", "Ольга", "Дмитрий",
            "Δημήτρης", "Ελένη", "美咲", "健太", "沙织", "ガクト",
            "지우", "민준", "يوسف", "فاطمة", "יעל", "नेहा"]
LAST_NL = ["Петрова", "Смирнов", "Кузнецов", "Παπαδόπουλος",
           "田中", "鈴木", "王", "李", "김", "박", "العلي", "כהן", "शर्मा"]
HANDLE_WORDS = "pixel wrangler cinder harbor lantern maple quartz ember vortex tundra cobalt saffron nimbus orbit kestrel marlin \
fennel gadget byte kernel pepper biscuit noodle thunder velvet willow zephyr atlas drift echo falcon glacier".split()
HANDLE_FIXED = ["night_owl_77", "TheRealDave", "sunny-side-up", "xX_slayer_Xx", "coffee4ever", "j0hnny5", "ana_lucia_dev", "bytewrangler",
                "pixelpusher", "grumpycat99", "lena.k", "ops-admin2", "mr_robot_42", "taco_tuesday", "skywalker88", "quietstorm", "dev.null",
                "r3dacted", "bluejay_2020", "the_whisperer", "hackerman1337", "codemonkey", "ladybug_77", "zed-zed-top", "oldschool.rob",
                "nina_codes", "kgb_agent007", "midnight.rider", "tinyturtle", "fluffybunny_x", "alpha-wolf", "gr8scott"]
CITY = ("Springfield Fairview Georgetown Riverton Lakeside Ashford Brookfield Cedarville Dunmore Eastport Glenwood Harborview "
        "Kingsbridge Maplewood Northfield Oakridge Pinehurst Queensbury Rosewood Stonebridge Thornton Westbrook Yorkville "
        "Lyon Porto Gdansk Leeds Tampere Graz Lausanne Malmo Bergen Aarhus Cork Ghent Utrecht Salzburg Nagoya Daegu Pune "
        "Mombasa Kumasi Accra Tunis Rabat Cusco Bogotá Medellín Valparaíso Montevideo Wellington Hobart").split()
CITY_PERSON = "Jackson Lincoln Madison Austin Charlotte Chelsea Victoria Florence Brooklyn Savannah Orlando Jordan Sydney Devon Georgia Clayton Dallas".split()
ORG = ["Northwind Traders", "Globex Corporation", "Initech Solutions", "Harborview Dental", "Blue Heron Logistics", "Summit Ridge Capital",
       "Pioneer Freight", "Lumen Analytics", "Ironwood Builders", "Redwood Credit Union", "Copperline Energy", "Silverleaf Pharmacy",
       "Atlas Cargo", "Meridian Health", "Brightpath Academy", "Kestrel Aerospace", "Oakmont Insurance", "Delta Fabrication", "Tidewater Marine",
       "Evergreen Foods", "Quarry Lane Books", "Falcon Security Ltd", "Orchard & Vine", "Sable Media Group", "Nimbus Cloud GmbH"]
ORG_PERSON = ["Johnson & Johnson", "Ernst & Young", "Smith & Nephew", "Morgan Stanley", "Wells Fargo", "Johnson Controls", "Marsh McLennan",
              "Williams Sonoma", "Harper Collins", "Thompson Reuters", "Anderson Consulting", "Baker McKenzie", "Taylor Wimpey", "Clark & Sons",
              "Martin Brothers Plumbing", "Davis Polk", "Roberts Dairy", "Miller Lumber", "Wilson Sporting Goods", "Evans Cycles"]
PROD = ["AirLoom Mini", "Nimbus 2000", "ThinkSpot X1", "Quartz Pro 14", "Ember Smart Mug", "Lantern Go", "Pixel Frame 8", "Kestrel Drone S2",
        "Orbit Buds Air", "Vortex Blender 900", "Atlas Backpack 30L", "HomeHub Max", "FitBand Lite", "SoundBar 5.1", "Cobalt Router AX6",
        "Zephyr Fan Tower", "Nova Kettle", "Pebble Lamp", "Drift Skateboard", "Saffron Spice Set"]
FILE = ["quarterly_report_final.pdf", "invoice-2231.xlsx", "IMG_20240315_0912.jpg", "backup_2024-05-01.tar.gz", "notes (1).txt", "resume_v3.docx",
        "budget.csv", "logo@2x.png", "screenshot 2024-03-22.png", "deploy.sh", "README.md", "config.production.yaml", "data_export_final_FINAL.zip",
        "meeting-minutes.pdf", "slides_v2.pptx", "id_rsa.pub"]
JOB = ["Senior Software Engineer", "Account Manager", "Chief Financial Officer", "Registered Nurse", "Operations Lead", "Customer Success Manager",
       "Warehouse Supervisor", "Data Analyst", "Head of Marketing", "Site Reliability Engineer", "Legal Counsel", "Product Owner", "Office Manager"]
WORD = "invoice report summary meeting budget roadmap checkout payment shipping returns archive weekly urgent draft pending".split()
HOST = ["db-prod-01", "api.internal.example.com", "web-eu-3", "gateway.staging.test", "cache02", "mail.example.org", "k8s-node-17", "ci-runner-4"]
UA = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
      "curl/8.4.0", "python-requests/2.31.0", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
      "PostmanRuntime/7.36.0", "okhttp/4.12.0"]
EMAIL_DOMAINS = ["example.com", "mail.test", "corp.example.org", "inbox.example.net"]

# (source, location, text, copies). Slots: {N} {N2} {N3} person full; {FN}{FN2} first; {LN}{LN2} last; {H}{H2} handle;
# modifiers: {N:rev} "Last, First"  {N:ini} "F. Last"  {N:mid} "First M. Last"  {N:plus} "First+Last"  {N:pct} "First%20Last"
# {N:up} {N:low} {H:up}; negatives: CITY CITYP ORG ORGP PROD FILE JOB WORD HOST UA EMAIL IP DATE TIME NUM ID UUID HEX B64 SLUG TOKEN
SPECS: list[tuple[str, str, str, int]] = [
    # ---- nested JSON (names)
    ("json_nested", "json_body.data.attributes.recipient_full_name", "{N}", 6), ("json_nested", "json_body.order.shipping_address.contact", "{N}", 6),
    ("json_nested", "json_body.customer.profile.display", "{N}", 5), ("json_nested", "json_body.invoice.billed_to", "{N}", 5),
    ("json_nested", "json_body.invoice.billed_to", "{ORG}", 5), ("json_nested", "json_body.invoice.billed_to", "{ORGP}", 5),
    ("json_nested", "json_body.users[0].first", "{FN}", 5), ("json_nested", "json_body.users[0].last", "{LN}", 5),
    ("json_nested", "json_body.members[3].display_name", "{N}", 5), ("json_nested", "json_body.passenger.names[0]", "{N}", 5),
    ("json_nested", "json_body.guest", "{N}", 5), ("json_nested", "json_body.attendee_list[2]", "{N}", 5),
    ("json_nested", "json_body.commit.author.name", "{N}", 6), ("json_nested", "json_body.meta.requested_by", "{N}", 4),
    ("json_nested", "json_body.meta.requested_by", "{H}", 4), ("json_nested", "json_body.patient.emergency_contact.full_name", "{N:rev}", 5),
    ("json_nested", "json_body.acct_holder", "{N:up}", 4), ("json_nested", "json_body.borrower.nm", "{N:mid}", 4),
    ("json_nested", "json_body.signatories[1].name", "{N:ini}", 4), ("json_nested", "json_body.review.reviewer", "{N}", 4),
    ("json_nested", "json_body.ticket.requester.name", "{N:low}", 3), ("json_nested", "json_body.sender", "{N}", 4),
    # ---- nested JSON (handles)
    ("json_nested", "json_body.commit.committer.login", "{H}", 6), ("json_nested", "json_body.issue.assignees[0].login", "{H}", 6),
    ("json_nested", "json_body.users[1].screen", "{H}", 5), ("json_nested", "json_body.audit.actor", "{H}", 6),
    ("json_nested", "json_body.repository.full_name", "{H}/{SLUG}", 5), ("json_nested", "json_body.player.tag", "{H}", 5),
    ("json_nested", "json_body.auth.principal", "{H}", 5), ("json_nested", "json_body.profile.nick", "{H}", 5),
    ("json_nested", "json_body.followers[7].username", "{H:low}", 4), ("json_nested", "json_body.owner.uname", "{H}", 4),
    ("json_nested", "json_body.created_by", "{H}", 4), ("json_nested", "json_body.display_name", "{H}", 3), ("json_nested", "json_body.display_name", "{N}", 3),
    # ---- nested JSON (negatives)
    ("json_neg", "json_body.company.name", "{ORG}", 5), ("json_neg", "json_body.venue.name", "{PROD}", 4), ("json_neg", "json_body.employee.title", "{JOB}", 4),
    ("json_neg", "json_body.shipment.city", "{CITY}", 4), ("json_neg", "json_body.geo.place", "{CITYP}", 6), ("json_neg", "json_body.account.owner", "{ORGP}", 6),
    ("json_neg", "json_body.customer.company", "{ORGP}", 5), ("json_neg", "json_body.product.name", "{PROD}", 5), ("json_neg", "json_body.file.original_name", "{FILE}", 5),
    ("json_neg", "json_body.device.hostname", "{HOST}", 3), ("json_neg", "json_body.token.sub", "{UUID}", 3), ("json_neg", "json_body.session.user_id", "{ID}", 4),
    ("json_neg", "json_body.user.email", "{EMAIL}", 4), ("json_neg", "json_body.name", "{PROD}", 3), ("json_neg", "json_body.name", "{ORG}", 3),
    ("json_neg", "json_body.team_name", "{ORGP}", 3), ("json_neg", "json_body.dept", "{JOB}", 3), ("json_neg", "json_body.location", "{CITYP}", 4),
    ("json_neg", "json_body.sku", "{HEX}", 3), ("json_neg", "json_body.assignee_group", "{ORG}", 3), ("json_neg", "json_body.label", "{WORD}", 3),
    # ---- query parameters
    ("query", "query_parameter.q", "{N}", 5), ("query", "query_parameter.q", "{CITY}", 4), ("query", "query_parameter.q", "{PROD}", 4),
    ("query", "query_parameter.user", "{H}", 6), ("query", "query_parameter.u", "{H}", 5), ("query", "query_parameter.name", "{N}", 5),
    ("query", "query_parameter.name", "{PROD}", 4), ("query", "query_parameter.owner", "{H}", 4), ("query", "query_parameter.fn", "{FN}", 4),
    ("query", "query_parameter.ln", "{LN}", 4), ("query", "query_parameter.redirect", "/users/{H}/home", 5), ("query", "query_parameter.ref", "{UUID}", 3),
    ("query", "query_parameter.who", "{N}", 4), ("query", "query_parameter.by", "{H}", 4), ("query", "query_parameter.sort", "name_asc", 2),
    ("query", "query_parameter.customer", "{N:rev}", 4), ("query", "query_parameter.city", "{CITYP}", 4), ("query", "query_parameter.token", "{TOKEN}", 3),
    # ---- forms
    ("form", "form.fullname", "{N}", 5), ("form", "form.cardholder_name", "{N:up}", 5), ("form", "form.shipping_name", "{N}", 4), ("form", "form.nickname", "{H}", 5),
    ("form", "form.account", "{H}", 4), ("form", "form.company", "{ORG}", 4), ("form", "form.referrer", "{N}", 4), ("form", "form.login", "{H}", 5),
    ("form", "form.first_name", "{FN}", 4), ("form", "form.surname", "{LN}", 4), ("form", "form.signature", "{N}", 4), ("form", "form.signature", "{ORG}", 3),
    ("form", "form.employer", "{ORGP}", 4), ("form", "form.nick", "{H:up}", 3),
    # ---- headers
    ("header", "header.x-forwarded-user", "{H}", 5), ("header", "header.from", "{N} <{EMAIL}>", 6), ("header", "header.from", "<{EMAIL}>", 3),
    ("header", "header.x-api-user", "{H}", 4), ("header", "header.referer", "https://{HOST}/people/{H}", 5), ("header", "header.x-device-owner", "{N}", 4),
    ("header", "header.user-agent", "{UA}", 3), ("header", "header.cookie", "theme=dark; uname={H}; sid={HEX}", 5), ("header", "header.cookie", "session={HEX}; locale=en_GB", 3),
    ("header", "header.set-cookie", "last_user={H}; Max-Age=86400; Path=/", 4), ("header", "header.referer", "https://{HOST}/search?q={N:pct}", 4),
    ("header", "header.referer", "https://{HOST}/catalog/{SLUG}", 3), ("header", "header.x-request-id", "{UUID}", 2), ("header", "header.host", "{HOST}", 2),
    ("header", "header.to", "\"{N}\" <{EMAIL}>", 4), ("header", "header.x-company", "{ORGP}", 3),
    # ---- free text bodies (narratives)
    ("narrative", "body.text", "Per my conversation with {N}, we agreed to move the deadline.", 5), ("narrative", "body.text", "Thanks for the quick turnaround, {FN}.", 5),
    ("narrative", "body.text", "{N} from {ORG} will join the call.", 5), ("narrative", "body.text", "Can you forward this to {N}?", 5),
    ("narrative", "body.text", "FYI @{H}", 4), ("narrative", "body.text", "Warm wishes,\n{N}", 5), ("narrative", "body.text", "Please address the letter to {N}, {JOB}.", 4),
    ("narrative", "body.text", "Mum and {FN} are coming on {DATE}.", 4), ("narrative", "body.text", "{FN} said {FN2} would be late.", 4),
    ("narrative", "body.text", "Interview panel: {N}, {N2}, {N3}.", 4), ("narrative", "body.text", "Condolences to the {LN} family.", 4),
    ("narrative", "body.text", "Welcome aboard, {FN}! Your laptop is ready.", 4), 
    ("narrative", "form.comment", "My neighbour {N} keeps parking in my spot. Tell {FN} to stop.", 4), ("narrative", "form.comment", "Delivered to the front desk. Signed for by {N}.", 4),
    ("narrative", "json_body.notes", "Called {N} twice, no answer; will try {FN2} tomorrow.", 4), ("narrative", "json_body.message", "{H} replied to {H2}: sounds good", 5),
    ("narrative", "json_body.message", "{N} ({H}) has joined the workspace", 5), ("narrative", "json_body.message", "Transfer from {N} to {N2}: {NUM} credits", 4),
    ("narrative", "json_body.comment", "Dr. {LN} will see you at {TIME}.", 4), ("narrative", "json_body.comment", "Attention Mr. {LN}: your parcel arrived.", 4),
    ("narrative", "json_body.feedback", "The driver, {FN}, was extremely helpful.", 4), ("narrative", "json_body.reason", "Requested by {N} on behalf of {ORG}", 4),
    ("narrative", "body.text", "Your reservation at {ORG} is confirmed for {DATE}.", 4), ("narrative", "body.text", "Greetings from {CITY}!", 3),
    ("narrative", "body.text", "Welcome to {ORG}", 3), ("narrative", "body.text", "Dear Valued Customer,", 2), ("narrative", "body.text", "Hi there,\n\nThanks for reaching out.", 2),
    ("narrative", "body.text", "Best regards,\nThe {ORG} Team", 4), ("narrative", "body.text", "Regards,\nCustomer Care", 2), 
    ("narrative", "body.text", "Thank you for shopping at {ORGP}.", 5), ("narrative", "body.text", "Order {HEX} dispatched from {CITY}.", 4),
    ("narrative", "json_body.title", "{PROD} review: worth it?", 4), ("narrative", "json_body.title", "Meeting with {ORG} about {WORD}", 4),
    # ---- chats / email / vcs / sql / csv / yaml / xml
    ("chat", "body.text", "[{TIME}] <{H}> anyone around?", 5), ("chat", "body.text", "<@{H}> are you free for a quick call?", 5),
    ("chat", "body.text", "{H}: lol ok", 4), ("chat", "body.text", "* {H} has quit (Ping timeout)", 4), ("chat", "body.text", "{N} is typing...", 3),
    ("email", "body.text", "Subject: Re: invoice\nFrom: {N} <{EMAIL}>\n\nHi {FN2}, see attached.", 5), ("email", "body.text", "To: {N}; {N2}\ncc: {ORG} Billing", 4),
    ("email", "body.text", "On {DATE}, {N} wrote:\n> please confirm", 4), ("email", "body.text", "Signed-off-by: {N} <{EMAIL}>", 4),
    ("vcs", "body.text", "commit {HEX}\nAuthor: {N} <{EMAIL}>\nDate:   {DATE}", 5), ("vcs", "body.text", "Merge pull request #{NUM} from {H}/{SLUG}", 5),
    ("sql", "json_body.query", "SELECT * FROM users WHERE username = '{H}'", 5), ("sql", "json_body.query", "UPDATE accounts SET owner = '{N}' WHERE id = {NUM}", 4),
    ("sql", "json_body.query", "SELECT city FROM offices WHERE name = '{CITY}'", 3),
    ("csv", "body.text", "id,name,city\n{NUM},{N},{CITY}", 5), ("csv", "body.text", "{NUM};{N:rev};{DATE}", 4), ("csv", "body.text", "user,role\n{H},admin\n{H2},viewer", 4),
    ("yaml", "body.text", "owner: {N}\nteam: {ORG}\nlead: {H}", 5), ("yaml", "body.text", "name: {PROD}\nversion: 1.{NUM}", 3),
    ("xml", "body.text", "<contact><name>{N}</name><city>{CITY}</city></contact>", 5), ("xml", "body.text", "<author>{H}</author>", 4),
    ("xml", "body.text", "<item><title>{PROD}</title></item>", 3),
    # ---- logs
    ("log", "body.text", "{IP} - {H} [{DATE}:{TIME}:00 +0000] \"GET /index.html HTTP/1.1\" 200 512", 6), ("log", "body.text", "{IP} - - [{DATE}:{TIME}:00 +0000] \"GET /health HTTP/1.1\" 200 2", 3),
    ("log", "body.text", "connection authorized: user={H} database=app", 5), ("log", "body.text", " {H} : TTY=pts/1 ; PWD=/home/{H} ; USER=root ; COMMAND=/bin/ls", 5),
    ("log", "body.text", "Accepted password for {H} from {IP} port 52814 ssh2", 4), ("log", "body.text", "audit: user \"{H}\" attempted action=delete", 4),
    ("log", "body.text", "{DATE} {TIME} WARN login throttled for {H} (attempt 4/5)", 5), ("log", "body.text", "MAIL FROM:<{EMAIL}>", 3),
    ("log", "body.text", "{DATE} {TIME} INFO job {UUID} finished in {NUM}ms", 3), ("log", "body.text", "Failed to load {FILE}: no such file", 3),
    # ---- multi-field-ish / odd
    ("short", "json_body.c", "{N}", 4), ("short", "form.n", "{N:ini}", 4), ("short", "query_parameter.p", "{FN}", 3),
]
_SLOT = re.compile(r"\{(\w+)(?::(\w+))?\}")
_LAT = re.compile(r"^[A-Za-zÀ-ɏ'\-]+$")


def _person_parts(rng, nonlatin_ok=True):
    if nonlatin_ok and rng.random() < .09:
        return rng.choice(FIRST_NL), rng.choice(LAST_NL)
    return rng.choice(FIRST), rng.choice(LAST)


def _handle(rng, f, l):
    pat = rng.randint(0, 8)
    f2, l2 = f.lower().replace("'", ""), l.lower().replace("'", "").replace(" ", "")
    if not (_LAT.match(f) and _LAT.match(l.replace(" ", ""))) or pat == 8:
        return rng.choice(HANDLE_FIXED)
    yy = str(rng.choice([77, 85, 92, 99, 2001, 2015, 21, 8]))
    return [f"{f}{l.replace(' ', '')}", f"{l2}_{f2[0]}", f"{f2[0]}{l2}{yy}", f"{f2}.{l2[0]}", f"{rng.choice(HANDLE_WORDS)}{rng.choice(HANDLE_WORDS).capitalize()}{yy}",
            f"the{rng.choice(HANDLE_WORDS)}", f"{rng.choice(HANDLE_WORDS)}_{rng.choice(HANDLE_WORDS)}42", f"{f2}{l2[:2]}".replace("e", "3") if rng.random() < .5 else f"{f2}-{yy}"][pat if pat < 8 else 0]


def _fill(spec_text: str, rng) -> tuple[str, list[tuple[int, int, str]]]:
    people: dict[str, tuple[str, str]] = {}
    out, spans, pos, last = [], [], 0, 0

    def person(key):
        if key not in people:
            people[key] = _person_parts(rng)
        return people[key]

    for m in _SLOT.finditer(spec_text):
        lit = spec_text[last:m.start()]; out.append(lit); pos += len(lit)
        name, mod = m.group(1), m.group(2)
        label = None
        if name in ("N", "N2", "N3", "FN", "FN2", "LN", "LN2"):
            f, l = person(name[-1] if name[-1].isdigit() else "1")
            cjk = bool(re.search(r"[぀-ヿ㐀-鿿가-힯]", f + l))
            if name.startswith("FN"): v = f
            elif name.startswith("LN"): v = l
            else:
                v = {None: f"{f} {l}", "rev": f"{l}, {f}", "ini": f"{f[0]}. {l}", "mid": f"{f} {rng.choice('ABCDEGHJKLMNPRSTW')}. {l}",
                     "plus": f"{f}+{l}", "pct": f"{f}%20{l}", "up": f"{f} {l}".upper(), "low": f"{f} {l}".lower()}[mod]
                if cjk and mod is None: v = l + f
            label = "PERSON_NAME"
        elif name in ("H", "H2"):
            f, l = person(name[-1] if name[-1].isdigit() else "1")
            v = _handle(rng, f, l)
            if mod == "up": v = v.upper()
            elif mod == "low": v = v.lower()
            label = "USERNAME"
        else:
            v = {"CITY": lambda: rng.choice(CITY), "CITYP": lambda: rng.choice(CITY_PERSON), "ORG": lambda: rng.choice(ORG),
                 "ORGP": lambda: rng.choice(ORG_PERSON), "PROD": lambda: rng.choice(PROD), "FILE": lambda: rng.choice(FILE),
                 "JOB": lambda: rng.choice(JOB), "WORD": lambda: rng.choice(WORD), "HOST": lambda: rng.choice(HOST),
                 "UA": lambda: rng.choice(UA), "IP": lambda: ".".join(str(rng.randint(1, 254)) for _ in range(4)),
                 "DATE": lambda: f"{rng.randint(2020, 2026)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
                 "TIME": lambda: f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}", "NUM": lambda: str(rng.randint(10, 99999)),
                 "ID": lambda: str(rng.randint(10 ** 5, 10 ** 9)), "HEX": lambda: "".join(rng.choice("0123456789abcdef") for _ in range(rng.choice((7, 12, 20)))),
                 "UUID": lambda: "-".join("".join(rng.choice("0123456789abcdef") for _ in range(n)) for n in (8, 4, 4, 4, 12)),
                 "B64": lambda: "dXNlcjpwYXNz", "SLUG": lambda: f"{rng.choice(WORD)}-{rng.choice(HANDLE_WORDS)}-{rng.randint(1, 99)}",
                 "TOKEN": lambda: "".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789") for _ in range(24)),
                 "EMAIL": lambda: f"{rng.choice(HANDLE_WORDS)}.{rng.choice(HANDLE_WORDS)}@{rng.choice(EMAIL_DOMAINS)}"}[name]()
        if label:
            spans.append((pos, pos + len(v), label))
        out.append(v); pos += len(v); last = m.end()
    out.append(spec_text[last:])
    return "".join(out), spans


def generate(seed: int = SEED) -> list[Example2]:
    rng = random.Random(seed)
    items, seen = [], set()
    for src, loc, tpl, n in SPECS:
        for _ in range(-(-n * 7 // 5)):
            for _try in range(50):
                text, spans = _fill(tpl, rng)
                if (loc, text) not in seen:
                    break
            else:
                continue  # fixed-text spec exhausted its variants: keep the benchmark duplicate-free
            seen.add((loc, text))
            tags = []
            if not spans: tags.append("no_entity")
            if not spans and src in ("json_neg", "narrative", "query", "form", "header", "short") and re.search(r"[A-Z]", text): tags.append("hard_negative")
            if len(spans) >= 2: tags.append("multi_entity")
            if any(not text[s:e].isascii() for s, e, _ in spans): tags.append("unicode")
            items.append((src, loc, tpl, text, spans, tags))
    # a few truncated / fragmented fields (cut after generation; spans clipped)
    out = []
    for i, (src, loc, tpl, text, spans, tags) in enumerate(items):
        if i % 37 == 0 and len(text) > 12:
            cut = rng.randint(6, len(text) - 1)
            text = text[:cut]; spans = [(s, min(e, cut), l) for s, e, l in spans if s < cut]; tags = tags + ["truncated"]
        spans_to_tags(tokenize(text), spans)  # strict alignment
        out.append(Example2(f"chal-{len(out):05d}", "challenge", src, tpl, loc, text, tuple(sorted(spans)), tuple(sorted(set(tags)))))
    return out
