"""Realistic values chosen from a field's *name* when the schema alone says only "string"
or "number". Contact data is always fictional: example.* domains, 555 phone numbers,
RFC 5737 documentation IP ranges and public gateway test card numbers."""
from __future__ import annotations

import datetime as dt
import re
import string
import uuid
from typing import Any, Callable, List, Optional, Tuple

DOMAINS = ["example.com", "example.org", "example.net"]
TEST_CARDS = ["4111111111111111", "4242424242424242", "5555555555554444", "378282246310005", "6011111111111117"]
US_STATES = ["AL", "AZ", "CA", "CO", "FL", "GA", "IL", "MA", "MI", "MN", "NC", "NJ", "NY", "OH", "OR", "PA", "TX",
             "UT", "VA", "WA", "WI"]


def tokens(name: Optional[str]) -> List[str]:
    """``shippingAddress_line1`` -> ['shipping', 'address', 'line', '1']"""
    if not name:
        return []
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    return [t for t in re.split(r"[^A-Za-z0-9]+|(?<=[A-Za-z])(?=\d)", s.lower()) if t]


class Semantics:
    def __init__(self, rng, fake):
        self.r = rng
        self.f = fake
        r, f = rng, fake
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

        def email() -> str:
            local = re.sub(r"[^a-z0-9]", "", f.first_name().lower()) + "." + re.sub(r"[^a-z0-9]", "", f.last_name().lower())
            return f"{local}{r.randint(1, 999)}@{r.choice(DOMAINS)}"

        def date(past_years: int = 5, future_years: int = 0) -> str:
            return (now.date() + dt.timedelta(days=r.randint(-365 * past_years, 365 * future_years))).isoformat()

        def datetime_() -> str:
            return (now - dt.timedelta(seconds=r.randint(0, 3 * 365 * 86400))).isoformat().replace("+00:00", "Z")

        # (token pattern on the joined name, allowed JSON types, generator)
        S, I, N, B = ("string",), ("integer",), ("number", "integer"), ("boolean",)
        self.rules: List[Tuple[str, Tuple[str, ...], Callable[[], Any]]] = [
            (r"(^| )e ?mail( |$)|email address", S, email),
            (r"(^| )(first|given) name", S, f.first_name),
            (r"(^| )(last|family|sur) ?name", S, f.last_name),
            (r"(^| )middle name", S, f.first_name),
            (r"(^| )(user ?name|login|handle)( |$)", S, lambda: f.user_name() + str(r.randint(1, 99))),
            (r"(^| )(company|organi[sz]ation|employer|business) ?(name)?$", S, f.company),
            (r"(^| )(product|item) ?name", S, lambda: f"{f.color_name()} {f.word().title()}"),
            (r"(^| )(file) ?name", S, lambda: f"{f.word()}.{r.choice(['pdf', 'png', 'csv', 'txt'])}"),
            (r"(^| )(full )?name$", S, lambda: f"{f.first_name()} {f.last_name()}"),
            (r"(^| )(phone|mobile|cell|tel|telephone|fax)( |$)", S,
             lambda: f"+1-{r.randint(201, 989)}-555-{r.randint(100, 199):04d}"),
            (r"(^| )(street|address ?line ?1?|line 1)( |$)", S, f.street_address),
            (r"(^| )(address ?line ?2|line 2)( |$)", S, lambda: f"Apt {r.randint(1, 999)}"),
            (r"(^| )address$", S, lambda: f"{f.street_address()}, {f.city()}, {r.choice(US_STATES)} {r.randint(1001, 99950):05d}"),
            (r"(^| )(city|town)( |$)", S, f.city),
            (r"(^| )(state|province|region)( code)?$", S, lambda: r.choice(US_STATES)),
            (r"(^| )(zip|postal|post) ?(code)?$|(^| )postcode", S, lambda: f"{r.randint(1001, 99950):05d}"),
            (r"(^| )country ?(code|iso)", S, f.country_code),
            (r"(^| )country", S, f.country),
            (r"(^| )(lat|latitude)$", N, lambda: round(r.uniform(-90, 90), 6)),
            (r"(^| )(lng|lon|long|longitude)$", N, lambda: round(r.uniform(-180, 180), 6)),
            (r"(^| )(url|uri|link|website|homepage|href)( |$)", S,
             lambda: f"https://{f.word()}.{r.choice(DOMAINS)}/{f.word()}"),
            (r"(^| )(image|avatar|photo|picture|logo|thumbnail)( |$)", S,
             lambda: f"https://img.{r.choice(DOMAINS)}/{f.word()}.png"),
            (r"(^| )(ip|ip address|ipv4)$", S, lambda: f"{r.choice(['192.0.2.', '198.51.100.', '203.0.113.'])}{r.randint(1, 254)}"),
            (r"(^| )(currency)( code)?$", S, lambda: r.choice(["USD", "EUR", "GBP", "INR", "JPY", "CAD"])),
            (r"(^| )(lang|language|locale)$", S, lambda: r.choice(["en-US", "en-GB", "fr-FR", "de-DE", "hi-IN", "ja-JP"])),
            (r"(^| )(time ?zone|tz)$", S, lambda: r.choice(["UTC", "America/New_York", "Europe/London", "Asia/Kolkata"])),
            (r"(^| )(card ?number|pan|credit card)( |$)", S, lambda: r.choice(TEST_CARDS)),
            (r"(^| )(expiry|expiration|exp)( date)?$", S,
             lambda: f"{r.randint(1, 12):02d}/{(now.year + r.randint(1, 5)) % 100:02d}"),
            (r"(^| )(cvv|cvc|security code)$", S, lambda: f"{r.randint(100, 999)}"),
            (r"(^| )(iban)$", S, lambda: "GB82TEST" + "".join(r.choice(string.digits) for _ in range(14))),
            (r"(^| )(password|passwd|secret|pass ?phrase)( |$)", S, lambda: f.password(length=14)),
            (r"(^| )(token|api ?key|access key|client secret)( |$)", S, lambda: "%032x" % r.getrandbits(128)),
            (r"(^| )(color|colour)$", S, f.color_name),
            (r"(^| )(job ?title|position|role ?title)$", S, f.job),
            (r"(^| )(title|subject|headline)$", S, lambda: f.sentence(nb_words=4).rstrip(".")),
            (r"(^| )(description|desc|notes?|comments?|message|summary|bio|remarks|text|body|content|reason)$", S,
             lambda: f.sentence(nb_words=10)),
            (r"(^| )(sku|code|reference|ref|order number|invoice number)$", S,
             lambda: "".join(r.choice(string.ascii_uppercase) for _ in range(3)) + "-" + str(r.randint(1000, 99999))),
            (r"(^| )(uuid|guid)$|(^| )id$", S, lambda: str(uuid.UUID(int=r.getrandbits(128), version=4))),
            (r"(^| )id$", I, lambda: r.randint(1, 100000)),
            (r"(^| )(birth|dob|birthday)", S,
             lambda: (now.date() - dt.timedelta(days=r.randint(18 * 365, 80 * 365))).isoformat()),
            (r"(^| )(date|day|on)$", S, lambda: date(2, 1)),
            (r"(^| )(at|time|timestamp|datetime)$", S, datetime_),
            (r"(^| )(slug)$", S, lambda: "-".join(f.words(3))),
            (r"(^| )(page|page number)$", I, lambda: r.randint(1, 5)),
            (r"(^| )(limit|size|page size|per page|top|count)$", I, lambda: r.choice([10, 20, 25, 50])),
            (r"(^| )(offset|skip)$", I, lambda: r.choice([0, 10, 20, 50])),
            (r"(^| )(age)$", I, lambda: r.randint(18, 90)),
            (r"(^| )(year)$", I, lambda: r.randint(1990, now.year + 2)),
            (r"(^| )(quantity|qty|count|units|items)$", I, lambda: r.randint(1, 10)),
            (r"(^| )(price|amount|total|cost|balance|salary|fee|subtotal|tax|discount)( |$)", N,
             lambda: round(r.uniform(1, 1000), 2)),
            (r"(^| )(percent|percentage|rate|ratio)$", N, lambda: round(r.uniform(0, 100), 2)),
            (r"(^| )(rating|score|stars)$", N, lambda: r.randint(1, 5)),
            (r"(^| )(is|has|can|should|enabled|active|verified|deleted|archived|visible|flag)( |$)", B,
             lambda: r.random() < 0.5),
        ]

    def value_for(self, name: Optional[str], json_type: str, context: Optional[str] = None) -> Any:
        """Returns a realistic value for ``name`` or None when nothing matches.
        ``context`` is the enclosing object/resource (e.g. "products"), used for ambiguous names."""
        toks = tokens(name)
        if not toks:
            return None
        if toks in (["name"], ["title"], ["display", "name"]) and json_type == "string" and context:
            ctx = " ".join(tokens(context))
            if re.search(r"product|item|article|sku|catalog|inventory", ctx):
                return f"{self.f.color_name()} {self.f.word().title()}"
            if re.search(r"compan|supplier|vendor|organi[sz]ation|org$|merchant|business|tenant|partner", ctx):
                return self.f.company()
            if re.search(r"categor|tag|group|team|department|project|role|plan|label", ctx):
                return self.f.word().title()
            if re.search(r"file|document|attachment", ctx):
                return f"{self.f.word()}.pdf"
        joined = " ".join(toks)
        for pattern, types, gen in self.rules:
            if json_type in types and re.search(pattern, joined):
                v = gen()
                if json_type == "integer" and isinstance(v, float):
                    v = int(v)
                return v
        return None
