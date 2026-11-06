# cloady-dns

Self-hosted DoH resolver for the Meituan crowdsource "card no dispatch" trick.

- Blocks time-sync domains (so the phone clock stays offset) and Meituan
  reporting/calibration domains (so dispatch logic is starved).
- Deliberately does NOT block p.meituan.com (photo upload endpoint):
  blocking it kills delivery-proof uploads (verified Nov 2026: NextDNS with
  the full 25-domain list blocks dispatch but breaks upload; CONDNS trial
  without it uploads fine).
- Forwards everything else to domestic DoH upstreams (doh.pub, alidns).

Endpoints: GET/POST /dns-query (DoH), /health, /__log?key=... (query log).
Stdlib only, no dependencies.
