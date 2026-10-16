# Authentik CSP fixtures

Unmodified Authentik 2025.12.6 templates and selected settings sections from
upstream revision `e1c90f3fae9d86d6a7a4f36018dafa9a1554f670` (MIT license).
The `.txt` suffix prevents repository Python validation from importing upstream
settings. Tests apply the production source patch before rendering templates
with Django and django-csp. Full patch applicability is also checked against the
complete pinned upstream source during qualification.
