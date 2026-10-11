# Third-party notices

This product includes third-party content. The applicable licenses and
notices are reproduced below. A copy of the Detection Rule License also ships
next to the vendored rules at `backend/rules/sigma/LICENSE`.

## SigmaHQ detection rules — Detection Rule License (DRL) 1.1

`backend/rules/sigma/` contains a sample of SigmaHQ rules
(https://github.com/SigmaHQ/sigma) at a pinned commit. They are made available
under the Detection Rule License (DRL) 1.1:

> # Detection Rule License (DRL) 1.1
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this rule set and associated documentation files (the "Rules"), to deal in the Rules without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Rules, and to permit persons to whom the Rules are furnished to do so, subject to the following conditions:
>
> If you share the Rules (including in modified form), you must retain the following if it is supplied within the Rules:
>
> 1. identification of the authors(s) ("author" field) of the Rule and any others designated to receive attribution, in any reasonable manner requested by the Rule author (including by pseudonym if designated).
>
> 2. a URI or hyperlink to the Rule set or explicit Rule to the extent reasonably practicable
>
> 3. indicate the Rules are licensed under this Detection Rule License, and include the text of, or the URI or hyperlink to, this Detection Rule License to the extent reasonably practicable
>
> If you use the Rules (including in modified form) on data, messages based on matches with the Rules must retain the following if it is supplied within the Rules:
>
> 1. identification of the authors(s) ("author" field) of the Rule and any others designated to receive attribution, in any reasonable manner requested by the Rule author (including by pseudonym if designated).
>
> THE RULES ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE RULES OR THE USE OR OTHER DEALINGS IN THE RULES.

The upstream license file for the pinned revision is reproduced at
`backend/rules/sigma/upstream-LICENSE.md`.

## MITRE ATT&CK — terms of use

This product reproduces MITRE ATT&CK content only where you import a bundle
into the local database via `scripts/update_attack.py` (see `SOURCES.md`);
no ATT&CK content is committed to this repository. MITRE ATT&CK and ATT&CK are
registered trademarks of The MITRE Corporation.

MITRE ATT&CK content is subject to the MITRE ATT&CK terms of use, reproduced
in part:

> The MITRE ATT&CK name and ATT&CK® are trademarks of The MITRE Corporation.
> MITRE grants you a limited, non-sublicensable, non-transferrable,
> revocable, non-exclusive license to use the ATT&CK content or information
> for your products, services, or other non-commercial or commercial use, in
> furtherance of providing an analytical service, capability, or tool that
> contributes to cybersecurity. MITRE does not grant to you a right to use the
> MITRE name (except as necessary to refer to the MITRE ATT&CK content), and
> all right, title and interest in and to the ATT&CK trademarks and logos
> remain in The MITRE Corporation. MITRE shall have no liability to you with
> respect to any injury, loss, expense, or damage to persons or property
> arising from your use of the ATT&CK content or information, whether or not
> caused by the negligence of MITRE, and MITRE shall not be liable for any
> special, incidental or consequential damages.
>
> The ATT&CK content is provided "as is", without warranty of any kind, either
> express or implied, including but not limited to the warranties of
> merchantability, fitness for a particular purpose, and non-infringement.
> MITRE does not warrant that the ATT&CK content is accurate, complete, or
> useful. In no event shall MITRE be liable for any claim, damages or other
> liability in connection with the ATT&CK content or information.

Full terms: https://attack.mitre.org/resources/terms-of-use/

## IANA top-level domains — public domain

The top-level-domain list at `backend/data/iana_tlds.txt` is adapted from the
public-domain list published by the Internet Corporation for Assigned Names
and Numbers (ICANN) at https://data.iana.org/TLD/tlds-alpha-by-domain.txt.

## Builtin detection rules — proprietary to this project

The rules under `backend/rules/builtin/` and the detection profiles under
`backend/data/profiles/` are authored for TriageLens and are not third-party
content; they are not covered by the third-party notices above.