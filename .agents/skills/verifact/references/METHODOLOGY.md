# Methodology

## Evidence states

- **Raw evidence:** original collected data. It is authoritative and immutable.
- **Normalized fact:** a traceable view of raw evidence used for analysis.
- **Observation:** a relevant fact without a security claim.
- **Hypothesis:** a possible explanation with named required conditions.
- **Candidate:** a supported hypothesis ready for independent challenge.
- **Validated:** a supported finding that survived challenge.
- **Rejected:** a candidate disproved or unsupported by available evidence.
- **Inconclusive:** a candidate that cannot be resolved with available evidence.

## Review

Prefer a fresh agent context or human reviewer. If the host cannot create one, use a clearly labeled same-agent adversarial pass. It may dispose a candidate but provides lower assurance than separate review. Verifact binds the review to the finding bytes, but reviewer identity is self-attested and not cryptographically verified.

## Research

Use authoritative sources for documented behavior, defaults, or prerequisites. Record the HTTPS URL, access time, and what the source supports. Research cannot prove what happened on the host. Never put sensitive host values in a search query.

## Confidence

- **High:** direct evidence establishes every material condition.
- **Medium:** the claim is established with bounded, non-material uncertainty.
- **Low:** material uncertainty remains; keep the item candidate or inconclusive.

Severity measures likely consequence and practical exposure, not evidence strength.

Missing core evidence lowers coverage. An empty retained core log is valid evidence. Optional gaps remain visible but do not lower overall coverage by themselves.
