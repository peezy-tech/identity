# Security

Report vulnerabilities privately through GitHub Security Advisories for this
repository. Do not open a public issue containing secrets, active session
material, OAuth credentials, wallet signatures, or an exploitable account-link
sequence.

Identity deployment secrets, provider credentials, database URLs, private
operational playbooks, and production client secrets do not belong in this
repository.

The service treats authentication, product authorization, and blockchain
transaction authority as separate boundaries. A valid identity token is never
evidence that a user authorized an on-chain transaction.
