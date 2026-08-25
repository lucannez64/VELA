# Web-session capability formal-assurance record

`m12_web_session_capability.spthy` models the temporary browser capability from
pending request through RO/RW grant, capsule delivery, challenge exchange,
token use, renewal, revocation, and expiry.

Run with Tamarin Prover 1.12.0 and Maude 3.5.1:

```bash
./run-session-proofs.sh
```

Expected result: **14 verified, 0 falsified, 0 warnings**.

The checked properties are:

- grant agreement with the originally named account, approver, nonce, mode,
  epoch, and hard cap;
- at most one grant, capsule delivery, and token exchange per challenge;
- token issuance only after an RW grant and browser-key proof;
- no token issuance from an RO grant;
- web-only scope at issuance and exact scope/epoch/hard-cap preservation at
  renewal;
- no token use after revocation or expiry; and
- device-only permanent-account actions, while legitimate RO, RW, and renewal
  traces remain reachable.

The symbolic model abstracts cryptographic verification as a private browser
proof constructor. The production refinement is checked by hax/F* in
`serverVELA/vela-session-policy`; database and storage atomicity remain covered
by executable integration and concurrency tests.
