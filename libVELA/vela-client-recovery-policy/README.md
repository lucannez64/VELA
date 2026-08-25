# Verified client recovery policy

This crate is the pure production decision boundary for crash-consistent
recovery publication, combining any two *distinct* recovery channels
(cloud + server, cloud + trusted contact, or server + trusted contact — M18),
and adopting the reconstructed RMS. Publication requires a durable
account/epoch/split-bound journal before external writes, strictly orders
finalization before active-cloud promotion, retries the same idempotent
operation after restart, and retires a journal when its epoch is no longer
active. Pair selection requires the exact requested account, two different
channels, one positive shared epoch, either matching split IDs or the legacy
both-absent case, authenticated shares with distinct coordinates, and — for
every trusted-contact share — proof that it was opened out of an
authenticated envelope addressed to this exact recipient (`recipient_bound`).
A one-sided or mismatched split ID is always rejected. The same boundary
plans trusted-contact delivery: seal only against a current, bound setup with
a recorded recipient key; retire the cached contact share whenever its epoch
is no longer current (RMS rotation) or the setup is deleted.

The proof boundary excludes parsing, HTTP, cloud storage, Shamir arithmetic,
and local persistence. `vela-crypto::recovery` converts those observations into
policy facts and is the only production reconstruction path used by desktop,
Android, and Apple clients.

Use the pinned hax/F*/Z3 installation described in
`../../serverVELA/vela-rekey-policy/README.md`, expose both opam switches on
`PATH`, and run:

```bash
./verify-fstar.sh
```

The runner extracts eighteen production/theorem entry points and checks every
F* verification condition without `--lax`.
