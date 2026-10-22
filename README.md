# FlowAuth

Replay an HTTP workflow under two identities, then check the object again from the owner's session. A write that returns an error can still show up in the final read.

Edit `examples/manifest.json` and the four request files for the target, then run:

```sh
python3 flowauth.py examples/manifest.json --out /tmp/flowauth-run
```

The manifest defines identities, ordered steps, a before/action/after check, and cleanup requests. Put cookies and authorization headers under `identities`. Use `capture` with `json:id` or `header:X-CSRF` to populate `${id}` or `${csrf}` in later requests. Raw request files can use CRLF or LF.

`report.json` records status codes, timing, body hashes, field changes, and the owner check. It omits identity headers, captured values, and response bodies.
