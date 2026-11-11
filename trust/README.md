# Trust list (optional)

Put a file named `c2pa-trust.pem` in this folder to let the extension check whether a Content
Credentials signer is on the C2PA trust list. **This folder ships empty on purpose**: a trust list
is a security decision, so the extension never bundles one you did not choose.

Get the official list on your own computer:

```
node tools/update-trust-list.mjs
```

Then reload the extension at `chrome://extensions`.

## What changes with and without it

| | Without the list | With the list |
|---|---|---|
| Image altered after signing | Detected | Detected |
| Signature genuine | Reported as valid, **signer identity "not checked"** | Reported as valid and **signer trusted** or **not on the list** |
| Signer unknown to the list | (can't tell) | Warned: the signature is real but who signed it cannot be confirmed |

A valid signature from an unknown signer only proves the file has not changed since *someone*
signed it. It says nothing about who that was, or whether the picture is real.

The list changes over time. Re-run the script now and then. A certificate revoked after
publication is not detected (this tool does not check revocation).
