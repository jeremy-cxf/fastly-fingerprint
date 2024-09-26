# Fastly Fingerprint

This is a compute template that simply returns all available Fastly Fingerprint attributes of the client caller.

To call it, simply call <your-url>/info. This is useful for research, or aggregation of multiple client fingerprints.

This should return a JSON response back:

```
{
  "client": {
    "ip": "76.41.121.131",
    "tls": {
      "protocol": "TLSv1.3",
      "neg_cipher": "TLS_AES_128_GCM_SHA256",
      "ja3": "b5001237acdf006056b409cc433726b0",
      "ja4": "t13d1715h2_5b57614c22b0_5c2c66f702b0"
    },
    "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "scheme": "https",
    "h2fp": "1:65536;4:131072;5:16384|12517377|1:0:0:201,2:0:0:101,3:0:0:1|m,p,a,s",
    "header_info": {
      "oh_count": "12",
      "oh_fp": "aB:a6:aT:aR:aQ:wE:fk:fq:c4:ix:q4:oW",
      "oh_order": [
        ":authority",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "priority",
        "te"
      ]
    }
  }
}
```
