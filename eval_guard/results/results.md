# Guard benchmark (eval f4c662bd80)

Self-written simulated corpus; obedient scripted agent; measured on one machine.

60 attack cases, 61 benign cases, 4 setups, 36.9 s total.

| Setup | Attacks stopped | Attacks that leaked data | Benign tasks completed | Benign tasks that needed approval |
|---|---|---|---|---|
| no_guard | 0/60 (0%) | 44/60 | 61/61 (100%) | 0/61 |
| keyword_filter | 10/60 (17%) | 18/60 | 60/61 (98%) | 0/61 |
| content_filter | 55/60 (92%) | 1/60 | 57/61 (93%) | 0/61 |
| shadowguard | 60/60 (100%) | 0/60 | 59/61 (97%) | 2/61 |

Attacks stopped, by attacker goal:

| Goal | no_guard | keyword_filter | content_filter | shadowguard |
|---|---|---|---|---|
| customer-dump | 0/9 | 1/9 | 9/9 | 9/9 |
| destructive | 0/11 | 1/11 | 11/11 | 11/11 |
| exfil-email | 0/13 | 5/13 | 13/13 | 13/13 |
| exfil-url | 0/13 | 1/13 | 13/13 | 13/13 |
| path-escape | 0/4 | 1/4 | 0/4 | 4/4 |
| public-copy | 0/9 | 1/9 | 9/9 | 9/9 |
| rug-pull | 0/1 | 0/1 | 0/1 | 1/1 |

Attacks stopped, by hiding technique:

| Technique | no_guard | keyword_filter | content_filter | shadowguard |
|---|---|---|---|---|
| aria-hidden | 0/5 | 0/5 | 5/5 | 5/5 |
| base64 | 0/5 | 0/5 | 5/5 | 5/5 |
| display-none | 0/5 | 0/5 | 5/5 | 5/5 |
| hex | 0/3 | 0/3 | 3/3 | 3/3 |
| html-comment | 0/5 | 1/5 | 5/5 | 5/5 |
| rot13 | 0/3 | 0/3 | 3/3 | 3/3 |
| split-hidden | 0/2 | 1/2 | 2/2 | 2/2 |
| tiny-font | 0/5 | 0/5 | 5/5 | 5/5 |
| tool-description | 0/1 | 0/1 | 0/1 | 1/1 |
| unicode-tags | 0/5 | 0/5 | 5/5 | 5/5 |
| visible | 0/9 | 2/9 | 5/9 | 9/9 |
| web-comment | 0/5 | 5/5 | 5/5 | 5/5 |
| white-text | 0/5 | 0/5 | 5/5 | 5/5 |
| zero-width | 0/2 | 1/2 | 2/2 | 2/2 |

Guard decision latency over 344 guarded calls: p50 1.2 ms, p95 2.19 ms, p99 6.37 ms (time from receiving the call to the verdict; tool execution excluded).
