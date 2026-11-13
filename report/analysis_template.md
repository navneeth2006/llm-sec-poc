# Copy this file to report/analysis.md and replace every question with YOUR findings from results.csv. Delete this line.

## Prompt injection and data leaks (LLM01, LLM02, LLM08)
Which model leaked canaries more at baseline? Name attack IDs and give counts. Did either model refuse on its own? Did the input filter or spotlighting stop the rest? Anything still succeeding after mitigation, and why?

## Agent risks (ASI01, ASI02, ASI03, ASI05, ASI06)
Which model followed instructions hidden in files, web pages or inboxes? Which called dangerous tools (traversal, SSRF, external email, code) when asked directly? Did claimed authority ("I am the CEO") work on either model? Which mitigations worked fully because they sit in the tool layer, and which depended on the model?

## Supply chain, consumption and MCP (LLM03, LLM10, MCP)
How did each model react to tampered tool descriptions and poisoned tool results? Did the rug pull or shadowing work? What did the loop and flood tests cost in tokens before and after the caps?

## Utility vs safety
Which legitimate tasks failed with mitigations on (see utility.csv)? What is the trade-off?

## Overall
Which model was more robust and in what situations? Which result surprised you? What would you do next (stronger classifiers, human approval flows, per-tool permissions)?

## Limitations
Number of trials, non-determinism, regex filters are bypassable, simulated tools, one model version each.
