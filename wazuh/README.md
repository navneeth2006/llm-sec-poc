# Wazuh integration (extra credit)

The runner and tool layer write one JSON event per line to `logs/llm_security.log`
(`attack_result`, `mitigation_block`). Wazuh can ingest and alert on them.

1. Copy `local_rules.xml` into `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager.
2. Add `ossec_localfile.xml` content to the agent's `ossec.conf` (path = where this repo's `logs/` lives).
3. Restart: `sudo systemctl restart wazuh-agent` and `sudo systemctl restart wazuh-manager`.
4. Run `python runner.py ...`; alerts appear in the dashboard (rule ids 100100-100102).

Note: sample rules, adjust for your setup.
