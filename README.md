# Vermeil Safety Layer

Personal safety layers for Hermes Agent, focused on AI safety and security. Implements prompt injection protection and deterministic memory tagging.

## Files

### `project_tags.py`
Deterministic project tagger for Hindsight auto-retain. Classifies conversation turns by project using keyword-driven patterns. Avoids LLM calls for tagging, keeping classification cheap and consistent. A turn that matches no project receives `None` (there is no `project:general`), ensuring that recall with `tags_match='any'` never hides untagged memories.

### `content_sanitizer.py`
Prompt injection defense implementing the "spotlighting" technique (Hines et al., 2024). Wraps untrusted content in XML delimiters, detects injection patterns, blocks markdown image exfiltration, and flags suspicious URLs.

## Threat Model

**Covered threats:**
- **Instruction override:** "ignore all previous instructions", "disregard above"
- **Role reassignment:** "you are now a...", "new persona", "jailbreak"
- **Prompt extraction:** "reveal your system prompt", "show me your rules"
- **Execution directives:** "run this command", "install the following package"
- **Exfiltration:** "send secrets to discord", "upload files to http"
- **Encoded injections:** base64-encoded attack patterns
- **Markdown image exfiltration:** URLs hidden in image syntax
- **Suspicious URLs:** shorteners (bitly, tinyurl), direct IPs, pastebin

**Not covered:**
- Subtle semantic injections that don't trigger regex patterns
- Attacks requiring multi-turn context to activate
- Injections in data already stored in persistent memory (the guardrail operates before write)
- Social engineering that doesn't use the detected pattern phrases

## Limitations

- Regex patterns are heuristic-based, not formal verification. A creative attacker can evade them.
- Spotlighting adds processing overhead but it's negligible (<1ms).
- `project_tags.py` uses keyword-driven classification: if a turn uses synonyms not in the list, it may not tag correctly. Extend the keyword list when new projects appear.

## Usage

```python
# project_tags.py
from project_tags import project_tags
tags = project_tags("Hindsight memory retain for this conversation")
# ['project:memoria']

# content_sanitizer.py
from content_sanitizer import sanitize_external_content, InjectionFlags
clean, flags = sanitize_external_content(raw_text, source="web_scrape")
if flags.count > 0:
    print(f"Injection detected: {flags.categories}")
```

## Testing

Run the basic test suite:

```bash
python test_safety_layer.py
```

Tests cover:
- Project classification correctness
- Injection pattern detection
- Full sanitize pipeline (image blocking, flagging)

## Credits

`project_tags.py` is an extension/modification of the **Hindsight** plugin for Hermes Agent, maintained by [vectorize-io](https://github.com/vectorize-io/hindsight). Hindsight is licensed under **MIT**.

`content_sanitizer.py` implements the spotlighting technique described in Hines et al., 2024.

## License

MIT — except for components derived from Hindsight, which retain their original license.