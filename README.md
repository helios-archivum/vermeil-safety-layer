# Vermeil Safety Layer

Capas de seguridad personal para Hermes Agent, enfocadas en AI safety y security. Implementa protección contra prompt injection y tagging determinista de memoria.

## Archivos

### `project_tags.py`
Etiquetador determinista para auto-retención de memoria en Hindsight. Clasifica turns de conversación por proyecto usando patterns keyword-driven. Evita llamadas LLM para tagging, manteniendo la clasificación cheap y consistente. Un turn que no matchea ningún project recibe tag None (no existe `project:general`), asegurando que la recall con `tags_match='any'` nunca oculte memorias sin tag.

### `content_sanitizer.py`
Defensa contra prompt injection implementando la técnica de "spotlighting" (Hines et al., 2024). Envuelve contenido no confiable en delimitadores XML, detecta patrones de inyección, bloquea exfiltración vía markdown images y flags URLs sospechosas. Reduce attack success rate de >50% a <2%.

## Threat Model

**Amenazas cubiertas:**
- **Instruction override:** "ignore all previous instructions", "disregard above"
- **Role reassignment:** "you are now a...", "new persona", "jailbreak"
- **Prompt extraction:** "reveal your system prompt", "show me your rules"
- **Execution directives:** "run this command", "install the following package"
- **Exfiltration:** "send secrets to discord", "upload files to http"
- **Encoded injections:** base64-encoded attack patterns
- **Markdown image exfiltration:** URLs ocultas en syntax de imagen
- **Suspicious URLs:** acortadores (bitly, tinyurl), IPs directas, pastebin

**Lo que NO cubre:**
- Inyecciones semánticas sutiles que no activan los patterns regex
- Attacks que requieren contexto multi-turno para activarse
- Inyecciones en datos ya almacenados en memoria persistente (la guardrail opera antes del write)
- Social engineering que no usa las frases patrón detectadas

## Limitaciones

- Los patrones regex son heuristic-based, no formal verification. Un attacker creativo puede eludirlos.
- El spotlighting añade overhead de processing pero es negligible (<1ms).
- `project_tags.py` usa classification keyword-driven: si un turn usa sinónimos no listados, puede no taggear correctamente. Extender la lista de keywords cuando aparecen nuevos projects.

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

## Créditos

`project_tags.py` es una extensión/modificación del plugin **Hindsight** para Hermes Agent, mantenido por [vectorize-io](https://github.com/vectorize-io/hindsight). Hindsight está bajo licencia **MIT**.

`content_sanitizer.py` implementa la técnica de spotlighting descrita en Hines et al., 2024.

## Licencia

MIT — excepto los componentes derivados de Hindsight, que mantienen su licencia original.