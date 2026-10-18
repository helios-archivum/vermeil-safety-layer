# Vermeil Safety Layer

Capas de seguridad personal para Hermes Agent, enfocadas en AI safety y security.

## Archivos

### `project_tags.py`
Etiquetador determinista para auto-retención de memoria en Hindsight. Clasifica turns de conversación por proyecto usando patterns keyword-driven. Evita llamadas LLM para tagging, manteniendo la clasificación cheap y consistente.

### `content_sanitizer.py`
Defensa contra prompt injection implementando la técnica de "spotlighting" (Hines et al., 2024). Envuelve contenido no confiable en delimitadores XML, detecta patrones de inyección, bloquea exfiltración vía markdown images y flags URLs sospechosas. Reduce attack success rate de >50% a <2%.

## Créditos

`project_tags.py` es una extensión/modificación del plugin **Hindsight** para Hermes Agent, mantenido por [vectorize-io](https://github.com/vectorize-io/hindsight). Hindsight está bajo licencia **MIT**.

## Licencia

MIT — excepto los componentes derivados de Hindsight, que mantienen su licencia original.
