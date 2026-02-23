from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .provider import AIProviderError, AIProviderRequest, AIProviderResponse


class OllamaProvider:
    def __init__(self, base_url: str = "http://localhost:11434") -> None:
        self.base_url = base_url.rstrip("/")

    def generate(self, request: AIProviderRequest) -> AIProviderResponse:
        payload = {
            "model": request.model,
            "prompt": request.prompt,
            "stream": False,
        }
        raw = json.dumps(payload).encode("utf-8")
        http_request = Request(
            url=f"{self.base_url}/api/generate",
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(http_request, timeout=60) as response:
                body = response.read().decode("utf-8")
        except HTTPError as exc:
            raise AIProviderError(
                f"Ollama respondio con error HTTP {exc.code}. Verifica modelo '{request.model}' y que Ollama este activo."
            ) from exc
        except URLError as exc:
            raise AIProviderError(
                "No se pudo conectar a Ollama en http://localhost:11434. "
                "Instala Ollama (https://ollama.com/download), inicia el servicio y descarga el modelo con: "
                f"ollama pull {request.model}"
            ) from exc
        except TimeoutError as exc:
            raise AIProviderError("Timeout al consultar Ollama. Verifica que el modelo este cargado localmente.") from exc

        try:
            payload_response = json.loads(body)
        except json.JSONDecodeError as exc:
            raise AIProviderError("Ollama devolvio una respuesta no valida en JSON.") from exc

        text = str(payload_response.get("response") or "").strip()
        if not text:
            raise AIProviderError("Ollama no devolvio contenido de respuesta.")

        return AIProviderResponse(text=text)
