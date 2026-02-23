# Antigraviti Playbook

## Alcance Permitido

Antigraviti puede tocar:
- `docs/`
- `README.md`
- `rulesets/`

## Alcance Restringido

Antigraviti NO puede tocar:
- `guardian/`
- `tests/`
- `pyproject.toml`

## Checklist Antes De Merge

1. Verificar que no cambie comportamiento de ejecución del scanner.
2. Confirmar que reglas nuevas tengan ID, severidad y recomendación.
3. Revisar que docs y README no contradigan el alcance local-first.
4. Ejecutar `python -m guardian scan --path . --out reports`.
5. Ejecutar `python -m unittest -q`.
6. Confirmar que `reports/scan.json` y `reports/scan.md` no entren al commit.
