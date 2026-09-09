from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_CONFIG_PATH = (
    PROJECT_ROOT
    / "config"
    / "detector.yaml"
)


def load_config(
    config_path: Path | None = None,
) -> dict[str, Any]:
    path = config_path or DEFAULT_CONFIG_PATH

    if not path.exists():
        raise FileNotFoundError(
            f"Arquivo de configuração não encontrado: {path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as config_file:
            config = yaml.safe_load(config_file)

    except yaml.YAMLError as error:
        raise RuntimeError(
            f"Erro ao interpretar configuração YAML: {error}"
        ) from error

    if not isinstance(config, dict):
        raise RuntimeError(
            "O arquivo de configuração possui formato inválido."
        )

    return config