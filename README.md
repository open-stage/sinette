# sinette

Minimalistic Python library for Sinette DMX levels. No checking, just getting levels.

## Status

- Subscribe and get DMX levels

## Installation

- With uv:

```bash
uv add sinette
```

- With pip

```bash
pip install sinette
```

## Usage

```python
import time

import sinette


sinette_universe = 1
sinette_scope = "local"
sinette_receiver = sinette.SinetteReceiver(scope=sinette_scope)


@sinette_receiver.listen_on("universe", universe=sinette_universe)
def on_sinette_dmx(packet):
    print(
        f"[{packet.scope}] universe {packet.universe}: {packet.dmxData[:16]}",
        flush=True,
    )


def main() -> None:
    sinette_receiver.join_multicast(sinette_universe)
    sinette_receiver.start()
    print(
        f"Listening for Sinette universe {sinette_universe} in scope {sinette_scope!r}. Press Ctrl-C to stop."
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sinette_receiver.stop()


if __name__ == "__main__":
    main()
```

## Development

PRs appreciated. You can use [uv](https://docs.astral.sh/uv/) to get the
project setup by running:

```bash
uv sync
```

### Format

- To format, use [ruff](https://docs.astral.sh/ruff/)

```bash
uv format
```

### Pre-commit hooks

- You can use the pre-commit hooks

```bash
uv run pre-commit install
```

### Testing

- To test, use pytest

```bash
uv run pytest
```
