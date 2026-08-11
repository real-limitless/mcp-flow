# Campaign storyboard

Static HTML frames used to produce README marketing screenshots for enterprise admins.

## Frames

| File | Output PNG |
| --- | --- |
| `frames/hero.html` | `docs/images/campaign-hero.png` |
| `frames/why.html` | `docs/images/campaign-why.png` |
| `frames/gateway.html` | `docs/images/campaign-gateway.png` |
| `frames/library.html` | `docs/images/campaign-library.png` |
| `frames/operator.html` | `docs/images/campaign-operator.png` |

## Capture

```bash
cd docs/campaign
./capture.sh
```

Requires network once for Google Fonts (or frames fall back to system fonts). Uses Playwright via a temp install when available.

Manual: open a frame in a browser at 100% zoom and screenshot the 1440×900 `#frame` canvas.

## Story

1. **Hero** — one MCP endpoint; harnesses get URL + agent key only  
2. **Why** — stop treating every laptop as a secret store  
3. **Gateway** — control plane + placement fan-out  
4. **Library** — admin-owned backends with sealed secrets  
5. **Operator** — TUI/CLI day-2 + enterprise defaults  
