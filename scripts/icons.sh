#!/usr/bin/env bash
# Regenerate the embedded icons from a square source PNG (transparent background):
#   internal/http/static/icon.png   128px, quantized  (page logo at 64px/24px on 2x screens, apple-touch-icon)
#   internal/http/static/favicon.ico 48/32/16 with PNG-compressed frames
# Requires: magick (ImageMagick 7), pngquant, oxipng, python3.
#
# Usage: scripts/icons.sh path/to/source.png
set -euo pipefail

src=${1:?usage: scripts/icons.sh <source.png>}
out=$(cd "$(dirname "$0")/.." && pwd)/internal/http/static
for tool in magick pngquant oxipng python3; do
	command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

# shrink <size> <out>: Lanczos downscale, strip metadata, palette-quantize, recompress.
shrink() {
	magick "$src" -strip -filter Lanczos -resize "$1x$1" "$work/plain.png"
	pngquant --quality=80-98 --speed 1 --strip --force --output "$2" "$work/plain.png"
	oxipng -q -o max --strip all "$2"
}

shrink 128 "$out/icon.png"
for sz in 16 32 48; do shrink "$sz" "$work/f-$sz.png"; done

# ICO container with PNG payloads (every current browser reads these).
python3 - "$work" "$out/favicon.ico" <<'PY'
import struct, sys
work, dest = sys.argv[1:]
sizes = [16, 32, 48]
datas = [open(f"{work}/f-{s}.png", "rb").read() for s in sizes]
offset = 6 + 16 * len(sizes)
entries = b""
for s, d in zip(sizes, datas):
    entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(d), offset)
    offset += len(d)
with open(dest, "wb") as f:
    f.write(struct.pack("<HHH", 0, 1, len(sizes)) + entries + b"".join(datas))
PY

ls -l "$out/icon.png" "$out/favicon.ico"
