"""List or extract selected files from a remote ZIP via HTTP range requests.

This avoids downloading the entire 3.25 GB AIT-LDS archive when only its
directory listing or a few small label/log samples are needed.
"""

from __future__ import annotations

import argparse
import io
import os
import urllib.request
import zipfile
from pathlib import Path


class HTTPRangeReader(io.RawIOBase):
    """Seekable, read-only HTTP file backed by byte-range requests."""

    def __init__(self, url: str, *, block_size: int = 4 * 1024 * 1024) -> None:
        self.url = url
        self.block_size = block_size
        self.position = 0
        self._cache_start = -1
        self._cache = b""
        request = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(request) as response:
            self.length = int(response.headers["Content-Length"])

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self.position + offset
        elif whence == os.SEEK_END:
            position = self.length + offset
        else:
            raise ValueError(f"unsupported whence: {whence}")
        if position < 0:
            raise ValueError("negative seek position")
        self.position = min(position, self.length)
        return self.position

    def read(self, size: int = -1) -> bytes:
        if self.position >= self.length:
            return b""
        if size is None or size < 0:
            size = self.length - self.position
        size = min(size, self.length - self.position)

        output = bytearray()
        while size:
            if not (
                self._cache_start <= self.position
                < self._cache_start + len(self._cache)
            ):
                self._fill_cache(self.position, max(size, self.block_size))
            cache_offset = self.position - self._cache_start
            available = min(size, len(self._cache) - cache_offset)
            if available <= 0:
                break
            output.extend(self._cache[cache_offset : cache_offset + available])
            self.position += available
            size -= available
        return bytes(output)

    def _fill_cache(self, start: int, requested: int) -> None:
        end = min(self.length - 1, start + requested - 1)
        request = urllib.request.Request(
            self.url, headers={"Range": f"bytes={start}-{end}"}
        )
        with urllib.request.urlopen(request) as response:
            if response.status not in (200, 206):
                raise OSError(f"range request failed: HTTP {response.status}")
            self._cache_start = start
            self._cache = response.read()


def list_entries(url: str, pattern: str | None) -> None:
    reader = HTTPRangeReader(url)
    with zipfile.ZipFile(reader) as archive:
        for info in archive.infolist():
            if pattern and pattern.casefold() not in info.filename.casefold():
                continue
            print(f"{info.file_size:>12}\t{info.compress_size:>12}\t{info.filename}")


def extract_entries(url: str, names: list[str], output_dir: Path) -> None:
    reader = HTTPRangeReader(url)
    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(reader) as archive:
        available = {info.filename for info in archive.infolist()}
        for name in names:
            if name not in available:
                raise KeyError(f"archive entry not found: {name}")
            target = (output_dir / name).resolve()
            root = output_dir.resolve()
            if root not in target.parents and target != root:
                raise ValueError(f"unsafe archive path: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(name) as source, target.open("wb") as destination:
                while chunk := source.read(1024 * 1024):
                    destination.write(chunk)
            print(target)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--pattern")
    extract_parser = subparsers.add_parser("extract")
    extract_parser.add_argument("--output-dir", type=Path, required=True)
    extract_parser.add_argument("names", nargs="+")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "list":
        list_entries(args.url, args.pattern)
    else:
        extract_entries(args.url, args.names, args.output_dir)


if __name__ == "__main__":
    main()
