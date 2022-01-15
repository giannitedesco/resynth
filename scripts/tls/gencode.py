#!/usr/bin/env python3

from typing import Generator, Tuple
from pathlib import Path
import csv


def _load_ciphers(p: Path) -> Generator[Tuple[int, str], None, None]:
    pfx = 'TLS_'
    with p.open() as f:
        rd = csv.reader(f)
        next(rd)
        for num, name, *_ in rd:
            if not name.startswith(pfx):
                continue
            name = name[len(pfx):]
            first, second = num.split(',')
            val = (int(first, 0) << 8) | int(second, 0)
            yield val, name.upper()


def _ciphers(p: Path, pkt: bool = False, stdlib: bool = False) -> None:
    ciphers = list(_load_ciphers(p))

    if pkt:
        print('\npub mod ciphers {')
        for val, name in ciphers:
            print(f'    pub const {name}: u16 = 0x{val:04x};')
        print('}')

    if stdlib:
        print("\nconst CIPHERS: phf::Map<&'static str, Symbol> = phf_map! {")
        for val, name in ciphers:
            print(f'    "{name}" => ')
            print(f'        Symbol::int_val(ciphers::{name} as u64),')
        print('};')


def _load_csv(p: Path) -> Generator[Tuple[int, str], None, None]:
    sfx = '_RESERVED'
    with p.open() as f:
        rd = csv.reader(f)
        next(rd)
        for num, name, *_ in rd:
            try:
                val = int(num)
            except ValueError:
                continue
            name, *_ = name.split(None, 1)
            if name.endswith(sfx):
                name = name[:-len(sfx)]
            name = name.upper()
            if name == 'UNASSIGNED':
                continue
            if name == 'RESERVED':
                continue
            yield val, name


def _hs(p: Path, pkt: bool = False, stdlib: bool = False) -> None:
    hs = list(_load_csv(p))

    if pkt:
        print('\npub mod handshake {')
        for val, name in hs:
            print(f'    pub const {name}: u8 = 0x{val:02x};')
        print('}')

    if stdlib:
        print("\nconst HANDSHAKE: phf::Map<&'static str, Symbol> = phf_map! {")
        for val, name in hs:
            print(f'    "{name}" => Symbol::int_val(handshake::{name} as u64),')
        print('};')


def _ext(p: Path, pkt: bool = False, stdlib: bool = False) -> None:
    hs = list(_load_csv(p))

    if pkt:
        print('\npub mod ext {')
        for val, name in hs:
            print(f'    pub const {name}: u16 = 0x{val:04x};')
        print('}')

    if stdlib:
        print("\nconst EXT: phf::Map<&'static str, Symbol> = phf_map! {")
        for val, name in hs:
            print(f'    "{name}" => Symbol::int_val(ext::{name} as u64),')
        print('};')


def main():
    base = Path('scripts/tls')
    ciphers = base / 'tls-parameters-4.csv'
    hs = base / 'tls-parameters-7.csv'
    ext = base / 'tls-extensiontype-values-1.csv'

    #_ciphers(ciphers, stdlib=True)
    #_hs(hs, pkt=True)
    _ext(ext, stdlib=True)


if __name__ == '__main__':
    main()
