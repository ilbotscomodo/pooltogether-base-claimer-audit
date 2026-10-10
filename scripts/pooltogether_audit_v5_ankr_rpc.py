#!/usr/bin/env python3
"""AKE / PoolTogether v5 historical claimer audit - Ankr Chain RPC (read-only).

Historical windows: 2026-09-01..2026-09-30 and 2026-10-01..2026-10-09 UTC.
Queries PrizePool ClaimedPrize logs via standard Ankr Base `eth_getLogs`
in restartable block chunks, bypassing Advanced API 403. Then verifies each event's timestamp and transaction receipts. Extracts on-chain claim rewards; converts to historical USD when
DefiLlama price data is available. No wallet, no signing, no transfers.

Set an ANKR_API_KEY in your environment; don't paste it into chat.
PowerShell:
    $env:ANKR_API_KEY = 'YOUR_OWN_API_KEY'
    python -m pip install requests pycryptodome
    python pooltogether_audit_v5_ankr_rpc.py --probe
    python pooltogether_audit_v5_ankr_rpc.py --chain Base

Official docs: https://www.ankr.com/docs/rpc-service/service-plans/
              https://dev.pooltogether.com/protocol/reference/prize-pool/prizepool/
"""
import argparse
import collections
import csv
import datetime as dt
from decimal import Decimal, getcontext
import json
import os
from pathlib import Path
import sys
import time

import requests
try:
    from Crypto.Hash import keccak
except ImportError:
    sys.exit('Installa le librerie: python -m pip install requests pycryptodome')

getcontext().prec = 50
UTC = dt.timezone.utc
WINDOWS = {
    '2026-09': (dt.datetime(2026, 9, 1, tzinfo=UTC), dt.datetime(2026, 10, 1, tzinfo=UTC)),
    '2026-10': (dt.datetime(2026, 10, 1, tzinfo=UTC), dt.datetime(2026, 10, 10, tzinfo=UTC)),
}
NETWORKS = {
    'Base': {'chain': 'base', 'id': 8453,
             'pool': '0x45b2010d8a4f08b53c9fa7544c51dfd9733732cb'},
    'Optimism': {'chain': 'optimism', 'id': 10,
                 'pool': '0xF35fE10ffd0a9672d0095c435fd8767A7fe29B55'},
}
SIG = 'ClaimedPrize(address,address,address,uint24,uint8,uint32,uint152,uint96,address)'
kh = keccak.new(digest_bits=256)
kh.update(SIG.encode('ascii'))
TOPIC = '0x' + kh.hexdigest()
OUT = Path(os.environ.get('AUDIT_OUT', 'pooltogether_audit_v5'))
ZERO = Decimal(0)


def read_json(path, default):
    if not path.is_file():
        return default
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, path)


def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for row in rows:
            w.writerow({k: '' if row.get(k) is None else str(row[k]) for k in fields})
    os.replace(tmp, path)


def intval(v):
    if isinstance(v, int): return v
    if isinstance(v, str): return int(v, 16 if v.startswith(('0x','0X')) else 10)
    raise ValueError(f'Numero inatteso: {str(v)[:60]}')


class Client:
    def __init__(self, api_key, delay):
        self.rpc = {
            name: f'https://rpc.ankr.com/{cfg["chain"]}/{api_key}'
            for name, cfg in NETWORKS.items()
        }
        self.s = requests.Session()
        self.s.headers.update({'User-Agent': 'AKE-Historical-Audit/5.0',
                               'Content-Type': 'application/json'})
        self.delay = max(0, delay)
        self.last_call = 0
        self.count = 0

    def call(self, url, method, params):
        # No endpoint URL in errors/logging: it contains the private API key.
        for retry in range(9):
            pause = self.delay - (time.monotonic() - self.last_call)
            if pause > 0: time.sleep(pause)
            self.last_call = time.monotonic()
            self.count += 1
            try:
                r = self.s.post(url, json={'jsonrpc': '2.0', 'id': self.count,
                                           'method': method, 'params': params}, timeout=45)
                if r.status_code in (429, 500, 502, 503, 504):
                    retry_after = r.headers.get('Retry-After')
                    try: wait = min(90.0, float(retry_after)) if retry_after else min(60.0, 2 ** retry)
                    except ValueError: wait = min(60.0, 2 ** retry)
                    print(f'  API HTTP {r.status_code}: riprovo dopo {wait:.1f}s', flush=True)
                    time.sleep(max(1.0, wait))
                    continue
                if r.status_code in (401, 403):
                    # Surface the real, sanitized reason; do not reveal the API key.
                    try:
                        body = r.json()
                        message = str(body.get('error', {}).get('message', '') if isinstance(body, dict) else '')
                        code = (body.get('error', {}).get('code', '') if isinstance(body, dict) else '')
                    except ValueError:
                        message, code = r.text[:220], ''
                    message = message.replace(os.environ.get('ANKR_API_KEY', ''), '[REDACTED]')[:180]
                    raise RuntimeError(f'{method}: HTTP {r.status_code}, codice {code}, motivo {message or "non specificato"}')
                if r.status_code >= 400:
                    raise RuntimeError(f'{method}: HTTP {r.status_code} da Ankr (URL non mostrato)')
                body = r.json()
                if not isinstance(body, dict) or body.get('jsonrpc') not in (None, '2.0'):
                    raise RuntimeError('Formato JSON-RPC non valido')
                if 'error' in body:
                    error = body['error'] or {}
                    code = error.get('code')
                    msg = str(error.get('message', error))
                    if code in (-32090, -32005, -32061, -32062, -32000) and any(
                        k in msg.lower() for k in ('rate', 'limit', 'temporar', 'busy', 'unavailable', 'timeout')
                    ):
                        wait = min(60.0, 2 ** retry)
                        print(f'  {method}: {msg[:95]} / riprovo dopo {wait:.1f}s', flush=True)
                        time.sleep(wait)
                        continue
                    raise RuntimeError(f'{method} errore RPC {code}: {msg[:240]}')
                if 'result' not in body:
                    raise RuntimeError(f'{method}: risultato mancante')
                return body['result']
            except (requests.Timeout, requests.ConnectionError) as err:
                if retry == 8:
                    raise RuntimeError(f'{method}: errore di rete ({type(err).__name__})') from err
                time.sleep(min(45.0, 2 ** retry))
        raise RuntimeError(f'{method}: troppi retry, nessun dato inventato')

    def chain_call(self, name, method, params):
        return self.call(self.rpc[name], method, params)

    def logs(self, name, from_block, to_block):
        """Standard chain RPC, NOT Advanced API: inclusive block bounds."""
        return self.chain_call(name, 'eth_getLogs', [{
            'fromBlock': hex(from_block), 'toBlock': hex(to_block),
            'address': NETWORKS[name]['pool'], 'topics': [TOPIC],
        }])

    def block(self, name, number):
        result = self.chain_call(name, 'eth_getBlockByNumber', [hex(number), False])
        if not isinstance(result, dict) or 'timestamp' not in result:
            raise RuntimeError(f'Blocco {number} non disponibile sul nodo: cronologia incompleta')
        return result


def block_at(client, name, timestamp):
    """First block with timestamp >= timestamp, using the head as upper bound.

    Avoid starting a binary search from genesis (problematic on pruned nodes).
    """
    head = intval(client.chain_call(name, 'eth_blockNumber', []))
    ts_head = intval(client.block(name, head)['timestamp'])
    if timestamp > ts_head:
        return head + 1
    guess = max(0, head - max(0, (ts_head - timestamp) // 2))
    guess_ts = intval(client.block(name, guess)['timestamp'])
    if guess_ts < timestamp:
        lo, hi = guess, head
    else:
        hi, step = guess, 5000
        while True:
            lo = max(0, hi - step)
            if intval(client.block(name, lo)['timestamp']) < timestamp:
                break
            if lo == 0:
                return 0
            hi, step = lo, step * 2
    while lo < hi:
        mid = (lo + hi) // 2
        if intval(client.block(name, mid)['timestamp']) < timestamp:
            lo = mid + 1
        else:
            hi = mid
    return lo


def get_token(client, name):
    cfg = NETWORKS[name]
    chain_id = intval(client.chain_call(name, 'eth_chainId', []))
    if chain_id != cfg['id']:
        raise RuntimeError(f'Chain ID sbagliato: atteso {cfg["id"]}, ricevuto {chain_id}')
    k = keccak.new(digest_bits=256); k.update(b'prizeToken()')
    data = client.chain_call(name, 'eth_call', [{'to': cfg['pool'],
            'data': '0x' + k.hexdigest()[:8]}, 'latest'])
    if not isinstance(data, str) or len(data) != 66:
        raise RuntimeError('PrizePool.prizeToken() sconosciuto')
    token = '0x' + data[-40:]
    decimals_data = client.chain_call(name, 'eth_call',
                             [{'to': token, 'data': '0x313ce567'}, 'latest'])
    dec = intval(decimals_data)
    if not 0 <= dec <= 36: raise RuntimeError('Decimali token inattesi')
    known_weth = token.lower() == '0x4200000000000000000000000000000000000006'
    label = 'WETH' if known_weth else 'token_' + token[:8]
    try:
        symbol_result = client.chain_call(name, 'eth_call',
                             [{'to': token, 'data': '0x95d89b41'}, 'latest'])
        raw = bytes.fromhex(symbol_result[2:])
        if len(raw) >= 96:
            offset = int.from_bytes(raw[:32], 'big')
            if offset + 32 <= len(raw):
                size = int.from_bytes(raw[offset:offset+32], 'big')
                if size <= 64 and offset + 32 + size <= len(raw):
                    label = raw[offset+32:offset+32+size].decode('utf-8', 'strict')
        elif len(raw) == 32:
            label = raw.rstrip(b'\0').decode('utf-8', 'strict')
    except (ValueError, UnicodeDecodeError, RuntimeError):
        pass
    return {'token': token, 'decimals': dec, 'symbol': label}


def get_logs_cached(client, name, month, directory, span, bounds, limit_chunks=0):
    """Restartable scan, with a checkpoint ONLY after the log batch is durable.

    Standard Ankr Freemium has a 3000-block cap; default 2000 for margin.
    """
    low, high = bounds       # high exclusive
    if low >= high:
        raise RuntimeError(f'{month}: intervallo vuoto o in futuro, verifica date/blocchi')
    state_file = directory / f'{month}_checkpoint.json'
    raw_file = directory / f'{month}_logs.jsonl'
    state = read_json(state_file, {})
    if state:
        if state.get('bounds') != [low, high]:
            raise RuntimeError('Checkpoint incompatibile con confini: non mischio i dati')
        if state.get('complete'):
            if not raw_file.exists():
                raise RuntimeError('Checkpoint completo senza file logs; ferma il report')
            print(f'  {month}: scansione gia completata, uso la cache', flush=True)
            return raw_file
        if not raw_file.exists() and state.get('chunks', 0) > 0:
            raise RuntimeError('Checkpoint presente, ma file log assente: non proseguo')
    elif raw_file.exists():
        raise RuntimeError('File log privo di checkpoint: sposta la cartella per ricominciare')
    current = int(state.get('nextBlock', low))
    chunks = int(state.get('chunks', 0))
    count = int(state.get('logs', 0))
    print(f'  {month}: blocchi {low}..{high-1}, riparto da {current}', flush=True)
    directory.mkdir(parents=True, exist_ok=True)
    raw_file.touch(exist_ok=True)
    while current < high:
        stop = min(current + span, high)
        try:
            logs = client.logs(name, current, stop - 1)
        except RuntimeError as exc:
            msg = str(exc).lower()
            if any(k in msg for k in ('block range', 'max range', 'range limit', 'too many blocks',
                                      'limit exceeded', 'query returned more than', '-32005')) and span > 1:
                span = max(1, span // 2)
                print(f'  Limite di intervallo: provo blocchi da {span}', flush=True)
                continue
            raise
        if not isinstance(logs, list):
            raise RuntimeError('eth_getLogs: dati inattesi; nessun avanzamento del checkpoint')
        with raw_file.open('a', encoding='utf-8') as f:
            for item in logs:
                if not isinstance(item, dict):
                    raise RuntimeError('Log non valido; arresto')
                f.write(json.dumps(item, ensure_ascii=False) + '\n')
            f.flush()
            os.fsync(f.fileno())
        current = stop
        chunks += 1
        count += len(logs)
        write_json(state_file, {'bounds': [low, high], 'nextBlock': current, 'chunks': chunks,
                                'logs': count, 'complete': current == high})
        if chunks % 20 == 0 or current == high:
            print(f'  {month}: {chunks} richieste, {count} eventi, '
                  f'{current-low:,}/{high-low:,} blocchi letti', flush=True)
        if limit_chunks and chunks >= limit_chunks and current != high:
            raise RuntimeError('Arresto di test --max-chunks: audit PARZIALE')
    return raw_file


def decode_event(log, decimals):
    if log.get('removed') is True:
        raise RuntimeError('Log marcato removed, richiede verifica della riorganizzazione')
    if not isinstance(log.get('topics'), list) or len(log['topics']) != 4:
        raise RuntimeError('ABI inattesa: attesi 4 topics')
    if log['topics'][0].lower() != TOPIC.lower():
        raise RuntimeError('Risposta Ankr contiene un topic diverso da ClaimedPrize')
    blob = bytes.fromhex(log['data'][2:])
    if len(blob) != 6*32: raise RuntimeError('ABI inattesa: evento non ha 6 parole')
    words = [int.from_bytes(blob[i:i+32], 'big') for i in range(0,len(blob),32)]
    return {'tx': log['transactionHash'].lower(),
            'block': intval(log['blockNumber']),
            'log_index': intval(log['logIndex']),
            'vault': '0x'+log['topics'][1][-40:],
            'winner': '0x'+log['topics'][2][-40:],
            'recipient': '0x'+log['topics'][3][-40:],
            'draw': words[0], 'tier': words[1], 'prize_index': words[2],
            'payout': Decimal(words[3]) / Decimal(10**decimals),
            'reward': Decimal(words[4]) / Decimal(10**decimals),
            'reward_recipient': '0x'+words[5].to_bytes(32, 'big')[-20:].hex()}


def cached_chain_read(client, name, cache, cache_file, method, params, key):
    if key in cache: return cache[key]
    result = client.chain_call(name, method, params)
    if result is None: raise RuntimeError(f'{method}: dato assente ({key})')
    cache[key] = result
    write_json(cache_file, cache)
    return result


def price_usd(session, day, name, token, cache, cache_file, delay):
    sym = f'{NETWORKS[name]["chain"]}:{token.lower()}'
    key = f'{day.isoformat()}/{sym}'
    if key in cache: return Decimal(cache[key])
    ts = int(dt.datetime.combine(day, dt.time(12), tzinfo=UTC).timestamp())
    from urllib.parse import quote
    url = f'https://coins.llama.fi/prices/historical/{ts}/' + quote(sym, safe=':')
    try:
        time.sleep(min(1.,delay))
        r = session.get(url, timeout=25)
        r.raise_for_status()
        result = r.json().get('coins', {}).get(sym, {})
        px = result.get('price')
        # WETH price as ETH is an explicit approximation if the chain token
        # cannot be priced; not applied to arbitrary non-WETH tokens.
        if px is None and token.lower() == '0x4200000000000000000000000000000000000006':
            fallback = f'https://coins.llama.fi/prices/historical/{ts}/coingecko:ethereum'
            j = session.get(fallback, timeout=25).json()
            px = j.get('coins',{}).get('coingecko:ethereum',{}).get('price')
        if px is None: return None
        cache[key] = str(px)
        write_json(cache_file, cache)
        return Decimal(str(px))
    except (requests.RequestException, ValueError, TypeError, KeyError):
        return None


def month_reports(client, name, token_meta, directory, skip_prices):
    raw_events = []
    seen = set()
    for month in WINDOWS:
        state = read_json(directory / f'{month}_checkpoint.json', {})
        if not state.get('complete'):
            raise RuntimeError(f'{month} incompleto, niente report')
        raw_file = directory / f'{month}_logs.jsonl'
        if not raw_file.exists():
            raise RuntimeError(f'Cache assente per {month}, non assumere zero eventi')
        with raw_file.open(encoding='utf-8') as f:
            for line in f:
                rec = json.loads(line)
                if rec.get('address','').lower() != NETWORKS[name]['pool'].lower():
                    raise RuntimeError('Risposta con contratto inatteso')
                row = decode_event(rec, token_meta['decimals'])
                key = (row['tx'], row['log_index'])
                if key in seen: continue
                seen.add(key)
                row['expected_month'] = month
                raw_events.append(row)
    print(f'  {name}: {len(raw_events)} eventi unici; lettura blocchi e ricevute...', flush=True)
    raw_events.sort(key=lambda x:(x['block'], x['log_index']))
    blocks_file, receipts_file = directory/'blocks.json', directory/'receipts.json'
    blocks = read_json(blocks_file,{})
    receipts = read_json(receipts_file,{})
    by_tx_count = collections.Counter(r['tx'] for r in raw_events)
    prices_file = directory/'prices.json'
    prices = read_json(prices_file,{})
    out = []
    for idx, ev in enumerate(raw_events, 1):
        b = cached_chain_read(client, name, blocks, blocks_file, 'eth_getBlockByNumber',
                              [hex(ev['block']), False], str(ev['block']))
        timestamp = dt.datetime.fromtimestamp(intval(b['timestamp']), UTC)
        start, end = WINDOWS[ev['expected_month']]
        if not start <= timestamp < end:
            raise RuntimeError(f'Confine temporale errato: tx {ev["tx"]} '
                               f'risulta {timestamp.isoformat()}, mese richiesto {ev["expected_month"]}')
        rec = cached_chain_read(client, name, receipts, receipts_file,
                                'eth_getTransactionReceipt', [ev['tx']], ev['tx'])
        if intval(rec['blockNumber']) != ev['block']:
            raise RuntimeError('Receipt non corrisponde al blocco evento: '+ev['tx'])
        # Execution + OP Stack L1 data fee + optional operator fee, if provided.
        exec_gas = intval(rec['gasUsed']) * intval(rec['effectiveGasPrice'])
        l1_fee = intval(rec['l1Fee']) if rec.get('l1Fee') is not None else None
        operator_fee = intval(rec['operatorFee']) if rec.get('operatorFee') is not None else 0
        gas_native = (Decimal(exec_gas + l1_fee + operator_fee) / Decimal(10**18)) if l1_fee is not None else None
        l2_native = Decimal(exec_gas)/Decimal(10**18)
        payer = rec['from'].lower()
        fee_alloc = gas_native/Decimal(by_tx_count[ev['tx']]) if gas_native is not None else None
        price = None if skip_prices else price_usd(client.s,timestamp.date(),name,token_meta['token'],
                                                   prices,prices_file,client.delay)
        weth_token = token_meta['token'].lower() == '0x4200000000000000000000000000000000000006'
        # Native gas fee is ETH on Base/Optimism. In the WETH case, ETH price
        # is a defensible estimate. Otherwise use a separate ETH quote.
        gas_price = price if weth_token else (None if skip_prices else price_usd(
            client.s, timestamp.date(), name, '0x4200000000000000000000000000000000000006',
            prices, prices_file,client.delay))
        reward_usd = ev['reward']*price if price is not None else None
        gas_usd = fee_alloc*gas_price if fee_alloc is not None and gas_price is not None else None
        row = dict(ev)
        row.update(month=timestamp.strftime('%Y-%m'), day=timestamp.date().isoformat(),
                   token=token_meta['symbol'], token_address=token_meta['token'],
                   gas_payer=payer, reward_recipient_is_gas_payer=(payer == ev['reward_recipient'].lower()),
                   fee_l2_eth_tx=l2_native, fee_l1_eth_tx=(Decimal(l1_fee)/Decimal(10**18) if l1_fee is not None else None),
                   gas_fee_eth_alloc=fee_alloc, reward_usd_est=reward_usd, gas_usd_est=gas_usd,
                   net_usd_if_same_payer=(reward_usd-gas_usd if reward_usd is not None and gas_usd is not None
                                          and payer == ev['reward_recipient'].lower() else None),
                   historic_token_usd=price, historic_eth_usd=gas_price)
        out.append(row)
        if idx % 25 == 0: print(f'  {name}: verificati {idx}/{len(raw_events)} eventi', flush=True)
    fields = ['day','month','tx','block','log_index','token','token_address','reward_recipient','gas_payer',
              'reward_recipient_is_gas_payer','reward','payout','gas_fee_eth_alloc','reward_usd_est',
              'gas_usd_est','net_usd_if_same_payer','historic_token_usd','historic_eth_usd',
              'fee_l2_eth_tx','fee_l1_eth_tx','draw','tier','prize_index','vault','winner','recipient']
    write_csv(directory/'events.csv',fields,out)

    def stats(events):
        recv = sum((e['reward'] for e in events),ZERO)
        txs = set(e['tx'] for e in events)
        # Each tx's fee is allocated across claim events, not duplicated.
        fees_known = all(e['gas_fee_eth_alloc'] is not None for e in events)
        reward_px_known = all(e['reward_usd_est'] is not None for e in events)
        gas_px_known = all(e['gas_usd_est'] is not None for e in events)
        fee = sum((e['gas_fee_eth_alloc'] for e in events if e['gas_fee_eth_alloc'] is not None),ZERO)
        rev_usd = sum((e['reward_usd_est'] for e in events if e['reward_usd_est'] is not None), ZERO)
        gas_usd = sum((e['gas_usd_est'] for e in events if e['gas_usd_est'] is not None), ZERO)
        # Operator net is not known if the gas payer != reward recipient.
        selfpaid = all(e['reward_recipient_is_gas_payer'] for e in events)
        return {'claims': len(events), 'transactions': len(txs),
                'reward_token': recv, 'gas_eth_est': fee if fees_known else None,
                'reward_usd_est': rev_usd if reward_px_known else None,
                'gas_usd_est': gas_usd if gas_px_known else None,
                'system_net_usd_est': rev_usd-gas_usd if reward_px_known and gas_px_known else None,
                'recipient_net_usd_est': rev_usd-gas_usd if reward_px_known and gas_px_known and selfpaid else None,
                'gas_data_complete': fees_known, 'prices_complete': reward_px_known and gas_px_known,
                'all_recipients_pay_gas': selfpaid}

    grouped = collections.defaultdict(list)
    for ev in out: grouped[(ev['month'],ev['reward_recipient'])].append(ev)
    monthly = [dict(chain=name,month=m,token=token_meta['symbol'],**stats(
        [e for e in out if e['month']==m])) for m in WINDOWS]
    operators = [dict(chain=name, month=m, reward_recipient=a, token=token_meta['symbol'],**stats(es))
                 for (m,a),es in sorted(grouped.items())]
    nums = ['claims','transactions','reward_token','gas_eth_est','reward_usd_est',
            'gas_usd_est','system_net_usd_est','recipient_net_usd_est',
            'gas_data_complete','prices_complete','all_recipients_pay_gas']
    write_csv(directory/'monthly_summary.csv', ['chain','month','token']+nums, monthly)
    write_csv(directory/'operators.csv', ['chain','month','reward_recipient','token']+nums, operators)
    write_json(directory/'audit_status.json', {
        'chain':name,'date_from':'2026-09-01T00:00:00Z',
        'date_until_exclusive':'2026-10-10T00:00:00Z','logs_complete':True,
        'receipts_complete':True,'token':token_meta,'periods':monthly,
        'usd_values_are_estimates':True,
        'note':'Ricompense contabili maturate: non prova di prelievo in wallet. '
               'Il net del sistema e una stima economica, non redditivita del nuovo bot. '
               'Se il destinatario non paga direttamente gas, il suo netto non e determinabile.'})
    print('\n=== AUDIT COMPLETATO, DATI DA BLOCKCHAIN ===')
    for m in monthly:
        print(f"  {m['month']}: {m['claims']} premi riscattati in {m['transactions']} transazioni, "
              f"ricompensa {m['reward_token']} {m['token']}, "
              f"USD stimati {m['reward_usd_est']} | gas USD {m['gas_usd_est']}")
    print('File:',directory.resolve())
    print('IMPORTANTE: i profitti netti personali non sono certi per destinatari diversi dai pagatori del gas.')
    return monthly


def main():
    p = argparse.ArgumentParser(description='PoolTogether storico Base - Ankr Chain RPC v5, no Advanced API')
    p.add_argument('--chain', choices=['Base'], default='Base')
    p.add_argument('--probe', action='store_true', help='Verifica la lettura di logs storici su Base')
    p.add_argument('--delay', type=float, default=0.4)
    p.add_argument('--span', type=int, default=2000, help='Blocchi per richiesta (max 3000 Freemium)')
    p.add_argument('--max-chunks', type=int, default=0, help='Solo test, report incompleto')
    p.add_argument('--no-prices', action='store_true')
    args = p.parse_args()
    if not 1 <= args.span <= 3000 or args.delay < 0:
        p.error('Usa --span da 1 a 3000, --delay >= 0')
    key = os.environ.get('ANKR_API_KEY', '').strip()
    if not key:
        sys.exit('Manca ANKR_API_KEY: imposta $env:ANKR_API_KEY = "..." in PowerShell.')
    name = 'Base'
    client = Client(key, args.delay)
    print('PoolTogether on-chain - Base, 1 settembre - 9 ottobre 2026, lettura RPC standard')
    meta = get_token(client, name)
    print('Contratto:', NETWORKS[name]['pool'])
    print('Token premio:', meta['symbol'], meta['token'], 'decimali', meta['decimals'])
    # Use block timestamps, no arbitrary hardcoded block numbers.
    bounds = {month: (block_at(client, name, int(t0.timestamp())),
                      block_at(client, name, int(t1.timestamp())))
              for month, (t0, t1) in WINDOWS.items()}
    for month, (lo, hi) in bounds.items():
        print(f'  {month}: blocchi [{lo}, {hi})')
    if args.probe:
        # One small, verifiably historical query near 1 September (may be zero events).
        low, high = bounds['2026-09']
        probe_high = min(low + 50, high)
        logs = client.logs(name, low, probe_high - 1)
        if not isinstance(logs, list):
            raise RuntimeError('Probe: eth_getLogs non ha restituito lista')
        print('PROBE OK: eth_getLogs consente la lettura storica; '
              f'{len(logs)} eventi in {probe_high-low} blocchi di prova (anche zero va bene).')
        print('Nessun risultato mensile calcolato; usa il comando senza --probe.')
        return
    directory = OUT / name.lower()
    for month in WINDOWS:
        get_logs_cached(client, name, month, directory, args.span, bounds[month], args.max_chunks)
    month_reports(client, name, meta, directory, args.no_prices)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, requests.RequestException, ValueError, KeyError, TypeError) as exc:
        print('\nERRORE:', str(exc), file=sys.stderr)
        print('NON interpretare uno storico incompleto come assenza di ricompense.', file=sys.stderr)
        sys.exit(2)