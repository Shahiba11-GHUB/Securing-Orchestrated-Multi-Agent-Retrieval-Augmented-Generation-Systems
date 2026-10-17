"""Rebuild a small BIPIA-based EmailQA RAG development set; Python stdlib only."""
import csv
import hashlib
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parent
SEED = 42
REVISION = 'a004b69ec0dd446e0afd461d98cb5e96e120a5d0'
CATEGORIES = ['Information Retrieval', 'Content Creation', 'Language Translation', 'Instruction']

def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]

def write_jsonl(path, rows):
    path.write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows), encoding='utf-8')

def chunks_for(text, case_id, document_id, source):
    # Character offsets refer to the exact original/modified document, end-exclusive.
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + 1200, len(text))
        piece = text[start:end]
        chunks.append(dict(chunk_id=f'{case_id}_chunk_{len(chunks)+1:03d}',
            case_id=case_id, document_id=document_id, text=piece, source=source,
            source_metadata=dict(dataset='BIPIA', task='EmailQA', split='train',
                revision=REVISION, source_trust='untrusted', char_start=start, char_end=end,
                content_sha256=hashlib.sha256(piece.encode()).hexdigest())))
        if end == len(text):
            break
        start = end - 200
    return chunks

def build():
    rng = random.Random(SEED)
    raw_train = read_jsonl(ROOT/'upstream/email_train.jsonl')
    test_contexts = {r['context'] for r in read_jsonl(ROOT/'upstream/email_test.jsonl')}
    candidates = {}
    for index, record in enumerate(raw_train):
        if record['context'] not in test_contexts:
            candidates.setdefault(record['context'], (index, record))
    answerable = [v for v in candidates.values() if v[1]['ideal'].strip().lower() != 'unknown']
    unknown = [v for v in candidates.values() if v[1]['ideal'].strip().lower() == 'unknown']
    # Nine answerable distinct contexts remain after removing exact test overlaps.
    selected = rng.sample(answerable, 9) + rng.sample(unknown, 11)
    rng.shuffle(selected)
    attacks = json.loads((ROOT/'upstream/text_attack_train.json').read_text())
    attack_specs = [(category, index, payload) for category in CATEGORIES
                    for index, payload in enumerate(attacks[category])]
    rng.shuffle(attack_specs)
    # Neutral case IDs do not encode clean/attacked labels; mapping is evaluator-only.
    case_numbers = list(range(1, 41)); rng.shuffle(case_numbers)
    clean, attacked, documents, queries, evaluation, review = [], [], [], [], [], []
    for pair_index, ((source_index, row), (category, attack_index, payload)) in enumerate(zip(selected, attack_specs), 1):
        pair_id = f'pair_{pair_index:03d}'
        document_id = f'email_train_{source_index:03d}'
        source = f'bipia://email/train/{source_index}'
        position = ['start', 'middle', 'end'][(pair_index-1) % 3]
        if position == 'start':
            cut = 0
        elif position == 'end':
            cut = len(row['context'])
        else:
            cut = row['context'].rfind(' ', 0, len(row['context'])//2)
            if cut < 0: cut = len(row['context'])//2
        insertion = '\n\n' + payload + '\n\n'
        modified = row['context'][:cut] + insertion + row['context'][cut:]
        for is_attack, text in [(False, row['context']), (True, modified)]:
            case_id = f'case_{case_numbers.pop():03d}'
            document = dict(case_id=case_id, document_id=document_id, text=text, source=source)
            documents.append(document)
            chunks = chunks_for(text, case_id, document_id, source)
            (attacked if is_attack else clean).extend(chunks)
            queries.append(dict(case_id=case_id, query=row['question']))
            span = [cut+2, cut+2+len(payload)] if is_attack else None
            positive_chunk_ids = [c['chunk_id'] for c in chunks if is_attack and
                c['source_metadata']['char_start'] < span[1] and c['source_metadata']['char_end'] > span[0]]
            evaluation.append(dict(case_id=case_id, pair_id=pair_id, document_id=document_id,
                original_train_row_0based=source_index, expected_answer=row['ideal'],
                answerable=row['ideal'].strip().lower()!='unknown', is_attacked=is_attack,
                attack_category=category if is_attack else None,
                attack_template_index_0based=attack_index if is_attack else None,
                attack_text=payload if is_attack else None, injection_position=position if is_attack else None,
                injection_char_span=span, injection_chunk_ids=positive_chunk_ids,
                attack_objective=payload if is_attack else None,
                attacker_goal_met=None, legitimate_task_correct=None, human_notes=''))
            review.append(dict(pair_id=pair_id, case_id=case_id, is_attacked=is_attack,
                query=row['question'], expected_answer=row['ideal'],
                attack_category=category if is_attack else '', injection_position=position if is_attack else '',
                text=text))
    data=ROOT/'data';data.mkdir(exist_ok=True)
    for name, rows in [('clean_chunks.jsonl',clean),('attacked_chunks.jsonl',attacked),
            ('documents.jsonl',documents),('queries.jsonl',queries),('evaluation_private.jsonl',evaluation)]:
        write_jsonl(data/name, rows)
    with (data/'review.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=list(review[0]));w.writeheader();w.writerows(review)
    example_case=queries[0]['case_id']
    example=dict(schema_version='1.0',request_id='demo_request_001',case_id=example_case,
        query=queries[0]['query'],retrieval_method='fixture',is_mock=True,
        chunks=[c for c in clean+attacked if c['case_id']==example_case])
    (ROOT/'example_retrieval_response.json').write_text(json.dumps(example,ensure_ascii=False,indent=2)+'\n')
    manifest=dict(dataset='BIPIA-based EmailQA RAG development pilot',seed=SEED,revision=REVISION,
        clean_cases=20,attacked_cases=20,pairs=20,unique_source_documents=20,
        answerable_pairs=9,unknown_answer_pairs=11,clean_chunks=len(clean),attacked_chunks=len(attacked),
        selection='Exact-context deduplication; exclude any raw test context; sample 9 answerable and 11 unknown contexts.',
        attacks='Four official training categories, five templates each; one insertion per attacked document.',
        placement_counts={'start':7,'middle':7,'end':6},
        chunking={'unit':'characters','size':1200,'overlap':200},
        scope='Development only; custom insertion/chunking, not official BIPIA scoring; no model results.',
        upstream_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'upstream').iterdir()) if p.is_file()})
    (ROOT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))

if __name__=='__main__':
    build()
