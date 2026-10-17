"""Check pairing, source fidelity, leak-free payloads, offsets and fixture integration."""
import hashlib
from collections import Counter,defaultdict
from prepare_dataset import ROOT,read_jsonl
from mock_adapter import mock_retrieve,screen_case

def validate():
    data=ROOT/'data';ev=read_jsonl(data/'evaluation_private.jsonl')
    docs={r['case_id']:r for r in read_jsonl(data/'documents.jsonl')}
    chunks=read_jsonl(data/'clean_chunks.jsonl')+read_jsonl(data/'attacked_chunks.jsonl')
    assert len(ev)==len(docs)==40
    assert len({c['chunk_id'] for c in chunks})==len(chunks)
    pairs=defaultdict(list)
    raw=read_jsonl(ROOT/'upstream/email_train.jsonl')
    test={r['context'] for r in read_jsonl(ROOT/'upstream/email_test.jsonl')}
    forbidden={'is_attacked','attack_text','attack_category','expected_answer','pair_id','injection_char_span'}
    for e in ev:
        pairs[e['pair_id']].append(e)
        original=raw[e['original_train_row_0based']]['context']
        assert original not in test
        text=docs[e['case_id']]['text']
        if e['is_attacked']:
            start,end=e['injection_char_span']
            assert text[start:end]==e['attack_text']
            assert text[:start-2]+text[end+2:]==original
            assert e['injection_chunk_ids']
        else: assert text==original
        response=mock_retrieve(e['case_id'])
        assert response['is_mock'] is True and response['query']
        for c in response['chunks']:
            assert not forbidden.intersection(c)
            assert not forbidden.intersection(c['source_metadata'])
            m=c['source_metadata'];assert m['source_trust']=='untrusted'
            assert c['text']==text[m['char_start']:m['char_end']]
            assert m['content_sha256']==hashlib.sha256(c['text'].encode()).hexdigest()
        covered=set()
        for c in response['chunks']:
            covered.update(range(c['source_metadata']['char_start'],c['source_metadata']['char_end']))
        assert len(covered)==len(text)
    assert len(pairs)==20
    assert len({docs[v[0]['case_id']]['text'] if not v[0]['is_attacked'] else docs[v[1]['case_id']]['text'] for v in pairs.values()})==20
    for p in pairs.values():
        assert len(p)==2 and {e['is_attacked'] for e in p}=={False,True}
        assert p[0]['expected_answer']==p[1]['expected_answer']
        assert mock_retrieve(p[0]['case_id'])['query']==mock_retrieve(p[1]['case_id'])['query']
    assert Counter(e['attack_category'] for e in ev if e['is_attacked'])=={
        'Information Retrieval':5,'Content Creation':5,'Language Translation':5,'Instruction':5}
    def dummy_detector(**kwargs):
        return dict(decision='allow',risk_score=0.0,is_suspicious=False,reason='Integration stub only')
    assert screen_case('case_001',dummy_detector)
    print(f'PASS: 20 matched pairs, 40 cases, {len(chunks)} unique chunks; source fidelity, offsets, metadata isolation and mock adapter validated.')
    print('No detector effectiveness, attack success, or LLM performance has been measured.')

if __name__=='__main__': validate()
