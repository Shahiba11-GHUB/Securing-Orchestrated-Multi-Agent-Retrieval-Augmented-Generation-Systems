"""Fixture adapter for detector integration. This does not perform retrieval."""
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parent

def mock_retrieve(case_id, request_id='demo_request_001'):
    queries = [json.loads(x) for x in (ROOT/'data/queries.jsonl').read_text().splitlines()]
    query = next((r['query'] for r in queries if r['case_id']==case_id), None)
    if query is None:
        raise KeyError(f'Unknown case_id: {case_id}')
    chunks = []
    for filename in ('clean_chunks.jsonl','attacked_chunks.jsonl'):
        chunks.extend(json.loads(line) for line in (ROOT/'data'/filename).read_text().splitlines()
                      if json.loads(line)['case_id']==case_id)
    return dict(schema_version='1.0', request_id=request_id, case_id=case_id,
        query=query, retrieval_method='fixture', is_mock=True, chunks=chunks)

def screen_case(case_id, detector):
    """detector(text=..., source=..., source_metadata=...) returns its decision dict."""
    response=mock_retrieve(case_id)
    decisions=[]
    for chunk in response['chunks']:
        result=detector(text=chunk['text'],source=chunk['source'],
                        source_metadata=dict(chunk['source_metadata']))
        if result.get('decision') not in {'allow','quarantine','block'}:
            raise ValueError('Invalid security decision')
        score=result.get('risk_score')
        if isinstance(score,bool) or not isinstance(score,(int,float)) or not 0 <= score <= 1:
            raise ValueError('risk_score must be numeric in [0,1]')
        if not isinstance(result.get('is_suspicious'),bool) or not isinstance(result.get('reason'),str):
            raise ValueError('Expected boolean is_suspicious and string reason')
        decisions.append(dict(result,chunk_id=chunk['chunk_id'],case_id=chunk['case_id']))
    return decisions

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--case-id',default='case_001')
    args=parser.parse_args();print(json.dumps(mock_retrieve(args.case_id),ensure_ascii=False,indent=2))
