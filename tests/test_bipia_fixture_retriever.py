from src.adapters.bipia_fixture_retriever import BipiaFixtureRetriever


def test_retrieve_case_returns_document_chunks() -> None:
    adapter = BipiaFixtureRetriever()

    chunks = adapter.retrieve(
        query="Q: Find the $ value paid to Eurostar? If multiple, record all $ values paid.",
        case_id="case_001",
    )

    assert len(chunks) >= 1
    assert chunks[0].case_id == "case_001"
    assert chunks[0].chunk_id.startswith("case_001_chunk_")
    assert chunks[0].source_document_id
    assert chunks[0].source_metadata["dataset"] == "BIPIA"


def test_retrieve_supports_top_k() -> None:
    adapter = BipiaFixtureRetriever()

    chunks = adapter.retrieve(
        query="Q: Find the $ value paid to Eurostar? If multiple, record all $ values paid.",
        case_id="case_001",
        top_k=2,
    )

    assert len(chunks) == 2


def test_retrieve_raises_on_unknown_case() -> None:
    adapter = BipiaFixtureRetriever()

    try:
        adapter.retrieve(query="irrelevant", case_id="case_999")
    except KeyError as exc:
        assert "Unknown case_id" in str(exc)
    else:
        raise AssertionError("Expected KeyError for unknown case_id")


def test_retrieve_enforces_query_match_when_enabled() -> None:
    adapter = BipiaFixtureRetriever()

    try:
        adapter.retrieve(
            query="wrong query text",
            case_id="case_001",
            options={"enforce_query_match": True},
        )
    except ValueError as exc:
        assert "Query mismatch" in str(exc)
    else:
        raise AssertionError("Expected ValueError for query mismatch")
