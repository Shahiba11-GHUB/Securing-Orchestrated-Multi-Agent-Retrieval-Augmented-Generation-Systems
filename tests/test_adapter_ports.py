import inspect

from src.adapters import ActionPort, RetrieverPort, SecurityPort


def test_retriever_port_is_abstract() -> None:
    assert inspect.isabstract(RetrieverPort)
    assert "retrieve" in RetrieverPort.__abstractmethods__


def test_security_port_is_abstract() -> None:
    assert inspect.isabstract(SecurityPort)
    assert "screen_chunks" in SecurityPort.__abstractmethods__


def test_action_port_is_abstract() -> None:
    assert inspect.isabstract(ActionPort)
    assert "execute" in ActionPort.__abstractmethods__
