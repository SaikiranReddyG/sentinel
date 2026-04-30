import pytest

from src.events import emit_event, set_output
from src.output import FileOutput, HttpPostOutput, StdoutOutput, make_output


class _CollectingOutput:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def test_emit_event_schema_compliance():
    sink = _CollectingOutput()
    set_output(sink)

    event = emit_event('sentinel.lifecycle.started', 'low', {'interface': 'lo'})

    required = {
        'schema_version',
        'timestamp',
        'source',
        'source_version',
        'host',
        'event_type',
        'severity',
        'payload',
    }

    assert required.issubset(event)
    assert event['source'] == 'sentinel'
    assert event['event_type'] == 'sentinel.lifecycle.started'
    assert event['severity'] == 'low'
    assert event['payload'] == {'interface': 'lo'}
    assert sink.events == [event]


def test_emit_event_invalid_severity_raises():
    with pytest.raises(ValueError):
        emit_event('sentinel.alert', 'invalid', {})


def test_emit_event_alert_shape():
    """Verify sentinel.alert events conform to the contract when emitted."""
    captured = []

    class Capture:
        def emit(self, event):
            captured.append(event)

        def flush(self):
            pass

    set_output(Capture())
    emit_event('sentinel.alert', 'high', {
        'detection_type': 'PORT_SCAN',
        'src_ip': '1.2.3.4',
        'dst_ip': '5.6.7.8',
        'message': 'test',
    })

    assert len(captured) == 1
    ev = captured[0]
    assert ev['event_type'] == 'sentinel.alert'
    assert ev['severity'] == 'high'
    assert ev['source'] == 'sentinel'
    assert isinstance(ev['timestamp'], str)
    assert ev['timestamp'].count(':') >= 2
    assert ev['payload']['detection_type'] == 'PORT_SCAN'


def test_make_output_factory(tmp_path):
    assert isinstance(make_output('stdout'), StdoutOutput)

    file_path = tmp_path / 'events.jsonl'
    assert isinstance(make_output('file', path=str(file_path)), FileOutput)

    assert isinstance(make_output('http_post', url='http://localhost:8080/events'), HttpPostOutput)