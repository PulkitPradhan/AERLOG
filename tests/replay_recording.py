"""Create a real checksummed recording for replay and regression tests."""

from pathlib import Path
from tempfile import TemporaryDirectory

from aerlog.capture.normalizer import EventNormalizer
from aerlog.events.models import ExecutionEvent, ExecutionSummary
from aerlog.storage.event_log import JsonlEventLogReader, JsonlEventLogWriter, JsonlReadResult


def read_recording(
    events: list[ExecutionEvent], norm: EventNormalizer, summary: ExecutionSummary | None
) -> JsonlReadResult:
    header = norm.build_header()
    with TemporaryDirectory() as tmp:
        data_dir = Path(tmp)
        writer = JsonlEventLogWriter(
            data_dir, header.execution_id, redaction_mode=header.redaction_mode
        )
        writer.open(header)
        try:
            writer.append_events(events)
            if summary is not None:
                writer.finalize(summary)
        finally:
            writer.close()
        return JsonlEventLogReader(data_dir).read_execution(header.execution_id)
