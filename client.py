import argparse
import asyncio
import logging
import time

from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

logger = logging.getLogger("quic_client")
logging.basicConfig(level=logging.DEBUG)

class ThroughputClientProtocol(QuicConnectionProtocol):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.total_bytes = 0
        self.start_time = None
        self.done = asyncio.Event()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            logger.debug(
                "Client: Received data (len=%d), end_stream=%s",
                len(event.data),
                event.end_stream
            )
            if self.start_time is None:
                self.start_time = time.time()
                logger.info("Client: First data received, starting timer.")

            self.total_bytes += len(event.data)

            if event.end_stream:
                logger.info("Client: end_stream on stream %d, finalizing goodput.", event.stream_id)
                self._report_goodput()

    def connection_close(self, error_code: int, frame_type: int, reason_phrase: str):
        logger.info(
            "Client: connection_close() from server (code=0x%x, reason='%s')",
            error_code,
            reason_phrase
        )
        if not self.done.is_set() and self.start_time is not None:
            self._report_goodput()
        super().connection_close(error_code, frame_type, reason_phrase)

    def connection_lost(self, exc):
        logger.info("Client: connection_lost() at Python transport layer.")
        if not self.done.is_set() and self.start_time is not None:
            self._report_goodput()
        super().connection_lost(exc)

    def _report_goodput(self):
        elapsed = time.time() - self.start_time
        goodput_mB_s = (self.total_bytes / elapsed) / (1024 * 1024)  # MB/s
        goodput_mbps = (self.total_bytes * 8 / elapsed) / 1e6        # Mbit/s

        logger.info(
            "Client: Goodput = %.2f MB/s (%.2f Mbit/s), total=%d bytes, elapsed=%.2f s",
            goodput_mB_s,
            goodput_mbps,
            self.total_bytes,
            elapsed,
        )
        self.done.set()

async def main(duration: int):
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["quic-throughput-test"])
    configuration.verify_mode = False

    configuration.initial_max_data = 50 * 1024 * 1024
    configuration.initial_max_stream_data_bidi_local = 10 * 1024 * 1024
    configuration.initial_max_stream_data_bidi_remote = 10 * 1024 * 1024
    configuration.initial_max_stream_data_uni = 10 * 1024 * 1024
    configuration.initial_max_streams_bidi = 100

    protocol = None
    try:
        async with connect("127.0.0.1", 5001, configuration=configuration,
                           create_protocol=ThroughputClientProtocol) as protocol:
            logger.info("Client: Connected, sending trigger init:%d", duration)
            trigger = f"init:{duration}".encode()
            stream_id = protocol._quic.get_next_available_stream_id()
            protocol._quic.send_stream_data(stream_id, trigger, end_stream=False)

            grace_period = 5
            total_wait = duration + grace_period
            logger.info("Client: Will wait up to %d seconds total for final close/end_stream.", total_wait)
            try:
                await asyncio.wait_for(protocol.done.wait(), timeout=total_wait)
            except asyncio.TimeoutError:
                logger.warning("Client: Timed out after %d s, forcibly reporting goodput.", total_wait)
                if not protocol.done.is_set() and protocol.start_time is not None:
                    protocol._report_goodput()

            logger.info("Client: Data transfer complete (done=%s).", protocol.done.is_set())
    except Exception as e:
        logger.error("Client: Connection error: %s", e)

    if protocol and not protocol.done.is_set() and protocol.start_time is not None:
        logger.info("Client: Exiting block, forcibly computing final goodput.")
        protocol._report_goodput()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=10, help="Duration (in seconds) for server to send data")
    args = parser.parse_args()
    asyncio.run(main(args.duration))
