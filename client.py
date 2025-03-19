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
    def connection_made(self, transport):
        super().connection_made(transport)
        peer = transport.get_extra_info("peername")
        logger.info("Client: Connected to server at %s", peer)

    def __init__(self, *args, **kwargs):
        self.total_bytes = 0
        self.start_time = None
        self.done = asyncio.Event()
        super().__init__(*args, **kwargs)
    
    def quic_event_received(self, event):
        if hasattr(event, "stream_id") and hasattr(event, "data"):
            logger.debug("Client: Event on stream %d: data=%s, end_stream=%s",
                         event.stream_id, event.data[:50], event.end_stream)
            if self.start_time is None:
                self.start_time = time.time()
                logger.info("Client: First data received on stream %d, starting timer.", event.stream_id)
            self.total_bytes += len(event.data)
            if event.end_stream:
                elapsed = time.time() - self.start_time
                throughput = self.total_bytes / elapsed / (1024 * 1024)  # MB/s
                logger.info("Client: Finished receiving %d bytes in %.2f seconds (%.2f MB/s)",
                            self.total_bytes, elapsed, throughput)
                self.done.set()

async def main(duration: int):
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["quic-throughput-test"]
    )
    configuration.verify_mode = False
    configuration.initial_max_data = 50 * 1024 * 1024              
    configuration.initial_max_stream_data_bidi_local = 10 * 1024 * 1024  
    configuration.initial_max_stream_data_bidi_remote = 10 * 1024 * 1024 
    configuration.initial_max_stream_data_uni = 10 * 1024 * 1024       
    configuration.initial_max_streams_bidi = 100
    
    try:
        async with connect("127.0.0.1", 4004, configuration=configuration,
                           create_protocol=ThroughputClientProtocol) as protocol:
            logger.info("Client: Connection established, sending trigger.")
            stream_id = protocol._quic.get_next_available_stream_id()
            trigger = f"init:{duration}".encode()
            logger.info("Client: Sending trigger payload '%s' on stream %d", trigger.decode(), stream_id)
            protocol._quic.send_stream_data(stream_id, trigger, end_stream=False)
            logger.info("Client: Waiting for data...")
            await protocol.done.wait()
            logger.info("Client: Data transfer complete.")
    except Exception as e:
        logger.error("Client: Connection error: %s", e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="QUIC Throughput Test Client")
    parser.add_argument("--duration", type=int, default=10, help="Duration of data transfer in seconds")
    args = parser.parse_args()
    asyncio.run(main(args.duration))
