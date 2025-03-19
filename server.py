import asyncio
import logging
import time
from aioquic.asyncio import serve, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

logger = logging.getLogger("quic_server")
logging.basicConfig(level=logging.DEBUG)

class ThroughputServerProtocol(QuicConnectionProtocol):
    def connection_made(self, transport):
        super().connection_made(transport)
        peer = transport.get_extra_info("peername")
        logger.info("Server: New connection established from %s", peer)

    def quic_event_received(self, event):
        # Log events for debugging.
        if hasattr(event, "stream_id") and hasattr(event, "data"):
            logger.debug("Server: Event on stream %d: data=%s, end_stream=%s",
                         event.stream_id, event.data, event.end_stream)
            if event.data.startswith(b"init"):
                parts = event.data.split(b":")
                if len(parts) > 1:
                    try:
                        duration = int(parts[1])
                    except Exception as e:
                        logger.error("Server: Error parsing duration, defaulting to 10 seconds: %s", e)
                        duration = 10
                else:
                    duration = 10
                logger.info("Server: Received trigger on stream %d, starting transmission for %d seconds.",
                            event.stream_id, duration)
                asyncio.ensure_future(self.handle_stream(event.stream_id, duration))

    async def handle_stream(self, stream_id: int, duration: int):
        chunk_size = 4096  
        chunk = b'\0' * chunk_size
        bytes_sent = 0
        start_time = time.time()
        logger.info("Server: Starting data transmission on stream %d", stream_id)
        while time.time() - start_time < duration:
            self._quic.send_stream_data(stream_id, chunk)
            bytes_sent += len(chunk)
            if bytes_sent % (1 * 1024 * 1024) < chunk_size:
                logger.debug("Server: Sent %d bytes on stream %d", bytes_sent, stream_id)
            # Yield control without extra delay.
            await asyncio.sleep(0)
        # Signal end-of-stream.
        self._quic.send_stream_data(stream_id, b'', end_stream=True)
        await asyncio.sleep(0.1)
        self._quic.close(error_code=0, reason_phrase="Transmission complete")
        elapsed = time.time() - start_time
        throughput = bytes_sent / elapsed / (1024 * 1024)  # MB/s
        logger.info("Server: Finished sending %d bytes in %.2f seconds (%.2f MB/s) on stream %d",
                    bytes_sent, elapsed, throughput, stream_id)

async def main():
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["quic-throughput-test"]
    )
    configuration.load_cert_chain("ssl_cert.pem", "ssl_key.pem")
    configuration.initial_max_data = 50 * 1024 * 1024              
    configuration.initial_max_stream_data_bidi_local = 10 * 1024 * 1024  
    configuration.initial_max_stream_data_bidi_remote = 10 * 1024 * 1024 
    configuration.initial_max_stream_data_uni = 10 * 1024 * 1024       
    configuration.initial_max_streams_bidi = 100
    
    logger.info("Server: Starting QUIC server on 127.0.0.1:4242")
    await serve("127.0.0.1", 4004, configuration=configuration,
                create_protocol=ThroughputServerProtocol)
    await asyncio.Event().wait()

if __name__ == '__main__':
    asyncio.run(main())
