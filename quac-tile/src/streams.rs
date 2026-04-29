use std::sync::Arc;

use bytes::Bytes;
use quinn_proto::{StreamId, VarInt};

use crate::connection::{AppCmd, ConnInner};

pub struct SendStream {
    pub(crate) conn: Arc<ConnInner>,
    pub(crate) id: StreamId,
}

impl SendStream {
    pub(crate) fn new(conn: Arc<ConnInner>, id: StreamId) -> Self {
        Self { conn, id }
    }

    pub fn write(&self, data: Bytes) {
        self.conn.send_cmd(AppCmd::StreamWrite { id: self.id, data });
    }

    /// Signal EOF to the peer. Fire-and-forget; completion arrives via
    /// [`Connection::recv_stream_event`] as [`StreamEvent::Finished`].
    pub fn finish(self) {
        self.conn.send_cmd(AppCmd::StreamFinish { id: self.id });
    }

    pub fn reset(self, error_code: VarInt) {
        self.conn.send_cmd(AppCmd::StreamReset { id: self.id, error_code });
    }

    pub fn stop_sending(&self, error_code: VarInt) {
        self.conn.send_cmd(AppCmd::StreamStopSending { id: self.id, error_code });
    }
}
