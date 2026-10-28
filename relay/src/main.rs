use axum::extract::ws::{Message, WebSocket};
use axum::{
    extract::{Path, State, WebSocketUpgrade},
    response::Response,
    routing::get,
    Router,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::info;

type Rooms = Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/ws/{room_id}", get(ws_handler))
        .fallback_service(ServeDir::new("static"))
        .layer(cors)
        .with_state(rooms);

    let addr = "0.0.0.0:4500";
    info!("keystone-relay listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(room_id): Path<String>,
    State(rooms): State<Rooms>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, room_id, rooms))
}

async fn handle_socket(mut socket: WebSocket, room_id: String, rooms: Rooms) {
    let maybe_tx = {
        let mut map = rooms.lock().await;
        map.remove(&room_id)
    };

    if let Some(tx) = maybe_tx {
        // Phone (sender): read one message and forward it to the waiting desktop
        if let Some(Ok(Message::Text(msg))) = socket.recv().await {
            info!("room {room_id}: signature received, forwarding");
            let _ = tx.send(msg.to_string());
        }
    } else {
        // Desktop (waiter): register room and wait up to 5 minutes
        let (tx, rx) = oneshot::channel::<String>();
        {
            let mut map = rooms.lock().await;
            map.insert(room_id.clone(), tx);
        }
        info!("room {room_id}: waiter registered");

        match tokio::time::timeout(std::time::Duration::from_secs(300), rx).await {
            Ok(Ok(payload)) => {
                let _ = socket.send(Message::Text(payload.into())).await;
                info!("room {room_id}: payload delivered, closing");
            }
            _ => {
                // Timeout or sender dropped — clean up
                let mut map = rooms.lock().await;
                map.remove(&room_id);
                info!("room {room_id}: timed out or cancelled");
            }
        }
    }
}
